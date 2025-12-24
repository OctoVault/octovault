/*
Copyright 2025 octovault.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	awsps "github.com/octovault/octovault/internal/aws/parameter_store"
	awssm "github.com/octovault/octovault/internal/aws/secret_manager"
	"github.com/octovault/octovault/internal/github"

	"sigs.k8s.io/controller-runtime/pkg/client"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	"github.com/octovault/octovault/internal/controller"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(octovaultv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {

	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var maxWorkers int
	var tlsOpts []func(*tls.Config)

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.IntVar(&maxWorkers, "max-workers", 1,
		"Number of workers for each controller.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {

		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {

		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	ovMaxWorkers := resolveWorkers(maxWorkers, "OVO_OV_MAX_CONCURRENT", 1)

	// Create watchers for metrics and webhooks certificates
	var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts

	if len(webhookCertPath) > 0 {

		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		var err error
		webhookCertWatcher, err = certwatcher.New(
			filepath.Join(webhookCertPath, webhookCertName),
			filepath.Join(webhookCertPath, webhookCertKey),
		)
		if err != nil {

			setupLog.Error(err, "Failed to initialize webhook certificate watcher")
			os.Exit(1)
		}

		webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
			config.GetCertificate = webhookCertWatcher.GetCertificate
		})
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: webhookTLSOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {

		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		var err error
		metricsCertWatcher, err = certwatcher.New(
			filepath.Join(metricsCertPath, metricsCertName),
			filepath.Join(metricsCertPath, metricsCertKey),
		)
		if err != nil {

			setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
			os.Exit(1)
		}

		metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
			config.GetCertificate = metricsCertWatcher.GetCertificate
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "08f842b9.octovault.it",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {

		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// OctoRepositoryController Field Indexer
	ctx := context.Background()
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&octovaultv1alpha1.OctoRepository{},
		"spec.credentialsRef.index",
		func(obj client.Object) []string {

			o := obj.(*octovaultv1alpha1.OctoRepository)
			ns := strings.TrimSpace(o.Spec.CredentialsRef.Namespace)
			name := strings.TrimSpace(o.Spec.CredentialsRef.Name)
			if ns == "" || name == "" {

				return nil
			}

			return []string{ns + "/" + name}
		},
	); err != nil {

		setupLog.Error(err, "unable to create field indexer for OctoRepository", "field", "spec.credentialsRef.index")
		os.Exit(1)
	}

	// OctoVault spec.octoRepositoryRef.name 인덱서 (OctoRepository → OctoVault 재매핑용)
	if err := mgr.GetFieldIndexer().IndexField(ctx, &octovaultv1alpha1.OctoVault{},
		"spec.octoRepositoryRef.name",
		func(obj client.Object) []string {

			ov := obj.(*octovaultv1alpha1.OctoVault)
			if ov.Spec.OctoRepositoryRef.Name == "" {
				return nil
			}

			return []string{ov.Spec.OctoRepositoryRef.Name}
		},
	); err != nil {

		setupLog.Error(err, "unable to set up field indexer", "field", "spec.octoRepositoryRef.name")
		os.Exit(1)
	}

	// Secret -> OctoRepository controller
	if err := (&controller.RepoSecretReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Workers: ovMaxWorkers,
	}).SetupWithManager(mgr); err != nil {

		setupLog.Error(err, "unable to create controller", "controller", "OctoRepositorySecret")
		os.Exit(1)
	}

	if err := (&controller.OctoRepositoryReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("octorepository-controller"),
		Workers:  ovMaxWorkers,
	}).SetupWithManager(mgr); err != nil {

		setupLog.Error(err, "unable to create controller", "controller", "OctoRepository")
		os.Exit(1)
	}

	gitUA := "octovault-operator"

	gitBase := os.Getenv("OVO_GIT_API_URL") // 비우면 자동으로 https://api.github.com
	gitRef := os.Getenv("OVO_GIT_REF")      // 비우면 디폴트 브랜치

	gitFetcher := github.NewFetcher(github.Options{
		BaseURL:        gitBase,
		HTTPClient:     nil, // 기본 타임아웃 15s
		SchemaFileName: "validator.schema.json",
		Ref:            gitRef,
		UserAgent:      gitUA,
	})

	region := os.Getenv("OVO_AWS_REGION")
	AwsSMTtlStr := os.Getenv("OVO_AWS_SM_TTL")
	if AwsSMTtlStr == "" {

		AwsSMTtlStr = "1m"
	}
	AwsPSTtlStr := os.Getenv("OVO_AWS_PS_TTL")
	if AwsPSTtlStr == "" {

		AwsPSTtlStr = "1m"
	}

	AwsSMTtl, err := time.ParseDuration(AwsSMTtlStr)
	if err != nil || AwsSMTtl <= 0 {

		AwsSMTtl = time.Minute
	}
	AwsPSTtl, err := time.ParseDuration(AwsPSTtlStr)
	if err != nil || AwsPSTtl <= 0 {

		AwsPSTtl = time.Minute
	}

	awsSMProv, err := awssm.New(context.Background(), region, AwsSMTtl)
	if err != nil {

		setupLog.Error(err, "AWS Secrets Manager provider init failed; AwsSecretManager type will be unavailable")
		awsSMProv = nil
	}

	awsPSProv, err := awsps.New(context.Background(), region, AwsPSTtl)
	if err != nil {

		setupLog.Error(err, "AWS Parameter Store provider init failed; AwsParameterStore type will be unavailable")
		awsPSProv = nil
	}

	if err := (&controller.OctoVaultReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("octovault"),
		Git:      gitFetcher,
		Workers:  ovMaxWorkers,
		AwsSM:    awsSMProv,
		AwsPS:    awsPSProv,
		// Validator: yourValidator,
	}).SetupWithManager(mgr); err != nil {

		setupLog.Error(err, "unable to create controller", "controller", "OctoVault")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if metricsCertWatcher != nil {

		setupLog.Info("Adding metrics certificate watcher to manager")
		if err := mgr.Add(metricsCertWatcher); err != nil {

			setupLog.Error(err, "unable to add metrics certificate watcher to manager")
			os.Exit(1)
		}
	}

	if webhookCertWatcher != nil {

		setupLog.Info("Adding webhook certificate watcher to manager")
		if err := mgr.Add(webhookCertWatcher); err != nil {

			setupLog.Error(err, "unable to add webhook certificate watcher to manager")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {

		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {

		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {

		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// resolveWorkers: env(>0) flag(>0) > def
func resolveWorkers(flagVal int, envKey string, def int) int {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {

			return n
		}
	}

	if flagVal > 0 {

		return flagVal
	}

	if def <= 0 {

		return 1
	}

	return def
}
