package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	"github.com/octovault/octovault/internal/controller"
)

type mapFetcher map[string][]byte

func (m mapFetcher) Fetch(ctx context.Context, org, repo, path, ref, token string) ([]byte, []byte, string, error) {
	return m[path], nil, "rev1", nil
}

// 대상 ConfigMap/Secret 이 지워지면 poll 주기(여기선 60m)를 기다리지 않고 바로 다시 만들어져야 한다.
func TestDeletedTargetsAreRestoredByWatch(t *testing.T) {

	env := &envtest.Environment{
		BinaryAssetsDirectory: firstEnvtestBinaryDir(),
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {

		t.Skipf("envtest unavailable (run 'make setup-envtest'): %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Cache:                  secretCacheOptions(),
		Client:                 secretClientOptions(),
	})
	require.NoError(t, err)

	targetSecrets, err := newTargetSecretCache(mgr)
	require.NoError(t, err)

	require.NoError(t, (&controller.OctoVaultReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("octovault"),
		Git: mapFetcher{
			"cm.yaml":  []byte("metadata:\n  type: ConfigMap\nspec:\n  data:\n    - key: a\n      value: b\n"),
			"sec.yaml": []byte("metadata:\n  type: Secret\nspec:\n  data:\n    - key: a\n      value: b\n"),
		},
		TargetSecrets: targetSecrets,
	}).SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	require.NoError(t, direct.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cred", Namespace: "default"},
		Data:       map[string][]byte{"password": []byte("tok")},
	}))
	require.NoError(t, direct.Create(ctx, &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "org"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:   "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{Name: "cred", Namespace: "default"},
		},
	}))

	for _, tc := range []struct {
		path   string
		target client.Object
	}{
		{path: "cm.yaml", target: &corev1.ConfigMap{}},
		{path: "sec.yaml", target: &corev1.Secret{}},
	} {
		name := "out-" + tc.path[:len(tc.path)-len(".yaml")]
		require.NoError(t, direct.Create(ctx, &octovaultv1alpha1.OctoVault{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: octovaultv1alpha1.OctoVaultSpec{
				OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "org"},
				Repository:        "test-repo",
				Path:              tc.path,
				TargetName:        name,
				PollInterval:      "60m",
			},
		}))

		key := client.ObjectKey{Name: name, Namespace: "default"}
		exists := func() bool { return direct.Get(ctx, key, tc.target) == nil }

		require.Eventually(t, exists, 20*time.Second, 100*time.Millisecond, "%s must be created", name)
		uid := tc.target.GetUID()

		require.NoError(t, direct.Delete(ctx, tc.target))
		require.Eventually(t, func() bool {

			return exists() && tc.target.GetUID() != uid
		}, 20*time.Second, 100*time.Millisecond, "%s must be recreated without waiting for the poll interval", name)
	}
}
