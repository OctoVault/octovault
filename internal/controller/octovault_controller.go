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

package controller

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	awsps "github.com/octovault/octovault/internal/aws/parameter_store"
	awssm "github.com/octovault/octovault/internal/aws/secret_manager"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/yaml"

	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CondReady = "Ready"

	LabelManagedBy   = "app.kubernetes.io/managed-by"
	LabelOVOwnerNS   = "octovault.it/owner-ns"   // <namespace>
	LabelOVOwnerName = "octovault.it/owner-name" // <name>
	AnnoOVOwnerFull  = "octovault.it/owner"      // "<ns>/<name>"
	AnnoOVRetainedBy = "octovault.it/retained-from"
	FinalizerOV      = "octovault.it/finalizer"
)

func labelSafe(v string) string {
	if len(v) <= 63 {

		return v
	}

	sum := sha1.Sum([]byte(v))
	return v[:31] + "-" + hex.EncodeToString(sum[:4])
}

func setManagedLabels(m *metav1.ObjectMeta, ov *octovaultv1alpha1.OctoVault) {
	if m.Labels == nil {

		m.Labels = map[string]string{}
	}
	m.Labels[LabelManagedBy] = "octovault"

	ns := ov.Namespace
	name := ov.Name
	name = labelSafe(name)

	m.Labels[LabelOVOwnerNS] = ns
	m.Labels[LabelOVOwnerName] = name

	if m.Annotations == nil {

		m.Annotations = map[string]string{}
	}
	m.Annotations[AnnoOVOwnerFull] = ns + "/" + name
}

// values.yaml 모델
// ConfigMap/Secret 공용: metadata.type
// ConfigMap: spec.data[].{key.value}
// Secret: spec.data[].{key,type,value,name}
type valuesDoc struct {
	Metadata struct {
		Type string `yaml:"type"`
	} `yaml:"metadata"`
	Spec struct {
		Data []struct {
			Key     string `yaml:"key"`
			Value   string `yaml:"value,omitempty"`   // Text일 때 사용
			Type    string `yaml:"type,omitempty"`    // "Text" | "AwsSecretManager"
			Name    string `yaml:"name,omitempty"`    // SecretManager일 때 참조
			JSONKey string `yaml:"jsonKey,omitempty"` // SecretManager의 SecretString(JSON) 키
		} `yaml:"data"`
	} `yaml:"spec"`
}

type GitFetcher interface {
	// Fetch fetches values.yaml from the given GitHub repository.
	// org: github.com/<org>, repo: <repo>, ref: <ref> path: path/to/values.yaml
	Fetch(ctx context.Context, org, repo, path, ref, token string) (valuesYAML []byte, schemaJSON []byte, revision string, err error)
}

type Validator interface {
	Validate(valuesYAML []byte, schemaJSON []byte) error
}

type AwsSecretsProvider interface {
	GetSecret(ctx context.Context, name string) (value []byte, meta awssm.Meta, err error)
	ExtractJSONKey(value []byte, jsonKey string) ([]byte, error)
}

type AwsParamProvider interface {
	GetParameter(ctx context.Context, name string, withDecryption bool) (value []byte, meta awsps.Meta, err error)
	ExtractJSONKey(value []byte, jsonKey string) (out []byte, err error)
}

type OctoVaultReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Git       GitFetcher
	Validator Validator

	Workers int

	AwsSM AwsSecretsProvider
	AwsPS AwsParamProvider
}

// +kubebuilder:rbac:groups=octovault.it,resources=octovaults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=octovault.it,resources=octovaults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=octovault.it,resources=octovaults/finalizers,verbs=update
// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets;configmaps;events,verbs=get;list;watch;create;update;patch

func (r *OctoVaultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := logf.FromContext(ctx)

	var ov octovaultv1alpha1.OctoVault
	if err := r.Get(ctx, req.NamespacedName, &ov); err != nil {

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 삭제 중이면 대상 리소스에서 OwnerRef
	if !ov.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ov, FinalizerOV) {

			_ = r.orphanTargets(ctx, &ov)
			controllerutil.RemoveFinalizer(&ov, FinalizerOV)

			if err := r.Update(ctx, &ov); err != nil {

				logger.Error(err, "failed to remove finalizer")
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// 파이널라이저 보장
	if !controllerutil.ContainsFinalizer(&ov, FinalizerOV) {

		controllerutil.AddFinalizer(&ov, FinalizerOV)
		if err := r.Update(ctx, &ov); err != nil {

			logger.Error(err, "failed to add finalizer")
			return ctrl.Result{}, err
		}
	}

	r.ensurePendingInit(ctx, &ov)

	poll := parseDurationOr(ov.Spec.PollInterval, time.Minute)

	// 1) OctoRepository & PAT Secret
	orepo, token, res, err := r.loadRepoAndToken(ctx, &ov)
	if err != nil || res.RequeueAfter > 0 {
		if err != nil {

			logger.Error(err, "failed to load repo and token")
		}

		return res, err
	}

	// 2) Fetch values.yaml
	valuesYAML, schemaJSON, rev, res, err := r.tryFetch(ctx, &ov, orepo, token, poll)
	if err != nil || res.RequeueAfter > 0 {
		if err != nil {

			logger.Error(err, "failed to fetch values")
		}

		return res, nil
	}

	if rev == "" {
		rev = "sha256:" + shortSHA(valuesYAML)
	}

	if res := r.tryValidate(&ov, valuesYAML, schemaJSON, poll); res.RequeueAfter > 0 {

		return res, nil
	}

	// 3) parse values.yaml
	doc, resolvedType, res := r.parseAndResolveType(&ov, valuesYAML, poll)
	if res.RequeueAfter > 0 {

		return res, nil
	}

	targetNS := ov.Spec.TargetNamespace
	if targetNS == "" {
		targetNS = ov.Namespace
	}

	// 4) apply
	appliedHash, res, err := r.applyOutput(ctx, &ov, doc, poll, resolvedType, rev, targetNS)
	if err != nil || res.RequeueAfter > 0 {
		if err != nil {

			logger.Error(err, "failed to apply output")
		}

		return res, err
	}

	// 5) status
	r.setSyncedStatus(ctx, &ov, appliedHash, resolvedType, rev)

	return ctrl.Result{RequeueAfter: poll}, nil
}

func (r *OctoVaultReconciler) ensurePendingInit(ctx context.Context, ov *octovaultv1alpha1.OctoVault) {
	if ov.Status.Phase == "" {

		desired := ov.Status
		desired.Phase = octovaultv1alpha1.OVPhasePending
		desired.Message = "initializing"
		r.updateStatusIfChanged(ctx, ov, desired)
	}
}

func (r *OctoVaultReconciler) loadRepoAndToken(ctx context.Context, ov *octovaultv1alpha1.OctoVault) (*octovaultv1alpha1.OctoRepository, string, ctrl.Result, error) {

	poll := parseDurationOr(ov.Spec.PollInterval, time.Minute)
	var orepo octovaultv1alpha1.OctoRepository

	if err := r.Get(ctx, types.NamespacedName{Name: ov.Spec.OctoRepositoryRef.Name}, &orepo); err != nil {
		if apierrors.IsNotFound(err) {

			ov.Status = fail("OctoRepositoryNotFound", fmt.Sprintf("no OctoRepository %q", ov.Spec.OctoRepositoryRef.Name))
			_ = r.Status().Update(ctx, ov)

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{RequeueAfter: poll}, err
	}

	var cred corev1.Secret
	secKey := types.NamespacedName{Namespace: orepo.Spec.CredentialsRef.Namespace, Name: orepo.Spec.CredentialsRef.Name}

	if err := r.Get(ctx, secKey, &cred); err != nil {
		if apierrors.IsNotFound(err) {

			ov.Status = fail("CredentialsNotFound", fmt.Sprintf("no Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name))
			_ = r.Status().Update(ctx, ov)

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{RequeueAfter: poll}, err
	}

	token := getFromSecret(&cred, "password")
	if token == "" {

		r.updateStatusIfChanged(ctx, ov, fail("SecretMissingPassword", fmt.Sprintf("no 'password' key in Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

		return nil, "", ctrl.Result{RequeueAfter: poll}, nil
	}

	if enc := getFromSecret(&cred, "passwordEncoding"); enc == "base64" {

		dec, err := base64.StdEncoding.DecodeString(token)
		if err != nil {

			r.updateStatusIfChanged(ctx, ov, fail("SecretInvalidPasswordEncoding", fmt.Sprintf("invalid base64 in 'password' key in Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		token = string(dec)
	}

	return &orepo, token, ctrl.Result{}, nil
}

func (r *OctoVaultReconciler) tryFetch(ctx context.Context, ov *octovaultv1alpha1.OctoVault, orepo *octovaultv1alpha1.OctoRepository, token string, poll time.Duration) ([]byte, []byte, string, ctrl.Result, error) {

	org := orepo.Spec.Organization
	ref := strings.TrimSpace(ov.Spec.GitRef)
	repo := normalizeRepoName(ov.Spec.Repository)
	// ctx context.Context, org, repo, path, ref, token string
	valuesYAML, schemaJSON, rev, err := r.fetch(ctx, org, repo, ov.Spec.Path, ref, token)

	if err != nil {

		r.updateStatusIfChanged(ctx, ov, fail("FetchFailed", fmt.Sprintf("failed to fetch values: %v", err)))
		return nil, nil, "", ctrl.Result{RequeueAfter: poll}, err
	}

	return valuesYAML, schemaJSON, rev, ctrl.Result{}, nil
}

func (r *OctoVaultReconciler) tryValidate(ov *octovaultv1alpha1.OctoVault, valuesYAML, schemaJSON []byte, poll time.Duration) ctrl.Result {
	if r.Validator != nil {
		if err := r.Validator.Validate(valuesYAML, schemaJSON); err != nil {

			r.updateStatusIfChanged(context.Background(), ov, fail("ValidateFailed", fmt.Sprintf("failed to validate values: %v", err)))

			return ctrl.Result{RequeueAfter: poll}
		}
	}

	return ctrl.Result{}
}

func (r *OctoVaultReconciler) parseAndResolveType(ov *octovaultv1alpha1.OctoVault, valuesYAML []byte, poll time.Duration) (valuesDoc, string, ctrl.Result) {

	var doc valuesDoc
	if err := yaml.Unmarshal(valuesYAML, &doc); err != nil {

		r.updateStatusIfChanged(context.Background(), ov, fail("ParseFailed", fmt.Sprintf("yaml parse failed: %v", err)))

		return doc, "", ctrl.Result{RequeueAfter: poll}
	}

	resolvedType := strings.TrimSpace(doc.Metadata.Type)
	if resolvedType == "" || (resolvedType != string(octovaultv1alpha1.OutputConfigMap) && resolvedType != string(octovaultv1alpha1.OutputSecret)) {

		r.updateStatusIfChanged(context.Background(), ov, fail("InvalidType", "metadata.type must be 'ConfigMap' or 'Secret'"))

		return doc, "", ctrl.Result{RequeueAfter: poll}
	}

	return doc, resolvedType, ctrl.Result{}
}

func (r *OctoVaultReconciler) applyOutput(ctx context.Context, ov *octovaultv1alpha1.OctoVault, doc valuesDoc, poll time.Duration, resolvedType, rev, targetNS string) (string, ctrl.Result, error) {
	var appliedHash string
	switch resolvedType {
	case string(octovaultv1alpha1.OutputConfigMap):
		data := make(map[string]string, len(doc.Spec.Data))
		for _, it := range doc.Spec.Data {

			k := strings.TrimSpace(it.Key)
			if k == "" {

				r.updateStatusIfChanged(ctx, ov, fail("InvalidData", "data.key must be non-empty"))
				return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("data.key must be non-empty")
			}
			data[k] = it.Value
		}
		appliedHash = sha256OfStringMap(data)

		if err := r.applyConfigMap(ctx, ov, targetNS, ov.Spec.TargetName, rev, data); err != nil {

			r.updateStatusIfChanged(ctx, ov, fail("ApplyFailed", fmt.Sprintf("failed to apply configmap: %v", err)))
			return "", ctrl.Result{RequeueAfter: poll}, err
		}

	case string(octovaultv1alpha1.OutputSecret):
		bytes := make(map[string][]byte, len(doc.Spec.Data))
		var extRefs []octovaultv1alpha1.ExternalRefStatus

		for _, it := range doc.Spec.Data {

			k := strings.TrimSpace(it.Key)
			if k == "" {

				r.updateStatusIfChanged(ctx, ov, fail("InvalidData", "data.key must be non-empty"))
				return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("data.key must be non-empty")
			}
			switch strings.ToLower(strings.TrimSpace(it.Type)) {
			case "", "text":
				bytes[k] = []byte(it.Value)
			case "awssecretmanager":

				if r.AwsSM == nil {

					r.updateStatusIfChanged(ctx, ov, fail("AwsNotConfigured", "AwsSecretManager type requires controller to be configured with AWS provider"))

					return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("AwsSecretManager type requires controller to be configured with AWS provider")
				}

				name := strings.TrimSpace(it.Name)
				if name == "" {

					r.updateStatusIfChanged(ctx, ov, fail("InvalidData",
						fmt.Sprintf("Secret data item %q missing 'name' for AwsSecretManager", k)))

					return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("secret data item %q missing 'name' for AwsSecretManager", name)
				}

				val, meta, err2 := r.AwsSM.GetSecret(ctx, name)
				if err2 != nil {

					r.updateStatusIfChanged(ctx, ov, fail("AwsSecretFetchFailed",
						fmt.Sprintf("failed to fetch from AWS secret manager %q: %v", name, err2)))

					return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("failed to fetch from AWS secret manager %q: %v", name, err2)
				}

				if jk := strings.TrimSpace(it.JSONKey); jk != "" {
					var err error
					val, err = r.AwsSM.ExtractJSONKey(val, jk)
					if err != nil {

						r.updateStatusIfChanged(ctx, ov, fail("AWSSecretJSONKeyError",
							fmt.Sprintf("aws secret %q jsonKey=%q: %v", name, jk, err)))

						return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("aws secret %q jsonKey=%q: %v", name, jk, err)
					}
				}

				bytes[k] = val

				extRefs = append(extRefs, octovaultv1alpha1.ExternalRefStatus{
					Provider:      "AwsSecretsManager",
					Name:          name,
					VersionID:     meta.VersionID,
					VersionStages: meta.VersionStages,
					Key:           k,
				})

			case "awsparameterstore", "parameterstore", "ssm":
				if r.AwsPS == nil {

					r.updateStatusIfChanged(ctx, ov, fail("ExternalSourceUnavailable",
						fmt.Sprintf("AwsParameterStore provider unavailable for %q", k)))

					return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("AwsParameterStore provider unavailable for %q", k)
				}
				paramName := strings.TrimSpace(it.Name)
				if paramName == "" {

					r.updateStatusIfChanged(ctx, ov, fail("InvalidData",
						fmt.Sprintf("Secret data item %q requires .name for AwsParameterStore", k)))

					return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("secret data item %q requires .name for AwsParameterStore", k)
				}
				// SecureString 가능성이 있으므로 복호화 활성화
				pv, _, err2 := r.AwsPS.GetParameter(ctx, paramName, true)
				if err2 != nil {

					r.updateStatusIfChanged(ctx, ov, fail("ExternalSourceFetchFailed",
						fmt.Sprintf("failed to fetch from AWS parameter store %q: %v", paramName, err2)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}
				if jk := strings.TrimSpace(it.JSONKey); jk != "" {
					// 값이 JSON일 때 특정 키만
					if out, err := r.AwsPS.ExtractJSONKey(pv, jk); err != nil {

						r.updateStatusIfChanged(ctx, ov, fail("ExternalJSONExtractFailed",
							fmt.Sprintf("aws parameter %q jsonKey=%q: %v", paramName, jk, err)))

						return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("aws parameter %q jsonKey=%q", paramName, jk)
					} else {

						pv = out
					}
				}

				bytes[k] = pv

			default:

				r.updateStatusIfChanged(ctx, ov, fail("UnsupportedDataType",
					fmt.Sprintf("unsupported data.type %q for key %q", it.Type, k)))

				return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("unsupported data.type %q for key %q", it.Type, k)
			}
		}

		appliedHash = sha256OfBytesMap(bytes)
		if err := r.applySecret(ctx, ov, targetNS, ov.Spec.TargetName, rev, bytes); err != nil {

			r.updateStatusIfChanged(ctx, ov, fail("ApplyFailed",
				fmt.Sprintf("failed to apply secret: %v", err)))

			return "", ctrl.Result{RequeueAfter: poll}, err
		}

		// AWS SM 등 외부 참조에 대한 요약 상태 업데이트
		if len(extRefs) > 0 {
			ov.Status.ExternalRefs = extRefs
			ov.Status.ExternalRefsSummary = summarizeExtRefs(extRefs)
		} else {

			ov.Status.ExternalRefs = nil
			ov.Status.ExternalRefsSummary = ""
		}
	}

	return appliedHash, ctrl.Result{}, nil
}
func (r *OctoVaultReconciler) setSyncedStatus(ctx context.Context, ov *octovaultv1alpha1.OctoVault, appliedHash, resolvedType, rev string) {

	targetNS := ov.Spec.TargetNamespace
	if targetNS == "" {

		targetNS = ov.Namespace
	}

	now := metav1.Now()
	next := ov.Status
	next.Phase = octovaultv1alpha1.OVPhaseSynced
	next.Message = ""
	next.ObservedRevision = rev
	next.LastSyncedTime = &now
	next.AppliedDataHash = appliedHash
	next.ResolvedType = resolvedType
	next.Conditions = upsertReadyCondition(next.Conditions, metav1.ConditionTrue, "Synced", "values applied")

	r.updateStatusIfChanged(ctx, ov, next)
	r.Recorder.Eventf(ov, corev1.EventTypeNormal, "Synced",
		"OctoVault synced: revision=%s, type=%s, target=%s/%s", rev, resolvedType, targetNS, ov.Spec.TargetName)
}

func (r *OctoVaultReconciler) fetch(ctx context.Context, org, repo, path, ref, token string) ([]byte, []byte, string, error) {
	if r.Git == nil {

		return nil, nil, "", fmt.Errorf("git fetcher not configured")
	}

	return r.Git.Fetch(ctx, org, repo, path, ref, token)
}

func (r *OctoVaultReconciler) applyConfigMap(ctx context.Context, ov *octovaultv1alpha1.OctoVault, ns, name, rev string, data map[string]string) error {

	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &cm)

	if apierrors.IsNotFound(err) {

		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"reconcile.octovault.it/managed-by": "octovault",
					"reconcile.octovault.it/owner":      ov.Name,
					"reconcile.octovault.it/revision":   rev,
				},
				Annotations: map[string]string{
					"reconcile.octovault.it/data-hash": sha256OfStringMap(data),
				},
				Name:      name,
				Namespace: ns,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(ov, ov.GroupVersionKind()),
				},
			},
			Data: data,
		}

		setManagedLabels(&cm.ObjectMeta, ov)

		return r.Create(ctx, &cm)
	} else if err != nil {

		return err
	}

	setManagedLabels(&cm.ObjectMeta, ov)

	if !equalStringMap(cm.Data, data) {
		if cm.Data == nil {

			cm.Data = map[string]string{}
		}

		for k := range cm.Data {

			delete(cm.Data, k)
		}

		for k, v := range data {

			cm.Data[k] = v
		}

		return r.Update(ctx, &cm)
	}

	return r.Update(ctx, &cm)
}

func (r *OctoVaultReconciler) applySecret(ctx context.Context, ov *octovaultv1alpha1.OctoVault, ns, name, rev string, data map[string][]byte) error {

	var sec corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &sec)

	if apierrors.IsNotFound(err) {

		sec = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"reconcile.octovault.it/managed-by": "octovault",
					"reconcile.octovault.it/owner":      ov.Name,
					"reconcile.octovault.it/revision":   rev,
				},
				Annotations: map[string]string{
					"reconcile.octovault.it/data-hash": sha256OfBytesMap(data),
				},
				Name:      name,
				Namespace: ns,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(ov, ov.GroupVersionKind()),
				},
			},
			Data: data,
			Type: corev1.SecretTypeOpaque,
		}

		setManagedLabels(&sec.ObjectMeta, ov)

		return r.Create(ctx, &sec)
	} else if err != nil {

		return err
	}

	setManagedLabels(&sec.ObjectMeta, ov)

	if !equalBytesMap(sec.Data, data) {
		if sec.Data == nil {

			sec.Data = map[string][]byte{}
		}

		for k := range sec.Data {

			delete(sec.Data, k)
		}

		for k, v := range data {

			sec.Data[k] = v
		}

		return r.Update(ctx, &sec)
	}

	return r.Update(ctx, &sec)
}

func (r *OctoVaultReconciler) orphanTargets(ctx context.Context, ov *octovaultv1alpha1.OctoVault) error {

	targetNS := ov.Spec.TargetNamespace
	if targetNS == "" {

		targetNS = ov.Namespace
	}

	// remove ownerRef가 실제로 뭔가 바꿨는지 반환
	removeOwner := func(obj metav1.Object) bool {

		owners := obj.GetOwnerReferences()
		if len(owners) == 0 {

			return false
		}

		changed := false
		kept := make([]metav1.OwnerReference, 0, len(owners))
		for _, o := range owners {
			if o.UID == ov.UID {

				changed = true
				continue
			}

			kept = append(kept, o)
		}

		if changed {

			obj.SetOwnerReferences(kept)
			a := obj.GetAnnotations()
			if a == nil {

				a = map[string]string{}
			}

			a[AnnoOVRetainedBy] = ov.Namespace + "/" + ov.Name
			obj.SetAnnotations(a)
		}

		return changed
	}

	var firstErr error
	tryCM := func() {

		var cm corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Namespace: targetNS, Name: ov.Spec.TargetName}, &cm); err == nil {
			if removeOwner(&cm.ObjectMeta) {
				if err := r.Update(ctx, &cm); err != nil && firstErr == nil {

					firstErr = err
				}
			}
		}
	}

	trySec := func() {

		var sec corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: targetNS, Name: ov.Spec.TargetName}, &sec); err == nil {
			if removeOwner(&sec.ObjectMeta) {
				if err := r.Update(ctx, &sec); err != nil && firstErr == nil {

					firstErr = err
				}
			}
		}
	}

	switch strings.ToLower(strings.TrimSpace(ov.Status.ResolvedType)) {
	case strings.ToLower(string(octovaultv1alpha1.OutputConfigMap)):
		tryCM()
	case strings.ToLower(string(octovaultv1alpha1.OutputSecret)):
		trySec()
	default:
		return fmt.Errorf("unknown resolvedType %q", ov.Status.ResolvedType)
	}

	return firstErr
}

func (r *OctoVaultReconciler) updateStatusIfChanged(ctx context.Context, ov *octovaultv1alpha1.OctoVault, desired octovaultv1alpha1.OctoVaultStatus) {
	prev := ov.Status
	if statusEqualOV(prev, desired) {

		return
	}

	ov.Status = desired
	if err := r.Status().Update(ctx, ov); err != nil {

		logf.FromContext(ctx).Error(err, "status update failed")
	}
}

func fail(reason, msg string) octovaultv1alpha1.OctoVaultStatus {
	return octovaultv1alpha1.OctoVaultStatus{
		Phase:      octovaultv1alpha1.OVPhaseFailed,
		Message:    msg,
		Conditions: upsertCond(nil, CondReady, metav1.ConditionFalse, reason, msg),
	}
}

func upsertCond(conds []metav1.Condition, t string, s metav1.ConditionStatus, reason, msg string) []metav1.Condition {
	now := metav1.Now()
	for i := range conds {
		if conds[i].Type == t {
			if conds[i].Status != s || conds[i].Reason != reason || conds[i].Message != msg {

				conds[i].Status = s
				conds[i].Reason = reason
				conds[i].Message = msg
				conds[i].LastTransitionTime = now
			}

			return conds
		}
	}

	return append(conds, metav1.Condition{
		Type:               t,
		Status:             s,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: now,
	})
}

func statusEqualOV(a, b octovaultv1alpha1.OctoVaultStatus) bool {
	if a.Phase != b.Phase || a.Message != b.Message || a.ObservedRevision != b.ObservedRevision || a.AppliedDataHash != b.AppliedDataHash || a.ResolvedType != b.ResolvedType {

		return false
	}

	var ar, br *metav1.Condition
	for i := range a.Conditions {
		if a.Conditions[i].Type == CondReady {

			ar = &a.Conditions[i]
			break
		}
	}

	for i := range b.Conditions {
		if b.Conditions[i].Type == CondReady {

			br = &b.Conditions[i]
			break
		}
	}

	if (ar == nil) != (br == nil) {

		return false
	}

	if ar != nil && br != nil {
		if ar.Status != br.Status || ar.Reason != br.Reason || ar.Message != br.Message {

			return false
		}
	}

	return true
}

func parseDurationOr(s string, d time.Duration) time.Duration {
	if s == "" {

		return d
	}

	if v, err := time.ParseDuration(s); err == nil && v > 0 {

		return v
	}

	return d
}

func normalizeRepoName(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {

			return s[i+1:]
		}
	}

	return s
}

func shortSHA(b []byte) string {

	h := sha256.New()
	h.Write(b)

	return hex.EncodeToString(h.Sum(nil))[:8]
}

func sha256OfStringMap(m map[string]string) string {
	if len(m) == 0 {

		return ""
	}

	keys := make([]string, 0, len(m))
	for k := range m {

		keys = append(keys, k)
	}

	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {

		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(m[k]))
		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil))
}

func sha256OfBytesMap(m map[string][]byte) string {
	if len(m) == 0 {

		return ""
	}

	keys := make([]string, 0, len(m))
	for k := range m {

		keys = append(keys, k)
	}

	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {

		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(m[k])
		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil))
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {

		return false
	}

	for k, va := range a {
		if vb, ok := b[k]; !ok || va != vb {

			return false
		}
	}

	return true
}

func equalBytesMap(a, b map[string][]byte) bool {
	if len(a) != len(b) {

		return false
	}

	for k, va := range a {
		vb, ok := b[k]

		if !ok || string(va) != string(vb) {

			return false
		}
	}

	return true
}

func getFromSecret(s *corev1.Secret, key string) string {
	if v, ok := s.Data[key]; ok && len(v) > 0 {

		return string(v)
	}

	if s.StringData != nil {
		if v, ok := s.StringData[key]; ok && v != "" {

			return v
		}
	}

	if v := s.Annotations["octovault.it/"+key]; v != "" {

		return v
	}

	return ""
}

func summarizeExtRefs(refs []octovaultv1alpha1.ExternalRefStatus) string {
	if len(refs) == 0 {

		return ""
	}

	parts := make([]string, 0, len(refs))
	for _, r := range refs {

		st := ""
		if len(r.VersionStages) > 0 {

			st = "[" + strings.Join(r.VersionStages, ",") + "]"
		}

		// key=name@vid[stages]
		parts = append(parts, fmt.Sprintf("%s=%s@%s%s", r.Key, r.Name, r.VersionID, st))
	}

	// 너무 길어지는 경우, k8s printer가 자르겠지만 기본 합침
	return strings.Join(parts, "; ")
}

func (r *OctoVaultReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// 핫루프 방지
	b := ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxWorkers(),
		}).
		For(&octovaultv1alpha1.OctoVault{}, builder.WithPredicates(predicate.GenerationChangedPredicate{}))

	// OctoRepository -> OctoVault Requeue ( 인덱서: octoRepositoryRef.name )
	mapOrepoToOV := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		var list octovaultv1alpha1.OctoVaultList
		if err := r.List(ctx, &list,
			client.MatchingFields{"spec.octoRepositoryRef.name": obj.GetName()}); err != nil {

			return nil
		}

		reqs := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {

			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: list.Items[i].Namespace,
				Name:      list.Items[i].Name,
			}})
		}

		return reqs
	})

	b = b.Watches(&octovaultv1alpha1.OctoRepository{}, mapOrepoToOV)

	return b.Complete(r)
}

func (r *OctoVaultReconciler) maxWorkers() int {
	if r.Workers > 0 {

		return r.Workers
	}

	return 1
}
