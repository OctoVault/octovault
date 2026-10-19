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
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	awsps "github.com/octovault/octovault/internal/aws/parameter_store"
	awssm "github.com/octovault/octovault/internal/aws/secret_manager"
	ghclient "github.com/octovault/octovault/internal/github"
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

// DefaultPollInterval spec.pollInterval 이 비었을 때의 기본 폴링 주기.
//
// 이전 기본값 1m 은 OctoVault 하나당 시간당 180 요청을 소모해 PAT 한도(5000/h)를
// 28개면 고갈시켰다. ETag 조건부 요청과 함께 쓰면 실제 소모는 이보다 훨씬 낮다.
const DefaultPollInterval = 5 * time.Minute

const (
	CondReady = "Ready"

	LabelManagedBy   = "app.kubernetes.io/managed-by"
	LabelOVOwnerNS   = "octovault.it/owner-ns"   // <namespace>
	LabelOVOwnerName = "octovault.it/owner-name" // <name>
	AnnoOVOwnerFull  = "octovault.it/owner"      // "<ns>/<name>"
	AnnoOVRetainedBy = "octovault.it/retained-from"
	// AnnoOVAdopt 이 값이 "true" 인 기존 대상만 OctoVault 가 이어받는다(claimTarget).
	AnnoOVAdopt = "octovault.it/adopt"
	FinalizerOV = "octovault.it/finalizer"
)

func labelSafe(v string) string {
	if len(v) <= 63 {

		return v
	}

	sum := sha1.Sum([]byte(v))
	return v[:31] + "-" + hex.EncodeToString(sum[:4])
}

func buildSysLabels(ov *octovaultv1alpha1.OctoVault, rev string) map[string]string {

	return map[string]string{
		"reconcile.octovault.it/managed-by": "octovault",
		"reconcile.octovault.it/owner":      labelSafe(ov.Name),
		"reconcile.octovault.it/revision":   rev,
		LabelManagedBy:                      "octovault",
		LabelOVOwnerNS:                      ov.Namespace,
		LabelOVOwnerName:                    labelSafe(ov.Name),
	}
}

func buildSysAnnotations(ov *octovaultv1alpha1.OctoVault, dataHash string) map[string]string {

	return map[string]string{
		"reconcile.octovault.it/data-hash": dataHash,
		AnnoOVOwnerFull:                    ov.Namespace + "/" + labelSafe(ov.Name),
	}
}

// values.yaml 모델
// ConfigMap/Secret 공용: metadata.type
// ConfigMap: spec.data[].{key.value}
// Secret: spec.data[].{key,type,value,name}
type valuesDoc struct {
	Metadata struct {
		Type        string            `yaml:"type"`
		Annotations map[string]string `yaml:"annotations,omitempty"`
		Labels      map[string]string `yaml:"labels,omitempty"`
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

// errTargetNotOwned 같은 이름의 ConfigMap/Secret 이 이미 있지만 이 OctoVault 가 소유하지 않은 경우.
// 덮어쓰면 OctoVault 생성 권한만으로 컨트롤러 권한을 빌려 남의 리소스를 바꿀 수 있게 된다.
var errTargetNotOwned = errors.New("target exists and is not controlled by this OctoVault")

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

	// reservedWarned UID → 이미 알린, values.yaml 에서 무시한 octovault.it 키 목록.
	reservedWarned sync.Map
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

	// 삭제 중이면 대상 리소스에서 이 OctoVault 의 ownerRef 를 떼어 GC 되지 않게 남긴 뒤 파이널라이저를 지운다.
	if !ov.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ov, FinalizerOV) {

			// 실패한 채로 파이널라이저를 지우면 ownerRef 가 남아 대상이 GC 로 삭제된다.
			if err := r.orphanTargets(ctx, &ov); err != nil {

				logger.Error(err, "failed to orphan targets; keeping finalizer")
				return ctrl.Result{}, err
			}

			controllerutil.RemoveFinalizer(&ov, FinalizerOV)

			if err := r.Update(ctx, &ov); err != nil {

				logger.Error(err, "failed to remove finalizer")
				return ctrl.Result{}, err
			}
		}

		// UID 별로 남겨 둔 기록을 지워, 지워진 OctoVault 의 항목이 메모리에 쌓이지 않게 한다.
		r.reservedWarned.Delete(string(ov.UID))

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

	poll := parseDurationOr(ov.Spec.PollInterval, DefaultPollInterval)

	// 아래 헬퍼들은 res 와 err 중 하나만 채워 반환한다.
	// 둘을 함께 반환하면 controller-runtime 이 res 를 버리고 5ms 부터 시작하는
	// 지수 백오프로 재시도하는데, 그 재시도마다 GitHub 를 다시 호출하게 된다.
	//
	// 1) OctoRepository & PAT Secret
	orepo, token, res, err := r.loadRepoAndToken(ctx, &ov)
	if err != nil {

		logger.Error(err, "failed to load repo and token")
		return ctrl.Result{}, err
	}

	if res.RequeueAfter > 0 {

		return res, nil
	}

	// 2) Fetch values.yaml
	valuesYAML, schemaJSON, rev, res := r.tryFetch(ctx, &ov, orepo, token, poll)
	if res.RequeueAfter > 0 {

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

	r.warnReservedKeys(ctx, &ov, doc)

	targetNS := ov.Spec.TargetNamespace
	if targetNS == "" {
		targetNS = ov.Namespace
	}

	if targetNS != ov.Namespace {
		r.updateStatusIfChanged(ctx, &ov, fail(ov.Status, "InvalidTargetNamespace",
			fmt.Sprintf("targetNamespace %q must match OctoVault namespace %q: cross-namespace targets are not supported", targetNS, ov.Namespace)))
		return ctrl.Result{RequeueAfter: poll}, nil
	}

	// 4) apply
	appliedHash, res, err := r.applyOutput(ctx, &ov, doc, poll, resolvedType, rev, targetNS)
	if err != nil {

		logger.Error(err, "failed to apply output")
		return ctrl.Result{}, err
	}

	if res.RequeueAfter > 0 {

		return res, nil
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

	poll := parseDurationOr(ov.Spec.PollInterval, DefaultPollInterval)
	var orepo octovaultv1alpha1.OctoRepository

	if err := r.Get(ctx, types.NamespacedName{Name: ov.Spec.OctoRepositoryRef.Name}, &orepo); err != nil {
		if apierrors.IsNotFound(err) {

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "OctoRepositoryNotFound", fmt.Sprintf("no OctoRepository %q", ov.Spec.OctoRepositoryRef.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{}, err
	}

	var cred corev1.Secret
	secKey := types.NamespacedName{Namespace: orepo.Spec.CredentialsRef.Namespace, Name: orepo.Spec.CredentialsRef.Name}

	if err := r.Get(ctx, secKey, &cred); err != nil {
		if apierrors.IsNotFound(err) {

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "CredentialsNotFound", fmt.Sprintf("no Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{}, err
	}

	token := getFromSecret(&cred, "password")
	if token == "" {

		r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "SecretMissingPassword", fmt.Sprintf("no 'password' key in Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

		return nil, "", ctrl.Result{RequeueAfter: poll}, nil
	}

	if enc := getFromSecret(&cred, "passwordEncoding"); enc == "base64" {

		dec, err := base64.StdEncoding.DecodeString(token)
		if err != nil {

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "SecretInvalidPasswordEncoding", fmt.Sprintf("invalid base64 in 'password' key in Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		token = string(dec)
	}

	return &orepo, token, ctrl.Result{}, nil
}

func (r *OctoVaultReconciler) tryFetch(ctx context.Context, ov *octovaultv1alpha1.OctoVault, orepo *octovaultv1alpha1.OctoRepository, token string, poll time.Duration) ([]byte, []byte, string, ctrl.Result) {

	logger := logf.FromContext(ctx)

	org := orepo.Spec.Organization
	ref := strings.TrimSpace(ov.Spec.GitRef)
	repo := normalizeRepoName(ov.Spec.Repository)
	// ctx context.Context, org, repo, path, ref, token string
	valuesYAML, schemaJSON, rev, err := r.fetch(ctx, org, repo, ov.Spec.Path, ref, token)

	if err != nil {

		// rate limit 이면 GitHub 이 알려준 리셋 시각까지 기다린다.
		// poll 주기로 계속 찔러보면 secondary rate limit 까지 유발한다.
		if retryAfter, limited := ghclient.RetryAfterFor(err); limited {

			logger.Info("github rate limit hit while fetching values; backing off until reset",
				"repository", repo, "path", ov.Spec.Path, "retryAfter", retryAfter)

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "RateLimited", fmt.Sprintf("github rate limit: %v", err)))

			return nil, nil, "", ctrl.Result{RequeueAfter: retryAfter}
		}

		logger.Error(err, "failed to fetch values", "repository", repo, "path", ov.Spec.Path)
		r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "FetchFailed", fmt.Sprintf("failed to fetch values: %v", err)))

		return nil, nil, "", ctrl.Result{RequeueAfter: poll}
	}

	return valuesYAML, schemaJSON, rev, ctrl.Result{}
}

func (r *OctoVaultReconciler) tryValidate(ov *octovaultv1alpha1.OctoVault, valuesYAML, schemaJSON []byte, poll time.Duration) ctrl.Result {
	if r.Validator != nil {
		if err := r.Validator.Validate(valuesYAML, schemaJSON); err != nil {

			r.updateStatusIfChanged(context.Background(), ov, fail(ov.Status, "ValidateFailed", fmt.Sprintf("failed to validate values: %v", err)))

			return ctrl.Result{RequeueAfter: poll}
		}
	}

	return ctrl.Result{}
}

func (r *OctoVaultReconciler) parseAndResolveType(ov *octovaultv1alpha1.OctoVault, valuesYAML []byte, poll time.Duration) (valuesDoc, string, ctrl.Result) {

	var doc valuesDoc
	if err := yaml.Unmarshal(valuesYAML, &doc); err != nil {

		r.updateStatusIfChanged(context.Background(), ov, fail(ov.Status, "ParseFailed", fmt.Sprintf("yaml parse failed: %v", err)))

		return doc, "", ctrl.Result{RequeueAfter: poll}
	}

	resolvedType := strings.TrimSpace(doc.Metadata.Type)
	if resolvedType == "" || (resolvedType != string(octovaultv1alpha1.OutputConfigMap) && resolvedType != string(octovaultv1alpha1.OutputSecret)) {

		r.updateStatusIfChanged(context.Background(), ov, fail(ov.Status, "InvalidType", "metadata.type must be 'ConfigMap' or 'Secret'"))

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

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData", "data.key must be non-empty"))
				return "", ctrl.Result{RequeueAfter: poll}, nil
			}
			data[k] = it.Value
		}
		appliedHash = sha256OfStringMap(data)

		if err := r.applyConfigMap(ctx, ov, targetNS, ov.Spec.TargetName, rev, appliedHash, data, doc.Metadata.Labels, doc.Metadata.Annotations); err != nil {
			// 소유하지 않은 리소스는 재시도해도 결과가 같다. 사용자가 이름을 바꾸거나
			// 기존 리소스를 정리할 때까지 poll 주기로 물러난다.
			if errors.Is(err, errTargetNotOwned) {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "TargetNotOwned", err.Error()))
				return "", ctrl.Result{RequeueAfter: poll}, nil
			}

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ApplyFailed", fmt.Sprintf("failed to apply configmap: %v", err)))
			return "", ctrl.Result{}, err
		}

	case string(octovaultv1alpha1.OutputSecret):
		bytes := make(map[string][]byte, len(doc.Spec.Data))
		var extRefs []octovaultv1alpha1.ExternalRefStatus

		for _, it := range doc.Spec.Data {

			k := strings.TrimSpace(it.Key)
			if k == "" {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData", "data.key must be non-empty"))
				return "", ctrl.Result{RequeueAfter: poll}, fmt.Errorf("data.key must be non-empty")
			}
			switch strings.ToLower(strings.TrimSpace(it.Type)) {
			case "", "text":
				bytes[k] = []byte(it.Value)
			case "awssecretmanager":

				if r.AwsSM == nil {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AwsNotConfigured", "AwsSecretManager type requires controller to be configured with AWS provider"))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}

				name := strings.TrimSpace(it.Name)
				if name == "" {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData",
						fmt.Sprintf("Secret data item %q missing 'name' for AwsSecretManager", k)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}

				val, meta, err2 := r.AwsSM.GetSecret(ctx, name)
				if err2 != nil {

					// 외부 소스 조회 실패는 poll 주기로 물러난다. err 를 반환하면 5ms 백오프로
					// 재시도하면서 이번엔 AWS 쪽 throttling 을 유발한다.
					// AwsParameterStore 경로와 동일하게 처리한다.
					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AwsSecretFetchFailed",
						fmt.Sprintf("failed to fetch from AWS secret manager %q: %v", name, err2)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}

				if jk := strings.TrimSpace(it.JSONKey); jk != "" {
					var err error
					val, err = r.AwsSM.ExtractJSONKey(val, jk)
					if err != nil {

						r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AWSSecretJSONKeyError",
							fmt.Sprintf("aws secret %q jsonKey=%q: %v", name, jk, err)))

						return "", ctrl.Result{RequeueAfter: poll}, nil
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

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalSourceUnavailable",
						fmt.Sprintf("AwsParameterStore provider unavailable for %q", k)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}
				paramName := strings.TrimSpace(it.Name)
				if paramName == "" {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData",
						fmt.Sprintf("Secret data item %q requires .name for AwsParameterStore", k)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}
				// SecureString 가능성이 있으므로 복호화 활성화
				pv, _, err2 := r.AwsPS.GetParameter(ctx, paramName, true)
				if err2 != nil {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalSourceFetchFailed",
						fmt.Sprintf("failed to fetch from AWS parameter store %q: %v", paramName, err2)))

					return "", ctrl.Result{RequeueAfter: poll}, nil
				}
				if jk := strings.TrimSpace(it.JSONKey); jk != "" {

					// 값이 JSON일 때 특정 키만
					out, err := r.AwsPS.ExtractJSONKey(pv, jk)
					if err != nil {

						r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalJSONExtractFailed",
							fmt.Sprintf("aws parameter %q jsonKey=%q: %v", paramName, jk, err)))

						return "", ctrl.Result{RequeueAfter: poll}, nil
					}

					pv = out
				}

				bytes[k] = pv

			default:

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "UnsupportedDataType",
					fmt.Sprintf("unsupported data.type %q for key %q", it.Type, k)))

				return "", ctrl.Result{RequeueAfter: poll}, nil
			}
		}

		appliedHash = sha256OfBytesMap(bytes)
		if err := r.applySecret(ctx, ov, targetNS, ov.Spec.TargetName, rev, appliedHash, bytes, doc.Metadata.Labels, doc.Metadata.Annotations); err != nil {
			// 소유하지 않은 리소스는 재시도해도 결과가 같다. 사용자가 이름을 바꾸거나
			// 기존 리소스를 정리할 때까지 poll 주기로 물러난다.
			if errors.Is(err, errTargetNotOwned) {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "TargetNotOwned", err.Error()))
				return "", ctrl.Result{RequeueAfter: poll}, nil
			}

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ApplyFailed",
				fmt.Sprintf("failed to apply secret: %v", err)))

			return "", ctrl.Result{}, err
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

func (r *OctoVaultReconciler) applyConfigMap(ctx context.Context, ov *octovaultv1alpha1.OctoVault, ns, name, rev, dataHash string, data map[string]string, userLabels, userAnnotations map[string]string) error {

	sysLabels := buildSysLabels(ov, rev)
	sysAnnotations := buildSysAnnotations(ov, dataHash)

	var cm corev1.ConfigMap
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &cm)

	if apierrors.IsNotFound(err) {

		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      mergeLabels(sysLabels, userLabels),
				Annotations: mergeAnnotations(sysAnnotations, userAnnotations),
				Name:        name,
				Namespace:   ns,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(ov, ov.GroupVersionKind()),
				},
			},
			Data: data,
		}

		return r.Create(ctx, &cm)
	} else if err != nil {

		return err
	}

	adopted, owned := claimTarget(&cm.ObjectMeta, ov)
	if !owned {

		return fmt.Errorf("configmap %s/%s: %w", ns, name, errTargetNotOwned)
	}

	desiredLabels := mergeLabels(sysLabels, userLabels)
	desiredAnnotations := mergeAnnotations(sysAnnotations, userAnnotations)

	if !adopted &&
		reflect.DeepEqual(cm.Labels, desiredLabels) &&
		reflect.DeepEqual(cm.Annotations, desiredAnnotations) &&
		reflect.DeepEqual(cm.Data, data) {
		return nil
	}

	// OctoVault owns the resource it creates; labels/annotations are fully replaced
	// by the desired state (system + user-specified keys). Third-party keys not
	// declared in values.yaml are intentionally pruned on each reconcile.
	cm.Labels = desiredLabels
	cm.Annotations = desiredAnnotations
	cm.Data = data

	return r.Update(ctx, &cm)
}

func (r *OctoVaultReconciler) applySecret(ctx context.Context, ov *octovaultv1alpha1.OctoVault, ns, name, rev, dataHash string, data map[string][]byte, userLabels, userAnnotations map[string]string) error {

	sysLabels := buildSysLabels(ov, rev)
	sysAnnotations := buildSysAnnotations(ov, dataHash)

	var sec corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &sec)

	if apierrors.IsNotFound(err) {

		sec = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels:      mergeLabels(sysLabels, userLabels),
				Annotations: mergeAnnotations(sysAnnotations, userAnnotations),
				Name:        name,
				Namespace:   ns,
				OwnerReferences: []metav1.OwnerReference{
					*metav1.NewControllerRef(ov, ov.GroupVersionKind()),
				},
			},
			Data: data,
			Type: corev1.SecretTypeOpaque,
		}

		return r.Create(ctx, &sec)
	} else if err != nil {

		return err
	}

	adopted, owned := claimTarget(&sec.ObjectMeta, ov)
	if !owned {

		return fmt.Errorf("secret %s/%s: %w", ns, name, errTargetNotOwned)
	}

	desiredLabels := mergeLabels(sysLabels, userLabels)
	desiredAnnotations := mergeAnnotations(sysAnnotations, userAnnotations)

	if !adopted &&
		reflect.DeepEqual(sec.Labels, desiredLabels) &&
		reflect.DeepEqual(sec.Annotations, desiredAnnotations) &&
		reflect.DeepEqual(sec.Data, data) {
		return nil
	}

	// OctoVault owns the resource it creates; labels/annotations are fully replaced
	// by the desired state (system + user-specified keys). Third-party keys not
	// declared in values.yaml are intentionally pruned on each reconcile.
	sec.Labels = desiredLabels
	sec.Annotations = desiredAnnotations
	sec.Data = data

	return r.Update(ctx, &sec)
}

// claimTarget 기존 대상을 이 OctoVault 가 관리해도 되는지 판단한다.
//
// 이미 controller 이면 그대로 쓴다. controller 가 없고 octovault.it/adopt: "true" 가 붙어 있으면
// controller ref 를 붙여 이어받는다(adopted=true). 삭제 후 재설치(Helm/Argo)처럼 남겨진 대상을 다시
// 관리하려면 이 어노테이션을 한 번 붙이면 된다. 이어받으면서 대상의 어노테이션은 values.yaml 기준으로
// 다시 쓰이므로 adopt 는 한 번만 쓰인다.
//
// retained-from 이나 owner 어노테이션 같은 이름 기반 흔적만으로는 이어받지 않는다. 그 흔적은 컨트롤러가
// 직접 남기므로, 그것만 믿으면 OctoVault 생성 권한만 있는 사용자가 지워진 OctoVault 와 같은 이름으로
// 만들어, 수정 권한이 없는 Secret 을 덮어쓸 수 있다. adopt 는 그 대상을 수정할 수 있는 주체만 붙일 수
// 있고, values.yaml 로는 넣을 수 없다(isReservedKey).
func claimTarget(obj *metav1.ObjectMeta, ov *octovaultv1alpha1.OctoVault) (adopted, owned bool) {
	if metav1.IsControlledBy(obj, ov) {

		return false, true
	}

	if metav1.GetControllerOf(obj) != nil || obj.GetAnnotations()[AnnoOVAdopt] != "true" {

		return false, false
	}

	obj.OwnerReferences = append(obj.OwnerReferences, *metav1.NewControllerRef(ov, ov.GroupVersionKind()))

	return true, true
}

func (r *OctoVaultReconciler) orphanTargets(ctx context.Context, ov *octovaultv1alpha1.OctoVault) error {

	// 대상은 언제나 OctoVault 와 같은 네임스페이스에 만든다(다른 네임스페이스는 InvalidTargetNamespace 로
	// 거부한다). spec.targetNamespace 를 나중에 다른 값으로 바꿔도 실제 대상은 원래 네임스페이스에 있다.
	targetNS := ov.Namespace

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
	// 이미 지워진 대상(NotFound)은 놓아줄 것이 없으므로 실패로 보지 않는다.
	recordErr := func(err error) {
		if err != nil && !apierrors.IsNotFound(err) && firstErr == nil {

			firstErr = err
		}
	}

	release := func(obj client.Object) {
		if removeOwner(obj) {

			recordErr(r.Update(ctx, obj))
		}
	}

	// 현재 spec.targetName 만 보면 안 된다. targetName 을 바꾸면 이전 이름의 대상도 여전히 이
	// OctoVault 소유로 남아 있어, 그대로 지우면 GC 가 함께 삭제한다. 그래서 생성 시 붙인 owner
	// 라벨로 이 OctoVault 가 만든 대상을 모두 찾는다. 라벨이 없는 오래된 대상을 위해 현재 이름도
	// 직접 확인한다. ResolvedType 과 무관하게 두 종류를 모두 본다(상태가 실제와 어긋날 수 있다).
	// removeOwner 는 이 OctoVault 의 UID 를 가진 ownerRef 만 지우므로 남의 리소스에는 영향이 없다.
	owned := client.MatchingLabels{LabelOVOwnerNS: ov.Namespace, LabelOVOwnerName: labelSafe(ov.Name)}
	current := types.NamespacedName{Namespace: targetNS, Name: ov.Spec.TargetName}

	var cms corev1.ConfigMapList
	recordErr(r.List(ctx, &cms, client.InNamespace(targetNS), owned))
	seenCM := map[string]bool{}
	for i := range cms.Items {

		seenCM[cms.Items[i].Name] = true
		release(&cms.Items[i])
	}

	if !seenCM[current.Name] {

		var cm corev1.ConfigMap
		err := r.Get(ctx, current, &cm)
		recordErr(err)
		if err == nil {

			release(&cm)
		}
	}

	var secs corev1.SecretList
	recordErr(r.List(ctx, &secs, client.InNamespace(targetNS), owned))
	seenSec := map[string]bool{}
	for i := range secs.Items {

		seenSec[secs.Items[i].Name] = true
		release(&secs.Items[i])
	}

	if !seenSec[current.Name] {

		var sec corev1.Secret
		err := r.Get(ctx, current, &sec)
		recordErr(err)
		if err == nil {

			release(&sec)
		}
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

// fail 직전 상태를 바탕으로 실패 상태를 만든다.
//
// ResolvedType, ObservedRevision, LastSyncedTime, ExternalRefs 는 마지막으로 성공한
// 동기화의 기록이므로 실패해도 지우지 않는다. 실패 한 번으로 상태가 실제 대상과 어긋나지 않게 한다.
func fail(prev octovaultv1alpha1.OctoVaultStatus, reason, msg string) octovaultv1alpha1.OctoVaultStatus {

	next := prev
	next.Phase = octovaultv1alpha1.OVPhaseFailed
	next.Message = msg

	// upsertCond 는 슬라이스를 제자리에서 고치므로 복사본을 넘긴다. 그렇지 않으면
	// prev 까지 바뀌어 updateStatusIfChanged 가 변경을 감지하지 못한다.
	conds := append([]metav1.Condition(nil), prev.Conditions...)
	next.Conditions = upsertCond(conds, CondReady, metav1.ConditionFalse, reason, msg)

	return next
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

	// OctoRepository 의 spec 이 바뀔 때만 fan-out 한다.
	//
	// predicate 가 없으면 status-only 업데이트와 informer 의 주기적 resync 까지
	// 이 매핑을 태우고, 그때마다 해당 OctoRepository 를 참조하는 모든 OctoVault 가
	// 한꺼번에 큐에 들어간다. rate limit 초과 -> 프로브 403 -> status 변경 ->
	// 전체 fan-out -> 요청 폭증 -> 한도 더 초과 로 이어지는 양성 피드백 루프가 된다.
	b = b.Watches(&octovaultv1alpha1.OctoRepository{}, mapOrepoToOV,
		builder.WithPredicates(predicate.GenerationChangedPredicate{}))

	return b.Complete(r)
}

func (r *OctoVaultReconciler) maxWorkers() int {
	if r.Workers > 0 {

		return r.Workers
	}

	return 1
}
