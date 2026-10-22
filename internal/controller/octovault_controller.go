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
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	awsps "github.com/octovault/octovault/internal/aws/parameter_store"
	awssm "github.com/octovault/octovault/internal/aws/secret_manager"
	ghclient "github.com/octovault/octovault/internal/github"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"sigs.k8s.io/yaml"

	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

// MinPollInterval spec.pollInterval 의 하한. 이보다 짧은 값은 이 값으로 올린다.
// 한 PAT 를 여러 OctoVault 가 나눠 쓰므로 짧은 주기 하나가 전체 한도를 잠식할 수 있다.
const MinPollInterval = 30 * time.Second

// warnUnparsablePollInterval CRD 패턴은 통과했지만 Go duration 범위를 넘는 값(예: 9999999999h)은
// 기본값으로 쓰되 조용히 넘기지 않는다. 같은 OctoVault 의 같은 값은 한 번만 로그로 남긴다.
// 값이 정상으로 돌아오면(그리고 삭제될 때) 기록을 지워, 기록이 계속 쌓이지 않게 한다.
func (r *OctoVaultReconciler) warnUnparsablePollInterval(ctx context.Context, ov *octovaultv1alpha1.OctoVault) {

	uid := string(ov.UID)
	v := strings.TrimSpace(ov.Spec.PollInterval)
	_, err := time.ParseDuration(v)
	if v == "" || err == nil {

		r.pollWarned.Delete(uid)
		return
	}

	if prev, seen := r.pollWarned.Swap(uid, v); seen && prev == v {

		return
	}

	logf.FromContext(ctx).Info("spec.pollInterval cannot be parsed; using the default",
		"pollInterval", v, "default", DefaultPollInterval, "error", err.Error())
	r.Recorder.Eventf(ov, corev1.EventTypeWarning, "InvalidPollInterval",
		"spec.pollInterval %q cannot be used (%v); polling every %s instead", v, err, DefaultPollInterval)
}

// pollIntervalOf spec.pollInterval 을 해석한다. 비었거나, 0 이거나, 해석할 수 없으면 기본값을 쓴다.
// 0 보다 크고 하한보다 짧으면 하한을 쓴다.
//
// 0 을 기본값으로 보는 것은 예전 동작 그대로다. 하한으로 올리면 0m 을 쓰던 OctoVault 가 업그레이드 후
// 5m 대신 30s 마다 polling 해 호출이 10배가 된다.
func pollIntervalOf(ov *octovaultv1alpha1.OctoVault) time.Duration {

	v, err := time.ParseDuration(strings.TrimSpace(ov.Spec.PollInterval))
	if err != nil || v == 0 {

		return DefaultPollInterval
	}

	return max(v, MinPollInterval)
}

const (
	CondReady = "Ready"

	LabelManagedBy   = "app.kubernetes.io/managed-by"
	LabelOVOwnerNS   = "octovault.it/owner-ns"   // <namespace>
	LabelOVOwnerName = "octovault.it/owner-name" // <name>
	AnnoOVOwnerFull  = "octovault.it/owner"      // "<ns>/<name>"
	AnnoOVRetainedBy = "octovault.it/retained-from"
	// AnnoOVAdopt 이 값이 "true" 인 기존 대상만 OctoVault 가 이어받는다(claimTarget).
	AnnoOVAdopt = "octovault.it/adopt"
	// AnnoOVOwnerUID 대상을 관리하는 OctoVault 의 UID. 소유 판단에 ownerReference 대신 쓴다(target_ownership.go).
	AnnoOVOwnerUID = "octovault.it/owner-uid"
	FinalizerOV    = "octovault.it/finalizer"
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
		AnnoOVOwnerUID:                     string(ov.UID),
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

			// WithDecryption AwsParameterStore 의 복호화 여부. 생략하면 true 로 본다
			// (이전 버전은 항상 복호화했으므로 기존 values.yaml 의 동작을 바꾸지 않는다).
			WithDecryption *bool `yaml:"withDecryption,omitempty"`
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

	// statusBackoff conflict 가 아닌 status 기록 실패가 이어질 때 재시도 간격을 늘린다.
	statusBackoff statusBackoff

	// reservedWarned UID → 이미 알린, values.yaml 에서 무시한 octovault.it 키 목록.
	reservedWarned sync.Map

	// SecretCache 라벨로 범위를 좁힌 Secret 캐시. 자격증명 Secret 을 여기서 먼저 찾는다. nil 이면 API 서버만 쓴다.
	SecretCache client.Reader

	// pollWarned UID → 이미 로그로 남긴 해석할 수 없는 pollInterval 값.
	pollWarned sync.Map

	// migrated 이전 버전의 ownerReference 를 이미 정리한 OctoVault UID. 프로세스마다 한 번만 찾는다.
	migrated sync.Map

	// targetConflicts UID → 대상 Update 가 연속으로 conflict 난 횟수(tolerateTargetConflict).
	targetConflicts sync.Map

	// TargetSecrets OctoVault 가 만든 Secret 만 담는 메타데이터 캐시(managed-by 라벨로 제한).
	// 기본 Secret 캐시는 자격증명 Secret 만 담으므로 대상 Secret 변경은 여기서 받는다.
	// nil 이면 대상 Secret 을 watch 하지 않고 poll 주기에만 맞춘다.
	TargetSecrets cache.Cache

	// DefaultRef spec.gitRef 가 비었을 때 Git 이 쓰는 ref(GIT_REF). status.observedRef 표시에만 쓴다.
	DefaultRef string
}

// +kubebuilder:rbac:groups=octovault.it,resources=octovaults,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=octovault.it,resources=octovaults/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=octovault.it,resources=octovaults/finalizers,verbs=update
// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *OctoVaultReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	// status 기록이 실패하면 poll 주기(기본 5분)까지 기다리지 않고 곧 다시 본다(statusWrites).
	ctx, writes := trackStatusWrites(ctx, &r.statusBackoff, req.String())

	return writes.apply(r.reconcile(ctx, req))
}

func (r *OctoVaultReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := logf.FromContext(ctx)

	var ov octovaultv1alpha1.OctoVault
	if err := r.Get(ctx, req.NamespacedName, &ov); err != nil {

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 삭제 중이면 대상 리소스에서 이 OctoVault 의 소유 표시(owner-uid, 이전 버전의 ownerReference)를 지워
	// 대상을 남긴 뒤 파이널라이저를 지운다.
	if !ov.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ov, FinalizerOV) {

			// 실패한 채로 파이널라이저를 지우면 소유 표시가 남는다. 이전 버전의 ownerReference 가 남은
			// 대상은 GC 로 삭제될 수 있다.
			if err := r.orphanTargets(ctx, &ov); err != nil {

				logger.Error(err, "failed to orphan targets; keeping finalizer")
				// 삭제가 끝나지 않는 이유를 kubectl describe 로 볼 수 있게 남긴다(같은 이벤트는 모아서 센다).
				r.Recorder.Eventf(&ov, corev1.EventTypeWarning, "ReleaseTargetsFailed",
					"deletion is waiting: could not release targets: %v", err)
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

		r.pollWarned.Delete(string(ov.UID))
		r.migrated.Delete(string(ov.UID))
		r.targetConflicts.Delete(string(ov.UID))

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

	poll := pollIntervalOf(&ov)
	r.warnUnparsablePollInterval(ctx, &ov)

	// 동기화(GitHub 조회, apply)보다 먼저 한다. 동기화가 실패하는 OctoVault 나 이전 targetName 으로 남은
	// 대상도 ownerReference 가 남아 있으면 foreground 삭제 때 GC 가 지운다.
	r.migrateLegacyOwnerRefs(ctx, &ov)

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

	// revision 은 라벨 값으로도 쓰이므로 라벨에 허용되지 않는 ':' 를 쓰지 않는다.
	if rev == "" {
		rev = "sha256-" + shortSHA(valuesYAML)
	}

	if f := r.validate(valuesYAML, schemaJSON); f != nil {

		r.updateStatusIfChanged(ctx, &ov, fail(ov.Status, f.reason, f.msg))
		return ctrl.Result{RequeueAfter: poll}, nil
	}

	// 3) parse values.yaml
	doc, resolvedType, f := parseValues(valuesYAML)
	if f != nil {

		r.updateStatusIfChanged(ctx, &ov, fail(ov.Status, f.reason, f.msg))
		return ctrl.Result{RequeueAfter: poll}, nil
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
	applied, res, err := r.applyOutput(ctx, &ov, doc, poll, resolvedType, rev, targetNS)
	if err != nil {

		logger.Error(err, "failed to apply output")
		return ctrl.Result{}, err
	}

	if res.RequeueAfter > 0 {

		return res, nil
	}

	r.targetConflicts.Delete(string(ov.UID))

	// 5) 방금 적용한 것과 다른 종류의 대상이 이 OctoVault 소유로 남아 있으면 지운다(metadata.type 전환).
	//
	// "정리가 필요하다"는 기록을 상태에 따로 두지 않고 매번 확인한다. Ready reason 같은 기록은
	// 사이에 끼는 다른 실패(FetchFailed 등)에 덮어써져 재시도가 사라질 수 있다. 확인은 캐시에서
	// 하므로(ConfigMap 은 기본 캐시, Secret 은 메타데이터 캐시) 남은 대상이 없으면 API 호출이 없다.
	// 실패해도 ResolvedType 은 실제로 적용한 종류로 기록해 상태가 사실과 어긋나지 않게 한다.
	if err := r.deleteStaleTarget(ctx, &ov, otherOutputKind(resolvedType)); err != nil {

		r.updateStatusIfChanged(ctx, &ov, fail(r.syncedStatus(&ov, applied), ReasonStaleTargetCleanupFailed,
			fmt.Sprintf("applied %s but failed to delete the previous %s %s/%s: %v",
				resolvedType, otherOutputKind(resolvedType), targetNS, ov.Spec.TargetName, err)))
		return ctrl.Result{RequeueAfter: poll}, nil
	}

	// 6) status
	r.setSyncedStatus(ctx, &ov, applied)

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

	poll := pollIntervalOf(ov)
	var orepo octovaultv1alpha1.OctoRepository

	if err := r.Get(ctx, types.NamespacedName{Name: ov.Spec.OctoRepositoryRef.Name}, &orepo); err != nil {
		if apierrors.IsNotFound(err) {

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "OctoRepositoryNotFound", fmt.Sprintf("no OctoRepository %q", ov.Spec.OctoRepositoryRef.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{}, err
	}

	// 자격증명 Secret 을 읽기 전에 막아야 한다. 허용되지 않은 네임스페이스가
	// 다른 팀의 토큰으로 private repo 를 읽는 경로가 된다.
	if !namespaceAllowed(&orepo, ov.Namespace) {

		r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "NamespaceNotAllowed", fmt.Sprintf("OctoRepository %q does not allow namespace %q", orepo.Name, ov.Namespace)))

		return nil, "", ctrl.Result{RequeueAfter: poll}, nil
	}

	// "owner/repo" 의 owner 가 OctoRepository 의 조직과 다르면 조용히 다른 조직에서 받아오게 된다.
	// 사용자가 적은 저장소와 실제로 읽는 저장소가 같아야 한다. 자격증명을 읽기 전에 거른다.
	if owner, ok := repositoryOwner(ov.Spec.Repository); ok && !strings.EqualFold(owner, strings.TrimPrefix(strings.TrimSpace(orepo.Spec.Organization), "github.com/")) {

		r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "RepositoryOwnerMismatch",
			fmt.Sprintf("repository owner %q does not match OctoRepository organization %q", owner, orepo.Spec.Organization)))

		return nil, "", ctrl.Result{RequeueAfter: poll}, nil
	}

	var cred corev1.Secret
	secKey := types.NamespacedName{Namespace: orepo.Spec.CredentialsRef.Namespace, Name: orepo.Spec.CredentialsRef.Name}

	if err := getCredentialSecret(ctx, r.SecretCache, r.Client, secKey, &cred); err != nil {
		if apierrors.IsNotFound(err) {

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "CredentialsNotFound", fmt.Sprintf("no Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)))

			return nil, "", ctrl.Result{RequeueAfter: poll}, nil
		}

		return nil, "", ctrl.Result{}, err
	}

	token, err := tokenFromSecret(&cred)
	if err != nil {

		var msg string
		switch {
		case errors.Is(err, errMissingPassword):
			msg = fmt.Sprintf("no 'password' key in Secret %q for OctoRepository %q", cred.Name, orepo.Name) + legacyAnnotationHint(&cred)
		case errors.Is(err, errLegacyPasswordEncoding):
			msg = fmt.Sprintf("Secret %q for OctoRepository %q: %v", cred.Name, orepo.Name, err)
		default:
			msg = fmt.Sprintf("invalid base64 in 'password' key in Secret %q for OctoRepository %q", orepo.Spec.CredentialsRef.Name, orepo.Name)
		}

		r.updateStatusIfChanged(ctx, ov, fail(ov.Status, tokenFailureReason(err), msg))

		return nil, "", ctrl.Result{RequeueAfter: poll}, nil
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

// syncFailure 상태에 기록할 실패. 호출자가 reconcile 의 ctx 로 기록한다.
type syncFailure struct {
	reason string
	msg    string
}

func (r *OctoVaultReconciler) validate(valuesYAML, schemaJSON []byte) *syncFailure {
	if r.Validator == nil {

		return nil
	}

	if err := r.Validator.Validate(valuesYAML, schemaJSON); err != nil {

		return &syncFailure{reason: "ValidateFailed", msg: fmt.Sprintf("failed to validate values: %v", err)}
	}

	return nil
}

func parseValues(valuesYAML []byte) (valuesDoc, string, *syncFailure) {

	var doc valuesDoc
	if err := yaml.Unmarshal(valuesYAML, &doc); err != nil {

		return doc, "", &syncFailure{reason: "ParseFailed", msg: fmt.Sprintf("yaml parse failed: %v", err)}
	}

	resolvedType := strings.TrimSpace(doc.Metadata.Type)
	if resolvedType != string(octovaultv1alpha1.OutputConfigMap) && resolvedType != string(octovaultv1alpha1.OutputSecret) {

		return doc, "", &syncFailure{reason: "InvalidType", msg: "metadata.type must be 'ConfigMap' or 'Secret'"}
	}

	return doc, resolvedType, nil
}

// appliedOutput 대상에 적용한 결과. 상태에는 setSyncedStatus 가 한 번에 기록한다.
type appliedOutput struct {
	resolvedType string
	rev          string
	hash         string
	extRefs      []octovaultv1alpha1.ExternalRefStatus
}

func (r *OctoVaultReconciler) applyOutput(ctx context.Context, ov *octovaultv1alpha1.OctoVault, doc valuesDoc, poll time.Duration, resolvedType, rev, targetNS string) (appliedOutput, ctrl.Result, error) {

	var appliedHash string
	var extRefs []octovaultv1alpha1.ExternalRefStatus
	switch resolvedType {
	case string(octovaultv1alpha1.OutputConfigMap):
		data := make(map[string]string, len(doc.Spec.Data))
		for _, it := range doc.Spec.Data {

			k := strings.TrimSpace(it.Key)
			if k == "" {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData", "data.key must be non-empty"))
				return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
			}
			data[k] = it.Value
		}
		appliedHash = sha256OfStringMap(data)

		if err := r.applyConfigMap(ctx, ov, targetNS, ov.Spec.TargetName, rev, appliedHash, data, doc.Metadata.Labels, doc.Metadata.Annotations); err != nil {
			// 소유하지 않은 리소스는 재시도해도 결과가 같다. 사용자가 이름을 바꾸거나
			// 기존 리소스를 정리할 때까지 poll 주기로 물러난다.
			if errors.Is(err, errTargetNotOwned) {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "TargetNotOwned", err.Error()))
				return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
			}

			if apierrors.IsConflict(err) && r.tolerateTargetConflict(ov) {

				return appliedOutput{}, ctrl.Result{RequeueAfter: StatusRetryInterval}, nil
			}

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ApplyFailed", fmt.Sprintf("failed to apply configmap: %v", err)))
			return appliedOutput{}, ctrl.Result{}, err
		}

	case string(octovaultv1alpha1.OutputSecret):
		bytes := make(map[string][]byte, len(doc.Spec.Data))

		for _, it := range doc.Spec.Data {

			k := strings.TrimSpace(it.Key)
			if k == "" {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData", "data.key must be non-empty"))
				return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
			}
			switch strings.ToLower(strings.TrimSpace(it.Type)) {
			case "", "text":
				bytes[k] = []byte(it.Value)
			case "awssecretmanager":

				if r.AwsSM == nil {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AwsNotConfigured", "AwsSecretManager type requires controller to be configured with AWS provider"))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}

				name := strings.TrimSpace(it.Name)
				if name == "" {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData",
						fmt.Sprintf("Secret data item %q missing 'name' for AwsSecretManager", k)))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}

				val, meta, err2 := r.AwsSM.GetSecret(ctx, name)
				if err2 != nil {

					// 외부 소스 조회 실패는 poll 주기로 물러난다. err 를 반환하면 5ms 백오프로
					// 재시도하면서 이번엔 AWS 쪽 throttling 을 유발한다.
					// AwsParameterStore 경로와 동일하게 처리한다.
					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AwsSecretFetchFailed",
						fmt.Sprintf("failed to fetch from AWS secret manager %q: %v", name, err2)))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}

				if jk := strings.TrimSpace(it.JSONKey); jk != "" {
					var err error
					val, err = r.AwsSM.ExtractJSONKey(val, jk)
					if err != nil {

						r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "AWSSecretJSONKeyError",
							fmt.Sprintf("aws secret %q jsonKey=%q: %v", name, jk, err)))

						return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
					}
				}

				bytes[k] = val

				extRefs = append(extRefs, octovaultv1alpha1.ExternalRefStatus{
					Provider:  "AwsSecretsManager",
					Name:      name,
					VersionID: meta.VersionID,
					// 순서가 바뀌어도 같은 상태로 보도록 정렬한다(AWS 가 순서를 보장하지 않는다).
					VersionStages: sortedCopy(meta.VersionStages),
					Key:           k,
				})

			case "awsparameterstore", "parameterstore", "ssm":
				if r.AwsPS == nil {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalSourceUnavailable",
						fmt.Sprintf("AwsParameterStore provider unavailable for %q", k)))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}
				paramName := strings.TrimSpace(it.Name)
				if paramName == "" {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "InvalidData",
						fmt.Sprintf("Secret data item %q requires .name for AwsParameterStore", k)))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}
				withDecryption := it.WithDecryption == nil || *it.WithDecryption
				pv, psMeta, err2 := r.AwsPS.GetParameter(ctx, paramName, withDecryption)
				if err2 != nil {

					r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalSourceFetchFailed",
						fmt.Sprintf("failed to fetch from AWS parameter store %q: %v", paramName, err2)))

					return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
				}
				if jk := strings.TrimSpace(it.JSONKey); jk != "" {

					// 값이 JSON일 때 특정 키만
					out, err := r.AwsPS.ExtractJSONKey(pv, jk)
					if err != nil {

						r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ExternalJSONExtractFailed",
							fmt.Sprintf("aws parameter %q jsonKey=%q: %v", paramName, jk, err)))

						return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
					}

					pv = out
				}

				bytes[k] = pv

				extRefs = append(extRefs, octovaultv1alpha1.ExternalRefStatus{
					Provider:  "AwsParameterStore",
					Name:      paramName,
					VersionID: strconv.FormatInt(psMeta.Version, 10),
					Key:       k,
				})

			default:

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "UnsupportedDataType",
					fmt.Sprintf("unsupported data.type %q for key %q", it.Type, k)))

				return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
			}
		}

		appliedHash = sha256OfBytesMap(bytes)
		if err := r.applySecret(ctx, ov, targetNS, ov.Spec.TargetName, rev, appliedHash, bytes, doc.Metadata.Labels, doc.Metadata.Annotations); err != nil {
			// 소유하지 않은 리소스는 재시도해도 결과가 같다. 사용자가 이름을 바꾸거나
			// 기존 리소스를 정리할 때까지 poll 주기로 물러난다.
			if errors.Is(err, errTargetNotOwned) {

				r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "TargetNotOwned", err.Error()))
				return appliedOutput{}, ctrl.Result{RequeueAfter: poll}, nil
			}

			if apierrors.IsConflict(err) && r.tolerateTargetConflict(ov) {

				return appliedOutput{}, ctrl.Result{RequeueAfter: StatusRetryInterval}, nil
			}

			r.updateStatusIfChanged(ctx, ov, fail(ov.Status, "ApplyFailed",
				fmt.Sprintf("failed to apply secret: %v", err)))

			return appliedOutput{}, ctrl.Result{}, err
		}
	}

	return appliedOutput{resolvedType: resolvedType, rev: rev, hash: appliedHash, extRefs: extRefs}, ctrl.Result{}, nil
}

// ReasonStaleTargetCleanupFailed 타입 전환 후 이전 종류의 대상을 지우지 못했다. 다음 poll 에서 다시 시도한다.
const ReasonStaleTargetCleanupFailed = "StaleTargetCleanupFailed"

// staleSecretExpected 이전 출력이 Secret 이었거나 지난 정리가 실패해, 남은 Secret 이 있을 수 있다.
func staleSecretExpected(ov *octovaultv1alpha1.OctoVault) bool {
	if ov.Status.ResolvedType == string(octovaultv1alpha1.OutputSecret) {

		return true
	}

	for _, c := range ov.Status.Conditions {
		if c.Type == CondReady && c.Reason == ReasonStaleTargetCleanupFailed {

			return true
		}
	}

	return false
}

func otherOutputKind(kind string) string {
	if kind == string(octovaultv1alpha1.OutputConfigMap) {

		return string(octovaultv1alpha1.OutputSecret)
	}

	return string(octovaultv1alpha1.OutputConfigMap)
}

func (r *OctoVaultReconciler) setSyncedStatus(ctx context.Context, ov *octovaultv1alpha1.OctoVault, out appliedOutput) {

	targetNS := ov.Spec.TargetNamespace
	if targetNS == "" {

		targetNS = ov.Namespace
	}

	// 이벤트는 상태가 실제로 바뀔 때만 남긴다. 매 폴링마다 남기면 OctoVault 수에 비례해
	// 의미 없는 이벤트가 쌓인다.
	if r.updateStatusIfChanged(ctx, ov, r.syncedStatus(ov, out)) {

		r.Recorder.Eventf(ov, corev1.EventTypeNormal, "Synced",
			"OctoVault synced: revision=%s, type=%s, target=%s/%s", out.rev, out.resolvedType, targetNS, ov.Spec.TargetName)
	}
}

// syncedStatus 적용 결과를 반영한 Synced 상태. 기록은 호출자가 한다.
func (r *OctoVaultReconciler) syncedStatus(ov *octovaultv1alpha1.OctoVault, out appliedOutput) octovaultv1alpha1.OctoVaultStatus {

	now := metav1.Now()
	next := ov.Status
	next.Phase = octovaultv1alpha1.OVPhaseSynced
	next.Message = ""
	next.ObservedRevision = out.rev
	next.ObservedRef = r.effectiveRef(ov)
	next.LastSyncedTime = &now
	next.AppliedDataHash = out.hash
	next.ResolvedType = out.resolvedType
	next.ExternalRefs = out.extRefs
	next.ExternalRefsSummary = summarizeExtRefs(out.extRefs)
	next.Conditions = upsertReadyCondition(next.Conditions, metav1.ConditionTrue, "Synced", "values applied")

	return next
}

// maxSilentTargetConflicts 대상 Update conflict 를 실패로 기록하지 않고 다시 시도하는 연속 횟수.
const maxSilentTargetConflicts = 3

// tolerateTargetConflict 대상 Update 의 conflict 를 조용히 다시 시도해도 되면 true.
//
// conflict 는 대상이 그사이 바뀌었다는 뜻이다. 대부분 곧 풀린다(ConfigMap 은 캐시가 방금 쓴 내용을 아직
// 받지 못한 경우, 예: 마이그레이션 직후). 하지만 다른 컨트롤러가 같은 대상을 계속 고치면 영원히
// 이어지므로, 연속 maxSilentTargetConflicts 번을 넘으면 ApplyFailed 로 드러낸다. 성공하면 초기화한다.
func (r *OctoVaultReconciler) tolerateTargetConflict(ov *octovaultv1alpha1.OctoVault) bool {

	n := 1
	if v, ok := r.targetConflicts.Load(string(ov.UID)); ok {

		n = v.(int) + 1
	}

	r.targetConflicts.Store(string(ov.UID), n)

	return n <= maxSilentTargetConflicts
}

// effectiveRef 동기화에 쓴 ref. 둘 다 비어 있으면 저장소의 기본 브랜치를 뜻하는 빈 문자열이다.
func (r *OctoVaultReconciler) effectiveRef(ov *octovaultv1alpha1.OctoVault) string {
	if ref := strings.TrimSpace(ov.Spec.GitRef); ref != "" {

		return ref
	}

	return strings.TrimSpace(r.DefaultRef)
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
			},
			Data: data,
		}

		return r.Create(ctx, &cm)
	} else if err != nil {

		return err
	}

	adopted, owned := r.claimTarget(ctx, &cm.ObjectMeta, ov)
	if !owned {

		return fmt.Errorf("configmap %s/%s: %w", ns, name, errTargetNotOwned)
	}

	// 이전 버전이 붙인 ownerReference 를 뗀다. 남겨 두면 foreground 삭제에서 GC 가 대상을 지운다.
	migrated := dropLegacyOwnerRef(&cm.ObjectMeta, ov.UID)

	desiredLabels := mergeLabels(sysLabels, userLabels)
	desiredAnnotations := mergeAnnotations(sysAnnotations, userAnnotations)

	if !adopted && !migrated &&
		reflect.DeepEqual(cm.Labels, desiredLabels) &&
		reflect.DeepEqual(cm.Annotations, desiredAnnotations) &&
		reflect.DeepEqual(cm.Data, data) &&
		len(cm.BinaryData) == 0 {
		return nil
	}

	// OctoVault owns the resource it creates; labels/annotations are fully replaced
	// by the desired state (system + user-specified keys). Third-party keys not
	// declared in values.yaml are intentionally pruned on each reconcile.
	// values.yaml 은 binaryData 를 만들지 않으므로, 손으로 넣은 binaryData 도 지운다(watch 가 반응하는 변경을
	// 실제로 되돌리지 않으면 이벤트마다 reconcile 만 돈다).
	cm.Labels = desiredLabels
	cm.Annotations = desiredAnnotations
	cm.Data = data
	cm.BinaryData = nil

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
			},
			Data: data,
			Type: corev1.SecretTypeOpaque,
		}

		return r.Create(ctx, &sec)
	} else if err != nil {

		return err
	}

	adopted, owned := r.claimTarget(ctx, &sec.ObjectMeta, ov)
	if !owned {

		return fmt.Errorf("secret %s/%s: %w", ns, name, errTargetNotOwned)
	}

	// 이전 버전이 붙인 ownerReference 를 뗀다. 남겨 두면 foreground 삭제에서 GC 가 대상을 지운다.
	migrated := dropLegacyOwnerRef(&sec.ObjectMeta, ov.UID)

	desiredLabels := mergeLabels(sysLabels, userLabels)
	desiredAnnotations := mergeAnnotations(sysAnnotations, userAnnotations)

	if !adopted && !migrated &&
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

// deleteStaleTarget 이전 종류(kind)의 대상을 지운다. 이 OctoVault 가 소유한 것만 지운다.
func (r *OctoVaultReconciler) deleteStaleTarget(ctx context.Context, ov *octovaultv1alpha1.OctoVault, kind string) error {

	key := types.NamespacedName{Namespace: ov.Namespace, Name: ov.Spec.TargetName}

	var obj client.Object
	switch kind {
	case string(octovaultv1alpha1.OutputConfigMap):
		obj = &corev1.ConfigMap{}
	case string(octovaultv1alpha1.OutputSecret):
		// Secret 조회는 캐시를 거치지 않으므로, 평소에는 매 poll 마다 API 를 부르지 않도록 메타데이터
		// 캐시로 먼저 존재와 소유를 확인한다. 지우는 데에는 이름과 UID 만 있으면 된다.
		// 다만 이 캐시는 managed-by 라벨로 범위가 좁혀져 있어, 라벨이 바뀐 Secret 은 보이지 않는다.
		// 남은 Secret 이 있을 법한 때(방금 Secret 에서 바뀌었거나 지난 정리가 실패했을 때)는 API 를 본다.
		if r.TargetSecrets != nil && !staleSecretExpected(ov) {

			secretMeta := &metav1.PartialObjectMetadata{}
			secretMeta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
			if err := r.TargetSecrets.Get(ctx, key, secretMeta); err != nil {

				return client.IgnoreNotFound(err)
			}

			if !ownedBy(secretMeta, ov) {

				return nil
			}

			return r.deleteWithUID(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}, secretMeta.UID)
		}

		obj = &corev1.Secret{}
	default:
		return nil
	}

	if err := r.Get(ctx, key, obj); err != nil {

		return client.IgnoreNotFound(err)
	}

	if !ownedBy(obj, ov) {

		return nil
	}

	return r.deleteWithUID(ctx, obj, obj.GetUID())
}

// deleteWithUID 조회와 삭제 사이에 같은 이름으로 다시 만들어진 객체를 지우지 않도록 UID 를 고정해 지운다.
func (r *OctoVaultReconciler) deleteWithUID(ctx context.Context, obj client.Object, uid types.UID) error {

	err := r.Delete(ctx, obj, client.Preconditions{UID: &uid})

	return client.IgnoreNotFound(err)
}

func (r *OctoVaultReconciler) orphanTargets(ctx context.Context, ov *octovaultv1alpha1.OctoVault) error {

	// 대상은 언제나 OctoVault 와 같은 네임스페이스에 만든다(다른 네임스페이스는 InvalidTargetNamespace 로
	// 거부한다). spec.targetNamespace 를 나중에 다른 값으로 바꿔도 실제 대상은 원래 네임스페이스에 있다.
	targetNS := ov.Namespace

	// releaseTarget 이 실제로 뭔가 바꿨는지(놓아줄 소유 표시가 있었는지) 반환한다.
	removeOwner := func(obj metav1.Object) bool {
		return releaseTarget(obj, ov)
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
	// OctoVault 소유로 남아 있다(이전 버전이 붙인 ownerReference 가 있으면 GC 가 함께 지운다).
	// 그래서 생성 시 붙인 owner 라벨로 이 OctoVault 가 만든 대상을 모두 찾는다. 라벨이 없는 오래된
	// 대상을 위해 현재 이름도 직접 확인한다. ResolvedType 과 무관하게 두 종류를 모두 본다.
	// releaseTarget 은 이 OctoVault 의 소유 표시만 지우므로 남의 리소스에는 영향이 없다.
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

// updateStatusIfChanged 상태가 바뀌어 기록에 성공했으면 true 를 반환한다.
func (r *OctoVaultReconciler) updateStatusIfChanged(ctx context.Context, ov *octovaultv1alpha1.OctoVault, desired octovaultv1alpha1.OctoVaultStatus) bool {

	prev := ov.Status
	if statusEqualOV(prev, desired) {

		return false
	}

	ov.Status = desired
	if err := r.Status().Update(ctx, ov); err != nil {

		logf.FromContext(ctx).Error(err, "status update failed")
		noteStatusWriteError(ctx, err)
		return false
	}

	return true
}

// fail 직전 상태를 바탕으로 실패 상태를 만든다.
//
// ResolvedType, ObservedRevision, LastSyncedTime, ExternalRefs 는 마지막으로 성공한
// 동기화의 기록이므로 실패해도 지우지 않는다. 실패 한 번으로 상태가 실제 대상과 어긋나지 않게 한다.
func fail(prev octovaultv1alpha1.OctoVaultStatus, reason, msg string) octovaultv1alpha1.OctoVaultStatus {

	next := prev
	next.Phase = octovaultv1alpha1.OVPhaseFailed
	next.Message = msg

	next.Conditions = upsertReadyCondition(prev.Conditions, metav1.ConditionFalse, reason, msg)

	return next
}

func statusEqualOV(a, b octovaultv1alpha1.OctoVaultStatus) bool {
	if a.Phase != b.Phase || a.Message != b.Message || a.ObservedRevision != b.ObservedRevision || a.ObservedRef != b.ObservedRef || a.AppliedDataHash != b.AppliedDataHash || a.ResolvedType != b.ResolvedType {

		return false
	}

	// 외부 시크릿이 회전돼 값은 같고 버전만 바뀐 경우도 상태에 남아야 한다.
	// Semantic 은 nil 과 빈 슬라이스를 같게 본다. reflect.DeepEqual 로 비교하면 VersionStages 가
	// nil 로 돌아오는지 [] 로 돌아오는지에 따라 매번 바뀐 것으로 보고 쓰기와 이벤트를 반복할 수 있다.
	if !equality.Semantic.DeepEqual(a.ExternalRefs, b.ExternalRefs) {

		return false
	}

	return readyConditionEqual(a.Conditions, b.Conditions)
}

// ParseDurationOr 비었거나, 파싱에 실패하거나, 0 이하면 기본값을 쓴다.
func ParseDurationOr(s string, d time.Duration) time.Duration {

	s = strings.TrimSpace(s)
	if s == "" {

		return d
	}

	if v, err := time.ParseDuration(s); err == nil && v > 0 {

		return v
	}

	return d
}

// namespaceAllowed AllowedNamespaces 가 비어 있으면 모든 네임스페이스를 허용한다.
func namespaceAllowed(orepo *octovaultv1alpha1.OctoRepository, ns string) bool {
	if len(orepo.Spec.AllowedNamespaces) == 0 {

		return true
	}

	return slices.Contains(orepo.Spec.AllowedNamespaces, ns)
}

// repositoryOwner "owner/repo" 에서 owner 를 꺼낸다. owner 가 없으면 false.
func repositoryOwner(repository string) (string, bool) {

	owner, _, found := strings.Cut(strings.TrimSpace(repository), "/")
	if !found || owner == "" {

		return "", false
	}

	return owner, true
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

	// 대상이 지워지거나 컨트롤러가 책임지는 부분이 손으로 바뀌면 poll 주기를 기다리지 않고 바로
	// 되돌린다. 어떤 변경에 반응하는지는 targetEventFilter 를 본다.
	// 컨트롤러 자신의 갱신도 이벤트가 되지만, 다음 reconcile 에서 바뀐 것이 없어 끝난다.
	b = b.Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.mapTargetToOctoVault),
		builder.WithPredicates(targetEventFilter[client.Object]()))

	if r.TargetSecrets != nil {

		secretMeta := &metav1.PartialObjectMetadata{}
		secretMeta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))

		b = b.WatchesRawSource(source.Kind(r.TargetSecrets, secretMeta,
			handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, obj *metav1.PartialObjectMetadata) []reconcile.Request {
				return r.mapTargetToOctoVault(ctx, obj)
			}),
			targetEventFilter[*metav1.PartialObjectMetadata]()))
	}

	return b.Complete(r)
}

func (r *OctoVaultReconciler) maxWorkers() int {
	if r.Workers > 0 {

		return r.Workers
	}

	return 1
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {

		return nil
	}

	out := append([]string(nil), in...)
	sort.Strings(out)

	return out
}
