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
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"time"

	ghclient "github.com/octovault/octovault/internal/github"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	LabelRepoTrue = "true"
)

// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// OctoRepositoryReconciler reconciles a OctoRepository object
type OctoRepositoryReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Workers  int

	Checker OrgAccessChecker
}

// DefaultCredentialRecheckInterval 자격증명 재검증 주기.
//
// Checker 가 같은 TTL 로 결과를 캐시하므로 이 주기당 GitHub 요청은 최대 1회다.
// 1분이던 이전 기본값은 OctoRepository 하나당 시간당 60~120 요청을 소모했다.
const DefaultCredentialRecheckInterval = 10 * time.Minute

var (
	orgURLPattern = regexp.MustCompile(`^github\.com/([A-Za-z0-9_.-]+)$`)

	// pollInterval GIT_CRED_TTL 로 조정한다. Checker 의 캐시 TTL 과 같은 값을 쓴다.
	pollInterval = func() time.Duration {

		if v := strings.TrimSpace(env("GIT_CRED_TTL")); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {

				return d
			}
		}

		return DefaultCredentialRecheckInterval
	}()
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the OctoRepository object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *OctoRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := logf.FromContext(ctx)

	var orepo octovaultv1alpha1.OctoRepository
	if err := r.Get(ctx, req.NamespacedName, &orepo); err != nil {

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if res, done := r.validateOrganizationAndMaybeFail(ctx, &orepo); done {

		logger.Info("invalid organization", "organization", orepo.Spec.Organization)
		return res, nil
	}

	// 아래 헬퍼들은 "상태에 기록하고 다음 주기에 다시 본다"(res) 와
	// "재시도가 의미 있는 일시적 오류"(err) 를 구분해 반환한다.
	// 두 값을 함께 반환하면 controller-runtime 이 res 를 버리고 5ms 백오프로
	// 재시도하기 때문에, 반드시 하나만 채워야 한다.
	sec, res, err := r.loadCredentialsSecret(ctx, &orepo)
	if err != nil {

		logger.Error(err, "failed to load credentials secret "+orepo.Spec.CredentialsRef.Name)
		return ctrl.Result{}, err
	}

	if res.RequeueAfter > 0 {

		return res, nil
	}

	if sec == nil {

		logger.Error(errors.New("secret is nil"), "credentials secret is nil")
		return ctrl.Result{RequeueAfter: pollInterval}, nil
	}

	pwd, res, err := r.extractAndDecodePassword(ctx, &orepo, sec)
	if err != nil {

		logger.Error(err, "failed to extract and decode password from secret "+sec.Name)
		return ctrl.Result{}, err
	}

	if res.RequeueAfter > 0 {

		return res, nil
	}

	if res, done := r.checkAccessAndMaybeFail(ctx, &orepo, pwd); done {

		return res, nil
	}

	return r.setSynced(ctx, &orepo, sec)
}

// ---- Helpers (same file) ----------------------------------------------------

func (r *OctoRepositoryReconciler) validateOrganizationAndMaybeFail(ctx context.Context, o *octovaultv1alpha1.OctoRepository) (ctrl.Result, bool) {

	logger := logf.FromContext(ctx)

	prev := o.Status
	orgField := strings.TrimSpace(o.Spec.Organization)
	if orgField == "" || !orgURLPattern.MatchString(orgField) {
		msg := fmt.Sprintf("organization must be in the format github.com/<org>, got %s", orgField)
		desired := prev
		desired.Phase = octovaultv1alpha1.OctoRepoPhaseFailed
		desired.Message = msg
		desired.SyncedSecretName = ""
		desired.Conditions = upsertReadyCondition(prev.Conditions, metav1.ConditionFalse, "InvalidOrganization", msg)

		if !statusEqual(prev, desired) {
			o.Status = desired

			if err := r.Status().Update(ctx, o); err != nil {

				logger.Error(err, "failed to update status to Failed")
			}

			r.Recorder.Eventf(o, corev1.EventTypeWarning, "InvalidOrganization", "%s", msg)
		}

		return ctrl.Result{RequeueAfter: pollInterval}, true
	}

	return ctrl.Result{}, false
}

func (r *OctoRepositoryReconciler) loadCredentialsSecret(ctx context.Context, o *octovaultv1alpha1.OctoRepository) (*corev1.Secret, ctrl.Result, error) {

	var sec corev1.Secret
	secKey := types.NamespacedName{
		Name:      o.Spec.CredentialsRef.Name,
		Namespace: o.Spec.CredentialsRef.Namespace,
	}

	if err := r.Get(ctx, secKey, &sec); err != nil {
		if apierrors.IsNotFound(err) {

			msg := fmt.Sprintf("secret %s not found", secKey.Name)
			r.setFailed(ctx, o, "SecretNotFound", msg)

			return nil, ctrl.Result{RequeueAfter: pollInterval}, nil
		}

		return nil, ctrl.Result{}, err
	}

	// track syncedSecretName
	if o.Status.SyncedSecretName != sec.Name {

		o.Status.SyncedSecretName = sec.Name
		_ = r.Status().Update(ctx, o)
	}

	return &sec, ctrl.Result{}, nil
}

func (r *OctoRepositoryReconciler) extractAndDecodePassword(ctx context.Context, o *octovaultv1alpha1.OctoRepository, sec *corev1.Secret) (string, ctrl.Result, error) {

	pwd := orgFromSecret(sec, "password")
	if pwd == "" {

		// 즉시 재시도해도 결과가 같다. 상태에 기록하고 다음 주기를 기다린다.
		r.setFailed(ctx, o, "SecretMissingPassword", "secret missing password")
		return "", ctrl.Result{RequeueAfter: pollInterval}, nil
	}

	if orgFromSecret(sec, "passwordEncoding") == "base64" {

		dec, err := base64.StdEncoding.DecodeString(pwd)
		if err != nil {

			r.setFailed(ctx, o, "SecretInvalidPasswordEncoding", fmt.Sprintf("failed to decode password from secret %s: %v", sec.Name, err))
			return "", ctrl.Result{RequeueAfter: pollInterval}, nil
		}

		pwd = string(dec)
	}

	return pwd, ctrl.Result{}, nil
}

func (r *OctoRepositoryReconciler) checkAccessAndMaybeFail(ctx context.Context, o *octovaultv1alpha1.OctoRepository, pwd string) (ctrl.Result, bool) {

	logger := logf.FromContext(ctx)

	if r.Checker == nil {

		r.setFailed(ctx, o, "CheckerNotConfigured", "controller was started without an org access checker")
		return ctrl.Result{RequeueAfter: pollInterval}, true
	}

	err := r.Checker.Check(ctx, o.Spec.Organization, pwd)
	if err == nil {

		return ctrl.Result{}, false
	}

	// rate limit 은 권한 문제가 아니다. 같은 이유로 계속 찔러봐야 한도만 더 소모하므로
	// GitHub 이 알려준 리셋 시각까지 기다린다.
	if retryAfter, limited := ghclient.RetryAfterFor(err); limited {

		logger.Info("github rate limit hit while verifying credentials; backing off",
			"organization", o.Spec.Organization, "retryAfter", retryAfter)

		r.setFailed(ctx, o, "RateLimited", err.Error())

		return ctrl.Result{RequeueAfter: retryAfter}, true
	}

	r.setFailed(ctx, o, "AccessDenied", err.Error())

	return ctrl.Result{RequeueAfter: pollInterval}, true
}

func (r *OctoRepositoryReconciler) setSynced(ctx context.Context, o *octovaultv1alpha1.OctoRepository, sec *corev1.Secret) (ctrl.Result, error) {

	prev := o.Status
	org := strings.TrimPrefix(strings.TrimSpace(o.Spec.Organization), "github.com/")
	desired := prev
	desired.Phase = octovaultv1alpha1.OctoRepoPhaseSynced
	desired.Message = fmt.Sprintf("organization %q is accessible", org)
	desired.Conditions = upsertReadyCondition(prev.Conditions, metav1.ConditionTrue, "Accessible", desired.Message)

	if !statusEqual(prev, desired) {

		o.Status = desired
		_ = r.Status().Update(ctx, o)

		r.Recorder.Eventf(o, corev1.EventTypeNormal, "Accessible", "organization %s is accessible; secret=%s", org, sec.Name)
		r.Recorder.Eventf(o, corev1.EventTypeNormal, "Synced", "organization %s is accessible; secret=%s", org, sec.Name)
	}

	return ctrl.Result{RequeueAfter: pollInterval}, nil
}

func (r *OctoRepositoryReconciler) setFailed(ctx context.Context, o *octovaultv1alpha1.OctoRepository, reason, msg string) {

	prev := o.Status
	desired := prev
	desired.Phase = octovaultv1alpha1.OctoRepoPhaseFailed
	desired.Message = msg
	desired.SyncedSecretName = prev.SyncedSecretName
	desired.Conditions = upsertReadyCondition(prev.Conditions, metav1.ConditionFalse, reason, msg)

	if !statusEqual(prev, desired) {

		o.Status = desired
		_ = r.Status().Update(ctx, o)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, reason, "%s", msg)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *OctoRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {

	mapSecretToOrepo := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		s, ok := obj.(*corev1.Secret)
		if !ok {

			return nil
		}

		// 인덱서 키: spec.credentialsRef.index == "<ns>/<name>"
		idx := s.Namespace + "/" + s.Name

		var list octovaultv1alpha1.OctoRepositoryList
		if err := r.List(ctx, &list,
			client.MatchingFields{"spec.credentialsRef.index": idx}); err != nil {

			return nil
		}

		reqs := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {

			reqs = append(reqs,
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name: list.Items[i].Name,
					},
				},
			)
		}

		return reqs
	})

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxWorkers(),
		}).
		For(&octovaultv1alpha1.OctoRepository{}, builder.WithPredicates(
			predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Secret{}, mapSecretToOrepo,
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {

				return obj.GetLabels()[LabelRepo] == LabelRepoTrue
			}))).
		Named("octorepository").
		Complete(r)
}

func (r *OctoRepositoryReconciler) maxWorkers() int {
	if r.Workers > 0 {

		return r.Workers
	}

	return 1
}

func upsertReadyCondition(conds []metav1.Condition, status metav1.ConditionStatus, reason, msg string) []metav1.Condition {

	now := metav1.Now()
	for i := range conds {
		if conds[i].Type == CondReady {
			// 값이 달라질 때만 transition 갱신
			if conds[i].Status != status || conds[i].Reason != reason || conds[i].Message != msg {

				conds[i].Status = status
				conds[i].Reason = reason
				conds[i].Message = msg
				conds[i].LastTransitionTime = now
			}

			return conds
		}
	}

	return append(conds, metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: now,
	})
}

func statusEqual(a, b octovaultv1alpha1.OctoRepositoryStatus) bool {

	if a.Phase != b.Phase || a.Message != b.Message || a.SyncedSecretName != b.SyncedSecretName {

		return false
	}

	var ar, br *metav1.Condition
	for i := range a.Conditions {
		if a.Conditions[i].Type == "Ready" {

			ar = &a.Conditions[i]
			break
		}
	}

	for i := range b.Conditions {
		if b.Conditions[i].Type == "Ready" {

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

func env(k string) string {
	if v, ok := syscall.Getenv(k); ok {

		return v
	}
	return ""
}
