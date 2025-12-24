package controller

import (
	"context"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	LabelRepo       = "octovault.it/repository"
	AnnOrganization = "octovault.it/organization"
)

// +kubebuilder:rbac:groups=octovault.it,resources=octorepositories,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
type RepoSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Workers int
}

func (r *RepoSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := logf.FromContext(ctx)

	var sec corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &sec); err != nil {

		logger.Error(err, "unable to fetch Secret")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 라벨이 없으면 관리 대상 아님
	if sec.GetLabels()[LabelRepo] != LabelRepoTrue {

		return ctrl.Result{}, nil
	}

	// 이미 이 Secret을 참조하는 OctoRepository 가 있으면 종료
	var list octovaultv1alpha1.OctoRepositoryList
	if err := r.List(ctx, &list,
		client.MatchingFields{"spec.credentialsRef.index": sec.Namespace + "/" + sec.Name},
	); err != nil {

		return ctrl.Result{}, err
	}
	if len(list.Items) > 0 {

		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *RepoSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// 이 컨트롤러는 Secret만 primary 로 본다
	pred := predicate.NewPredicateFuncs(func(obj client.Object) bool {

		return obj.GetLabels()[LabelRepo] == LabelRepoTrue
	})

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: r.maxWorkers(),
		}).
		For(&corev1.Secret{}, builder.WithPredicates(pred)).
		Complete(r)
}

func (r *RepoSecretReconciler) maxWorkers() int {
	if r.Workers > 0 {

		return r.Workers
	}

	return 1
}

func orgFromSecret(secret *corev1.Secret, org string) string {
	if v, ok := secret.Data[org]; ok && len(v) > 0 {

		return string(v)
	}

	if secret.StringData != nil {
		if v, ok := secret.StringData[org]; ok && v != "" {

			return v
		}
	}

	return ""
}
