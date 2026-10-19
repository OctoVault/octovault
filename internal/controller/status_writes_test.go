package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	errConflict  = apierrors.NewConflict(schema.GroupResource{Resource: "x"}, "x", errors.New("stale"))
	errForbidden = apierrors.NewForbidden(schema.GroupResource{Resource: "x"}, "x", errors.New("no RBAC"))
)

func TestStatusWrites_Apply(t *testing.T) {

	poll := ctrl.Result{RequeueAfter: 5 * time.Minute}

	untouched := &statusWrites{}
	res, err := untouched.apply(poll, nil)
	assert.NoError(t, err)
	assert.Equal(t, poll, res)

	conflict := &statusWrites{err: errConflict}
	res, err = conflict.apply(poll, nil)
	assert.NoError(t, err)
	assert.Equal(t, StatusRetryInterval, res.RequeueAfter, "conflicts retry soon")

	soon := ctrl.Result{RequeueAfter: time.Second}
	res, _ = conflict.apply(soon, nil)
	assert.Equal(t, time.Second, res.RequeueAfter, "an earlier requeue is kept")

	forbidden := &statusWrites{err: errForbidden}
	res, err = forbidden.apply(poll, nil)
	assert.NoError(t, err, "returning an error would discard RequeueAfter for a millisecond backoff")
	assert.Equal(t, StatusErrorRetryInterval, res.RequeueAfter, "other failures retry after a minute")

	reconcileErr := errors.New("reconcile failed")
	_, err = conflict.apply(poll, reconcileErr)
	assert.ErrorIs(t, err, reconcileErr, "a reconcile error wins")
}

// OctoVault 도 status 기록이 실패하면 poll 주기까지 기다리지 않는다.
func TestOctoVault_StatusWriteFailure_Retries(t *testing.T) {

	for _, tc := range []struct {
		name string
		err  error
		want time.Duration
	}{
		{name: "conflict retries soon", err: errConflict, want: StatusRetryInterval},
		{name: "forbidden retries after a minute", err: errForbidden, want: StatusErrorRetryInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const path = "values/status.yaml"

			rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
			rec.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					return tc.err
				},
			})

			res, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}})
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.RequeueAfter)
		})
	}
}

// OctoRepository 에서 conflict 가 아닌 status 기록 실패는 5초가 아니라 1분 뒤에 다시 시도한다.
func TestOctoRepository_NonConflictStatusWriteFailure_RetriesAfterAMinute(t *testing.T) {

	ctx := context.Background()
	scheme := schemeForRepoTests(t)
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
		Data:       map[string][]byte{"password": []byte("dummy")},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:   "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{Name: "creds", Namespace: "devops"},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&octovaultv1alpha1.OctoRepository{}).
		WithObjects(sec, orepo).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				return errForbidden
			},
		}).
		Build()

	r := &OctoRepositoryReconciler{Client: cl, Scheme: scheme, Recorder: record.NewFakeRecorder(64), Checker: deniedChecker{}}

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)
	assert.Equal(t, StatusErrorRetryInterval, res.RequeueAfter)
}
