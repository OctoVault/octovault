package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	ghclient "github.com/octovault/octovault/internal/github"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// OctoRepository 의 첫 검증 성공은 상태를 한 번만 써야 한다.
func TestOctoRepository_FirstSync_WritesStatusOnce(t *testing.T) {

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

	writes := 0
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&octovaultv1alpha1.OctoRepository{}).
		WithObjects(sec, orepo).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {

				writes++

				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Checker:  fixedChecker{result: ghclient.AccessResult{}},
	}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)
	assert.Equal(t, 1, writes)

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	assert.Equal(t, "creds", got.Status.SyncedSecretName)
}

// 상태를 기록하지 못하면 이벤트를 남기지 않고 에러로 재시도해야 한다.
func TestOctoRepository_StatusWriteFailure_EmitsNoEventAndRetries(t *testing.T) {

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
				return apierrors.NewConflict(schema.GroupResource{Resource: "octorepositories"}, obj.GetName(), errors.New("stale"))
			},
		}).
		Build()

	recorder := record.NewFakeRecorder(64)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
		Checker:  fixedChecker{result: ghclient.AccessResult{}},
	}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.Error(t, err)
	assert.Empty(t, recorder.Events, "no event may claim a status that was not written")
}
