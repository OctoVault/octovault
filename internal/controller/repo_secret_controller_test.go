package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// 공용 스킴/클라이언트 생성 헬퍼 -----------------------------------------------

func schemeForRepoSecretTests(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, octovaultv1alpha1.AddToScheme(s))
	return s
}

func fakeClientWithIndex(t *testing.T, s *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	// MatchingFields("spec.credentialsRef.index")를 위한 인덱서 등록
	return fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithIndex(&octovaultv1alpha1.OctoRepository{}, "spec.credentialsRef.index",
			func(obj client.Object) []string {
				o := obj.(*octovaultv1alpha1.OctoRepository)
				ns := strings.TrimSpace(o.Spec.CredentialsRef.Namespace)
				name := strings.TrimSpace(o.Spec.CredentialsRef.Name)
				if ns == "" || name == "" {
					return nil
				}
				return []string{ns + "/" + name}
			}).
		Build()
}

// -----------------------------------------------------------------------------

func TestRepoSecret_IgnoresSecretWithoutLabel(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoSecretTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "creds",
			Namespace: "devops",
			// LabelRepo 미설정
		},
	}

	cl := fakeClientWithIndex(t, scheme, sec)
	r := &RepoSecretReconciler{Client: cl, Scheme: scheme}

	res, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "devops", Name: "creds"},
	})
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), res.RequeueAfter)

	var list octovaultv1alpha1.OctoRepositoryList
	require.NoError(t, cl.List(ctx, &list))
	require.Len(t, list.Items, 0)
}

func TestRepoSecret_OctoRepositoryAlreadyReferencesSecret(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoSecretTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "creds",
			Namespace: "devops",
			Labels: map[string]string{
				LabelRepo: LabelRepoTrue,
			},
		},
	}

	existing := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: "existing-orepo",
		},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/exist",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientWithIndex(t, scheme, sec, existing)
	r := &RepoSecretReconciler{Client: cl, Scheme: scheme}

	res, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "devops", Name: "creds"},
	})
	require.NoError(t, err)
	// 이미 참조 중이면 새로 만들지 않고 종료
	require.Equal(t, time.Duration(0), res.RequeueAfter)

	// Secret과 동일 이름의 orepo가 새로 생기지 않아야 함
	var notCreated octovaultv1alpha1.OctoRepository
	err = cl.Get(ctx, client.ObjectKey{Name: "creds"}, &notCreated)
	require.Error(t, err) // NotFound 여야 정상
}
