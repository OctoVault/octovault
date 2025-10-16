package controller

import (
	"context"
	"strings"
	"testing"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIndex_FindOreposBySecretName(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, octovaultv1alpha1.AddToScheme(scheme))

	orepo1 := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "a"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/org1",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Namespace: "ns", Name: "sec-a",
			},
		},
	}
	orepo2 := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "b"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/org2",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Namespace: "ns", Name: "sec-b",
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(orepo1, orepo2).
		// ★ 인덱스 등록: spec.credentialsRef.index  (값: "<ns>/<name>")
		WithIndex(&octovaultv1alpha1.OctoRepository{}, "spec.credentialsRef.index",
			func(obj client.Object) []string {
				o := obj.(*octovaultv1alpha1.OctoRepository)
				ns := strings.TrimSpace(o.Spec.CredentialsRef.Namespace)
				name := strings.TrimSpace(o.Spec.CredentialsRef.Name)
				if ns == "" || name == "" {
					return nil
				}
				return []string{ns + "/" + name}
			},
		).
		Build()

	// "ns/sec-b" 를 참조하는 OctoRepository만 조회
	var list octovaultv1alpha1.OctoRepositoryList
	err := cl.List(ctx, &list,
		client.MatchingFields{"spec.credentialsRef.index": "ns/sec-b"},
	)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, "b", list.Items[0].Name)

	// 존재하지 않는 Secret 키 조회 → 0
	list = octovaultv1alpha1.OctoRepositoryList{}
	err = cl.List(ctx, &list,
		client.MatchingFields{"spec.credentialsRef.index": "nsX/sec-x"},
	)
	require.NoError(t, err)
	require.Len(t, list.Items, 0)

	// 개별 Get
	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "a"}, &got))
	require.Equal(t, "github.com/org1", got.Spec.Organization)
}
