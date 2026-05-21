package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// cross-namespace OwnerReference는 Kubernetes에서 허용되지 않으므로
// targetNamespace != ov.Namespace 이면 Reconcile을 즉시 실패 처리한다.

func newCrossNSReconciler(t *testing.T, ovNS, targetNS string, fetcher *staticFetcher) (*OctoVaultReconciler, client.Client, *octovaultv1alpha1.OctoVault) {
	t.Helper()

	const (
		orepoName = "orepo-cross-ns"
		credName  = "cred-cross-ns"
		ovName    = "ov-cross-ns"
		target    = "target-resource"
		path      = "values/cross-ns.yaml"
	)

	scheme := newScheme(t)

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credName, Namespace: ovNS},
		StringData: map[string]string{"password": "dummy"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: orepoName},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name: credName, Namespace: ovNS,
			},
		},
	}
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{Name: ovName, Namespace: ovNS},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: orepoName},
			Repository:        "test-org/test-repo",
			Path:              path,
			TargetName:        target,
			TargetNamespace:   targetNS,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git:      fetcher,
	}

	return rec, cl, ov
}

func TestOctoVault_CrossNamespace_IsRejected(t *testing.T) {
	// cross-namespace targetNamespace가 설정된 경우 Reconcile이 Failed 상태로 전환됨

	ctx := context.Background()
	const path = "values/cross-ns.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: sampleConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newCrossNSReconciler(t, "app-ns", "other-ns", fetcher)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}, &updated))

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "InvalidTargetNamespace", updated.Status.Conditions[0].Reason)

	// ConfigMap이 생성되지 않았음을 확인
	var cm corev1.ConfigMap
	err = cl.Get(ctx, client.ObjectKey{Namespace: "other-ns", Name: "target-resource"}, &cm)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "ConfigMap must not be created in other-ns")
}

func TestOctoVault_SameNamespace_IsAllowed(t *testing.T) {
	// targetNamespace == ov.Namespace 이면 정상 동작

	ctx := context.Background()
	const path = "values/cross-ns.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: sampleConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newCrossNSReconciler(t, "app-ns", "app-ns", fetcher)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}, &updated))

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}

func TestOctoVault_EmptyTargetNamespace_IsAllowed(t *testing.T) {
	// targetNamespace가 비어 있으면 ov.Namespace로 기본 설정되어 정상 동작

	ctx := context.Background()
	const path = "values/cross-ns.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: sampleConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newCrossNSReconciler(t, "app-ns", "", fetcher)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}, &updated))

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}
