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

// 토큰은 Secret data 에서만 읽는다. annotation 은 암호화되지 않고 메타데이터 조회 권한만으로
// 보이므로 토큰 저장 위치로 받아들이지 않는다. OctoRepository 컨트롤러와도 같은 규칙이다.

func TestOctoVault_TokenInAnnotation_IsIgnored(t *testing.T) {

	ctx := context.Background()
	const (
		ns   = "app-ns"
		path = "values/cred.yaml"
	)

	scheme := newScheme(t)
	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cred", Namespace: ns,
			Annotations: map[string]string{"octovault.it/password": "token-in-annotation"},
		},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo-cred"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:   "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{Name: "cred", Namespace: ns},
		},
	}
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{Name: "ov-cred", Namespace: ns},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "orepo-cred"},
			Repository:        "test-org/test-repo",
			Path:              path,
			TargetName:        "target-resource",
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git:      &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"},
	}

	key := client.ObjectKey{Name: ov.Name, Namespace: ns}
	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "SecretMissingPassword", updated.Status.Conditions[0].Reason)
}
