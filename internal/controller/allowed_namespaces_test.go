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

// OctoRepository.spec.allowedNamespaces 가 설정되면 목록에 없는 네임스페이스의
// OctoVault 는 자격증명을 쓸 수 없어야 한다.

func reconcileWithAllowedNamespaces(t *testing.T, ovNS string, allowed []string) (octovaultv1alpha1.OctoVault, client.Client) {
	t.Helper()

	const (
		credNS = "cred-ns"
		path   = "values/allowed.yaml"
		target = "target-resource"
	)

	scheme := newScheme(t)

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cred", Namespace: credNS},
		StringData: map[string]string{"password": "dummy"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo-allowed"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:      "github.com/test-org",
			CredentialsRef:    octovaultv1alpha1.NamespacedObjectRef{Name: "cred", Namespace: credNS},
			AllowedNamespaces: allowed,
		},
	}
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{Name: "ov-allowed", Namespace: ovNS},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "orepo-allowed"},
			Repository:        "test-org/test-repo",
			Path:              path,
			TargetName:        target,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git:      &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"},
	}

	ctx := context.Background()
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))

	return updated, cl
}

func TestOctoVault_AllowedNamespaces_ListedNamespace_Syncs(t *testing.T) {

	updated, _ := reconcileWithAllowedNamespaces(t, "team-a", []string{"team-a", "team-b"})

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}

func TestOctoVault_AllowedNamespaces_UnlistedNamespace_IsRejected(t *testing.T) {

	updated, cl := reconcileWithAllowedNamespaces(t, "intruder", []string{"team-a"})

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "NamespaceNotAllowed", updated.Status.Conditions[0].Reason)

	var cm corev1.ConfigMap
	err := cl.Get(context.Background(), client.ObjectKey{Name: "target-resource", Namespace: "intruder"}, &cm)
	assert.True(t, err != nil && client.IgnoreNotFound(err) == nil, "target must not be created")
}

func TestOctoVault_AllowedNamespaces_Empty_AllowsAll(t *testing.T) {

	updated, _ := reconcileWithAllowedNamespaces(t, "anywhere", nil)

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}
