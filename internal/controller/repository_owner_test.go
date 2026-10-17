package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// spec.repository 의 owner 는 OctoRepository 의 조직(github.com/test-org)과 같아야 한다.

func reconcileWithRepository(t *testing.T, repository string) octovaultv1alpha1.OctoVault {
	t.Helper()

	ctx := context.Background()
	const path = "values/owner.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Spec.Repository = repository
	require.NoError(t, cl.Update(ctx, &current))

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))

	return updated
}

func TestOctoVault_RepositoryOwnerMismatch_IsRejected(t *testing.T) {

	updated := reconcileWithRepository(t, "other-org/test-repo")

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "RepositoryOwnerMismatch", updated.Status.Conditions[0].Reason)
}

func TestOctoVault_RepositoryOwner_IsCaseInsensitive(t *testing.T) {

	updated := reconcileWithRepository(t, "Test-Org/test-repo")

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}

func TestOctoVault_RepositoryWithoutOwner_UsesOctoRepositoryOrg(t *testing.T) {

	updated := reconcileWithRepository(t, "test-repo")

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}
