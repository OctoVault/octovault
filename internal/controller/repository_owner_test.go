package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

type countingFetcher struct {
	GitFetcher
	calls int
}

func (f *countingFetcher) Fetch(ctx context.Context, org, repo, path, ref, token string) ([]byte, []byte, string, error) {

	f.calls++

	return f.GitFetcher.Fetch(ctx, org, repo, path, ref, token)
}

// owner 가 맞지 않으면 자격증명 Secret 을 읽지도, GitHub 를 부르지도 않아야 한다.
func TestOctoVault_RepositoryOwnerMismatch_StopsBeforeCredentialsAndFetch(t *testing.T) {

	ctx := context.Background()
	const path = "values/owner.yaml"

	static := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, static)
	fetcher := &countingFetcher{GitFetcher: static}
	rec.Git = fetcher
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Spec.Repository = "other-org/test-repo"
	require.NoError(t, cl.Update(ctx, &current))

	secretReads := 0
	rec.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, k client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {

				secretReads++
			}

			return c.Get(ctx, k, obj, opts...)
		},
	})

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.NoError(t, cl.Get(ctx, key, &current))
	assert.Equal(t, "RepositoryOwnerMismatch", current.Status.Conditions[0].Reason)
	assert.Zero(t, secretReads, "the credentials Secret must not be read")
	assert.Zero(t, fetcher.calls, "GitHub must not be called")
}

// organization 앞뒤 공백은 다른 경로처럼 무시한다.
func TestOctoVault_RepositoryOwner_IgnoresOrganizationWhitespace(t *testing.T) {

	ctx := context.Background()
	const path = "values/owner.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})

	var orepo octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.OctoRepositoryRef.Name}, &orepo))
	orepo.Spec.Organization = " github.com/test-org "
	require.NoError(t, cl.Update(ctx, &orepo))

	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}
