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

// status.observedRef 는 동기화에 쓴 ref(spec.gitRef, 없으면 GIT_REF)를 보여줘야 한다.

func TestOctoVault_ObservedRef_FollowsSpecAndDefault(t *testing.T) {

	ctx := context.Background()
	const path = "values/ref.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	rec.DefaultRef = "main"
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	get := func() octovaultv1alpha1.OctoVault {
		var o octovaultv1alpha1.OctoVault
		require.NoError(t, cl.Get(ctx, key, &o))

		return o
	}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	assert.Equal(t, "main", get().Status.ObservedRef, "empty gitRef falls back to GIT_REF")

	current := get()
	current.Spec.GitRef = "release-1"
	require.NoError(t, cl.Update(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	assert.Equal(t, "release-1", get().Status.ObservedRef, "a changed gitRef is recorded even if the file is identical")
}
