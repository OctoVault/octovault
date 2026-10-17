package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// 실패 상태로 전환돼도 마지막 성공 동기화의 기록은 남아야 하고,
// 그 상태에서 OctoVault 를 지우면 대상 리소스는 GC 되지 않고 남아야 한다.

var invalidTypeYAML = []byte(`
metadata:
  type: Unknown
spec:
  data:
    - key: foo
      value: bar
`)

func TestOctoVault_Failure_PreservesLastSyncRecord(t *testing.T) {

	ctx := context.Background()
	const path = "values/failure.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var synced octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &synced))
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, synced.Status.Phase)

	fetcher.files[path] = invalidTypeYAML
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var failed octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &failed))

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, failed.Status.Phase)
	assert.Equal(t, "InvalidType", failed.Status.Conditions[0].Reason)
	assert.Equal(t, synced.Status.ResolvedType, failed.Status.ResolvedType)
	assert.Equal(t, synced.Status.ObservedRevision, failed.Status.ObservedRevision)
	assert.Equal(t, synced.Status.AppliedDataHash, failed.Status.AppliedDataHash)
	assert.NotNil(t, failed.Status.LastSyncedTime)
}

func TestOctoVault_DeleteAfterFailure_RetainsTarget(t *testing.T) {

	ctx := context.Background()
	const path = "values/failure.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	fetcher.files[path] = invalidTypeYAML
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	require.NoError(t, cl.Delete(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &cm))
	assert.Empty(t, cm.OwnerReferences, "ownerRef must be removed so GC keeps the target")
	assert.Equal(t, ov.Namespace+"/"+ov.Name, cm.Annotations[AnnoOVRetainedBy])
}
