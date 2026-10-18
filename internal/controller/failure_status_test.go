package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

func TestOctoVault_DeleteWithEmptyResolvedType_RetainsTarget(t *testing.T) {
	// 이전 버전이 실패 시 ResolvedType 을 지운 상태로 남은 OctoVault 도 대상을 남겨야 한다.

	ctx := context.Background()
	const path = "values/failure.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleSecretYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Status = octovaultv1alpha1.OctoVaultStatus{Phase: octovaultv1alpha1.OVPhaseFailed}
	require.NoError(t, cl.Status().Update(ctx, &current))
	require.NoError(t, cl.Delete(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &sec))
	assert.Empty(t, sec.OwnerReferences, "ownerRef must be removed so GC keeps the target")
}

func TestOctoVault_Delete_ReleasesTargetsOfBothKinds(t *testing.T) {
	// ResolvedType 이 실제 대상과 어긋나도(여기선 ConfigMap 으로 기록됐지만 Secret 도 소유 중)
	// 삭제 시 두 종류 모두 ownerRef 를 풀어 GC 되지 않게 해야 한다.

	ctx := context.Background()
	const path = "values/failure.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleSecretYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Status.ResolvedType = "ConfigMap"
	require.NoError(t, cl.Status().Update(ctx, &current))
	require.NoError(t, cl.Delete(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &sec))
	assert.Empty(t, sec.OwnerReferences, "the Secret must be released even though status says ConfigMap")
}

// targetName 을 바꾼 뒤 지워도 이전 이름의 대상까지 남아야 한다(GC 되면 안 된다).
func TestOctoVault_DeleteAfterTargetRename_RetainsBothTargets(t *testing.T) {

	ctx := context.Background()
	const path = "values/failure.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	oldName := current.Spec.TargetName
	current.Spec.TargetName = oldName + "-v2"
	require.NoError(t, cl.Update(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.NoError(t, cl.Get(ctx, key, &current))
	require.NoError(t, cl.Delete(ctx, &current))
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	for _, name := range []string{oldName, oldName + "-v2"} {
		var cm corev1.ConfigMap
		require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: name, Namespace: ov.Namespace}, &cm), name)
		assert.Empty(t, cm.OwnerReferences, "%s must be released so GC keeps it", name)
	}
}

// 대상을 놓아주지 못하면 파이널라이저를 지우지 않고 에러로 재시도해야 한다.
func TestOctoVault_OrphanFailure_KeepsFinalizer(t *testing.T) {

	ctx := context.Background()
	const path = "values/failure.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	rec.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*corev1.ConfigMap); ok {

				return errors.New("apiserver unavailable")
			}

			return c.Update(ctx, obj, opts...)
		},
	})

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	require.NoError(t, cl.Delete(ctx, &current))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.Error(t, err, "the failure must be returned so the deletion is retried")

	require.NoError(t, cl.Get(ctx, key, &current), "the OctoVault must still exist")
	assert.Contains(t, current.Finalizers, FinalizerOV)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &cm))
	assert.NotEmpty(t, cm.OwnerReferences, "nothing was released yet")
}
