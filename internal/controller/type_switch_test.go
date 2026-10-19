package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// metadata.type 이 ConfigMap 에서 Secret 으로 바뀌면 이전 ConfigMap 은 지워져야 한다.
// 단, 이 OctoVault 가 소유하지 않은 것은 건드리지 않는다.

func TestOctoVault_TypeSwitch_DeletesPreviousOwnedTarget(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, target, &corev1.ConfigMap{}))

	fetcher.files[path] = sampleSecretYAML
	fetcher.rev = "rev2"
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.NoError(t, cl.Get(ctx, target, &corev1.Secret{}))
	err = cl.Get(ctx, target, &corev1.ConfigMap{})
	assert.True(t, err != nil && client.IgnoreNotFound(err) == nil, "previous ConfigMap must be deleted")

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, "Secret", updated.Status.ResolvedType)
}

func TestOctoVault_TypeSwitch_KeepsUnownedTarget(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleSecretYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	// 이전에 ConfigMap 으로 동기화된 것처럼 상태를 두고, 같은 이름의 ConfigMap 은 남이 만든 것으로 둔다.
	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Status.ResolvedType = "ConfigMap"
	require.NoError(t, cl.Status().Update(ctx, &current))
	require.NoError(t, cl.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ov.Spec.TargetName, Namespace: ov.Namespace},
		Data:       map[string]string{"keep": "me"},
	}))

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &cm))
	assert.Equal(t, "me", cm.Data["keep"])
}

// failDeletes 대상 종류의 Delete 를 403 으로 실패시킨다(예: ClusterRole 에 delete 가 빠진 경우).
func failDeletes(t *testing.T, rec *OctoVaultReconciler, cl client.Client, kind client.Object, failing *bool) {
	t.Helper()

	rec.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if *failing && reflect.TypeOf(obj) == reflect.TypeOf(kind) {

				return apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, obj.GetName(), errors.New("no delete permission"))
			}

			return c.Delete(ctx, obj, opts...)
		},
	})
}

// 정리에 실패해도 새로 만든 대상은 OctoVault 삭제 시 GC 되면 안 된다.
func TestOctoVault_TypeSwitch_CleanupFailure_KeepsNewTargetOnDelete(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	failing := true
	failDeletes(t, rec, cl, &corev1.ConfigMap{}, &failing)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	fetcher.files[path] = sampleSecretYAML
	fetcher.rev = UpdateRevAfter
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, ReasonStaleTargetCleanupFailed, updated.Status.Conditions[0].Reason)
	assert.Equal(t, "Secret", updated.Status.ResolvedType, "status must record the kind that was actually applied")

	require.NoError(t, cl.Delete(ctx, &updated))
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, target, &sec))
	assertReleased(t, &sec)
}

// 정리가 실패한 상태에서 원래 종류로 되돌리면, 중간에 만든 대상이 지워져야 한다.
func TestOctoVault_TypeSwitch_RevertBeforeCleanup_DeletesIntermediateTarget(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	failing := true
	failDeletes(t, rec, cl, &corev1.ConfigMap{}, &failing)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	fetcher.files[path] = sampleSecretYAML
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	// ConfigMap 으로 되돌린다. 이번에는 Secret 을 지워야 하고, Secret 삭제는 성공한다.
	failing = false
	fetcher.files[path] = sampleConfigMapYAML
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	err = cl.Get(ctx, target, &corev1.Secret{})
	assert.True(t, err != nil && client.IgnoreNotFound(err) == nil, "intermediate Secret must be deleted")

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "ConfigMap", updated.Status.ResolvedType)
}

// 정리 실패 뒤 다른 실패(여기선 InvalidType)로 Ready reason 이 덮어써져도,
// 다음 성공한 동기화에서 남은 대상이 지워져야 한다.
func TestOctoVault_TypeSwitch_CleanupRetrySurvivesOtherFailures(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	failing := true
	failDeletes(t, rec, cl, &corev1.ConfigMap{}, &failing)
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}
	reconcileOnce := func() octovaultv1alpha1.OctoVault {
		_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		require.NoError(t, err)

		var o octovaultv1alpha1.OctoVault
		require.NoError(t, cl.Get(ctx, key, &o))

		return o
	}

	reconcileOnce()

	fetcher.files[path] = sampleSecretYAML
	require.Equal(t, ReasonStaleTargetCleanupFailed, reconcileOnce().Status.Conditions[0].Reason)

	fetcher.files[path] = invalidTypeYAML
	require.Equal(t, "InvalidType", reconcileOnce().Status.Conditions[0].Reason, "another failure overwrites the reason")

	failing = false
	fetcher.files[path] = sampleSecretYAML
	updated := reconcileOnce()

	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
	err := cl.Get(ctx, target, &corev1.ConfigMap{})
	assert.True(t, err != nil && client.IgnoreNotFound(err) == nil, "the stale ConfigMap must still be cleaned up")
}

// blindSecretCache managed-by 라벨이 바뀌어 메타데이터 캐시에서 보이지 않게 된 Secret 을 흉내 낸다.
type blindSecretCache struct {
	cache.Cache
}

func (blindSecretCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
}

func (blindSecretCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return nil
}

// Secret 에서 ConfigMap 으로 바뀐 직후에는 메타데이터 캐시에 없더라도 API 로 확인해 남은 Secret 을 지운다.
func TestOctoVault_TypeSwitch_SecretMissingFromMetadataCacheIsStillCleaned(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleSecretYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	rec.TargetSecrets = blindSecretCache{}
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	require.NoError(t, cl.Get(ctx, target, &corev1.Secret{}))

	fetcher.files[path] = sampleConfigMapYAML
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	require.NoError(t, cl.Get(ctx, target, &corev1.ConfigMap{}))
	err = cl.Get(ctx, target, &corev1.Secret{})
	assert.True(t, err != nil && client.IgnoreNotFound(err) == nil, "the previous Secret must be deleted even if the metadata cache cannot see it")
}

func TestStaleSecretExpected(t *testing.T) {

	ov := &octovaultv1alpha1.OctoVault{}
	assert.False(t, staleSecretExpected(ov))

	ov.Status.ResolvedType = "Secret"
	assert.True(t, staleSecretExpected(ov))

	ov.Status.ResolvedType = string(octovaultv1alpha1.OutputConfigMap)
	ov.Status.Conditions = []metav1.Condition{{Type: CondReady, Reason: ReasonStaleTargetCleanupFailed}}
	assert.True(t, staleSecretExpected(ov))
}

// metadataSecretCache fake client 의 Secret 메타데이터를 돌려주는 메타데이터 캐시. Get 횟수를 센다.
type metadataSecretCache struct {
	cache.Cache
	src  client.Client
	gets int
}

func (c *metadataSecretCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {

	c.gets++

	var sec corev1.Secret
	if err := c.src.Get(ctx, key, &sec); err != nil {

		return err
	}

	sec.ObjectMeta.DeepCopyInto(&obj.(*metav1.PartialObjectMetadata).ObjectMeta)

	return nil
}

func (c *metadataSecretCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return nil
}

// 평소(직전 출력이 ConfigMap 이고 정리 실패도 없음)에는 남은 Secret 을 메타데이터 캐시로 찾아 지운다.
func TestOctoVault_StaleSecret_IsDeletedThroughMetadataCache(t *testing.T) {

	ctx := context.Background()
	const path = "values/switch.yaml"

	fetcher := &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)
	metaCache := &metadataSecretCache{src: cl}
	rec.TargetSecrets = metaCache
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}
	target := client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	// 이 OctoVault 가 소유한 Secret 이 같은 이름으로 남아 있는 상황(예: 이전 정리 흔적이 사라진 뒤).
	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, target, &cm))
	require.NoError(t, cl.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: target.Name, Namespace: target.Namespace,
		Labels:          cm.Labels,
		Annotations:     cm.Annotations,
		OwnerReferences: cm.OwnerReferences,
	}}))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	assert.Positive(t, metaCache.gets, "the steady-state path must use the metadata cache")
	err = cl.Get(ctx, target, &corev1.Secret{})
	assert.True(t, apierrors.IsNotFound(err), "the stale Secret must be deleted: %v", err)
	require.NoError(t, cl.Get(ctx, target, &corev1.ConfigMap{}), "the ConfigMap stays")
}
