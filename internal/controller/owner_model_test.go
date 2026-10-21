package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// 대상 소유는 ownerReference 가 아니라 owner-uid 어노테이션으로 표시한다(target_ownership.go).
// ownerReference 가 있으면 foreground 삭제에서 GC 가 대상을 지우므로, 새로 만드는 대상에는 절대 붙지 않아야 한다.

func getTarget(t *testing.T, cl client.Client, obj client.Object) {
	t.Helper()

	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, obj))
}

func TestOctoVault_NewTarget_HasOwnerUIDAndNoOwnerReference(t *testing.T) {

	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ownershipNS}})

	_, updated := reconcileOwnership(t, rec, cl, ov)
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var cm corev1.ConfigMap
	getTarget(t, cl, &cm)
	assert.Empty(t, cm.OwnerReferences, "GC must have nothing to cascade from")
	assert.Equal(t, "ov-uid", cm.Annotations[AnnoOVOwnerUID])
	assert.Equal(t, ownershipNS, cm.Labels[LabelOVOwnerNS])
	assert.Equal(t, "ov-ownership", cm.Labels[LabelOVOwnerName])
}

// 이전 버전이 만든 대상(ownerReference 로 소유)은 계속 관리하고, ownerReference 를 떼고 owner-uid 로 옮긴다.
func TestOctoVault_LegacyOwnerReference_IsMigrated(t *testing.T) {

	ctrlTrue := true
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: octovaultv1alpha1.GroupVersion.String(), Kind: "OctoVault", Name: "ov-ownership", UID: types.UID("ov-uid"), Controller: &ctrlTrue},
				{APIVersion: "v1", Kind: "Unrelated", Name: "keep", UID: types.UID("unrelated-uid")},
			},
		},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var cm corev1.ConfigMap
	getTarget(t, cl, &cm)
	assert.Equal(t, "ov-uid", cm.Annotations[AnnoOVOwnerUID])
	require.Len(t, cm.OwnerReferences, 1, "only this OctoVault's ownerReference is removed")
	assert.Equal(t, types.UID("unrelated-uid"), cm.OwnerReferences[0].UID)
	assert.Equal(t, "bar", cm.Data["foo"])
}

// 다른 OctoVault 가 owner-uid 로 소유한 대상은 덮어쓰지 않는다.
func TestOctoVault_TargetOwnedByAnotherOctoVaultUID_IsRefused(t *testing.T) {

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			Annotations: map[string]string{
				AnnoOVOwnerUID:  "other-uid",
				AnnoOVOwnerFull: ownershipNS + "/someone-else",
			},
		},
		Data: map[string]string{"keep": "me"},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason)

	var cm corev1.ConfigMap
	getTarget(t, cl, &cm)
	assert.Equal(t, "other-uid", cm.Annotations[AnnoOVOwnerUID])
	assert.Equal(t, "me", cm.Data["keep"])
}

// 파이널라이저가 돌지 못하고 OctoVault 가 지워져 owner-uid 가 옛 UID 로 남은 대상은, 같은 <ns>/<name> 이라도
// 그것만으로는 이어받지 않는다. adopt 가 붙어야 이어받는다.
func TestOctoVault_StaleOwnerUID_IsAdoptedOnlyWithAdopt(t *testing.T) {

	stale := func(extra map[string]string) *corev1.Secret {
		ann := map[string]string{AnnoOVOwnerUID: "previous-uid", AnnoOVOwnerFull: ownershipNS + "/ov-ownership"}
		for k, v := range extra {
			ann[k] = v
		}

		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ownershipTarget, Namespace: ownershipNS, Annotations: ann}}
	}

	rec, cl, ov := newOwnershipReconciler(t, sampleSecretYAML, stale(nil))
	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason, "the name alone is not enough")

	rec, cl, ov = newOwnershipReconciler(t, sampleSecretYAML, stale(map[string]string{AnnoOVAdopt: "true"}))
	_, updated = reconcileOwnership(t, rec, cl, ov)
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var sec corev1.Secret
	getTarget(t, cl, &sec)
	assert.Equal(t, "ov-uid", sec.Annotations[AnnoOVOwnerUID])
	assert.NotContains(t, sec.Annotations, AnnoOVAdopt)
}

func TestMapTargetToOctoVault(t *testing.T) {

	longName := "ov-" + strings.Repeat("x", 80)
	scheme := newScheme(t)
	short := &octovaultv1alpha1.OctoVault{ObjectMeta: metav1.ObjectMeta{Name: "short", Namespace: "ns", UID: "short-uid"}}
	long := &octovaultv1alpha1.OctoVault{ObjectMeta: metav1.ObjectMeta{Name: longName, Namespace: "ns", UID: "long-uid"}}
	rec := &OctoVaultReconciler{Client: newFakeClient(t, scheme, short, long)}
	ctx := context.Background()

	target := func(labels, annotations map[string]string) *metav1.PartialObjectMetadata {
		return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "ns", Labels: labels, Annotations: annotations}}
	}
	names := func(obj client.Object) []string {
		var out []string
		for _, r := range rec.mapTargetToOctoVault(ctx, obj) {
			out = append(out, r.Name)
		}

		return out
	}

	assert.Equal(t, []string{"short"}, names(target(map[string]string{LabelOVOwnerNS: "ns", LabelOVOwnerName: "short"}, nil)))
	assert.Equal(t, []string{longName}, names(target(map[string]string{LabelOVOwnerNS: "ns", LabelOVOwnerName: labelSafe(longName)}, nil)),
		"a hashed owner-name label still maps to the long-named OctoVault")
	assert.Equal(t, []string{"short"}, names(target(nil, map[string]string{AnnoOVOwnerFull: "ns/short"})),
		"falls back to the owner annotation when labels are gone")
	assert.Empty(t, names(target(map[string]string{LabelOVOwnerNS: "ns", LabelOVOwnerName: "short"}, map[string]string{AnnoOVOwnerUID: "someone-else"})),
		"a different owner UID does not map")
	assert.Empty(t, names(target(nil, nil)), "objects without owner traces are ignored")

	foreign := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "attacker",
		Labels: map[string]string{LabelOVOwnerNS: "ns", LabelOVOwnerName: "short"}}}
	assert.Empty(t, names(foreign), "owner labels pointing at another namespace are ignored")

	foreignAnno := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "attacker",
		Annotations: map[string]string{AnnoOVOwnerFull: "ns/short"}}}
	assert.Empty(t, names(foreignAnno), "an owner annotation pointing at another namespace is ignored")
}

func TestTargetChanged_OwnerUID(t *testing.T) {

	base := func() *metav1.PartialObjectMetadata {
		return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnoOVOwnerUID: "ov"}}}
	}

	removed := base()
	delete(removed.Annotations, AnnoOVOwnerUID)
	assert.True(t, targetChanged(base(), removed), "removing owner-uid by hand must be reverted right away")
}

// 업그레이드 시점에 동기화가 실패하는 OctoVault 의 대상이나, targetName 을 바꾸기 전 이름으로 남은 대상도
// 동기화보다 먼저 ownerReference 를 떼야 한다. 남아 있으면 foreground 삭제 때 GC 가 지운다.
func TestOctoVault_LegacyOwnerReferences_AreMigratedEvenWhenSyncFails(t *testing.T) {

	ctrlTrue := true
	legacy := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{
			Name: name, Namespace: ownershipNS,
			Labels: map[string]string{LabelOVOwnerNS: ownershipNS, LabelOVOwnerName: "ov-ownership"},
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: octovaultv1alpha1.GroupVersion.String(), Kind: "OctoVault", Name: "ov-ownership", UID: types.UID("ov-uid"), Controller: &ctrlTrue},
			},
		}
	}

	oldName := &corev1.ConfigMap{ObjectMeta: legacy("previous-target-name")}
	rec, cl, ov := newOwnershipReconciler(t, invalidTypeYAML, oldName)
	require.NoError(t, cl.Create(context.Background(), &corev1.Secret{ObjectMeta: legacy("legacy-secret")}))

	_, updated := reconcileOwnership(t, rec, cl, ov)
	require.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase, "the sync itself fails")

	for _, obj := range []client.Object{&corev1.ConfigMap{}, &corev1.Secret{}} {
		name := "previous-target-name"
		if _, isSecret := obj.(*corev1.Secret); isSecret {

			name = "legacy-secret"
		}

		require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: name, Namespace: ownershipNS}, obj))
		assert.Empty(t, obj.GetOwnerReferences(), "%s: the legacy ownerReference must be removed", name)
		assert.Equal(t, "ov-uid", obj.GetAnnotations()[AnnoOVOwnerUID], "%s: owner-uid must be set", name)
	}
}

// 한 번 모두 옮긴 뒤에는 poll 마다 대상을 다시 찾지 않는다.
func TestOctoVault_LegacyOwnerReferenceMigration_RunsOnce(t *testing.T) {

	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ownershipNS}})

	secretLists := 0
	rec.Client = interceptor.NewClient(cl.(client.WithWatch), interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.SecretList); ok {

				secretLists++
			}

			return c.List(ctx, list, opts...)
		},
	})

	for range 3 {
		reconcileOwnership(t, rec, cl, ov)
	}

	assert.Equal(t, 1, secretLists)
}
