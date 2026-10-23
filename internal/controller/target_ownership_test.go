package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// 같은 이름의 대상 리소스가 이미 있는데 이 OctoVault 가 소유하지 않았다면
// 덮어쓰지 않고 TargetNotOwned 로 실패해야 한다.

const (
	ownershipNS     = "app-ns"
	ownershipTarget = "target-resource"
	ownershipPath   = "values/ownership.yaml"
)

func newOwnershipReconciler(t *testing.T, values []byte, existing client.Object) (*OctoVaultReconciler, client.Client, *octovaultv1alpha1.OctoVault) {
	t.Helper()

	scheme := newScheme(t)

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cred-ownership", Namespace: ownershipNS},
		StringData: map[string]string{"password": "dummy"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo-ownership"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name: "cred-ownership", Namespace: ownershipNS,
			},
		},
	}
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{Name: "ov-ownership", Namespace: ownershipNS, UID: types.UID("ov-uid")},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "orepo-ownership"},
			Repository:        "test-org/test-repo",
			Path:              ownershipPath,
			TargetName:        ownershipTarget,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov, existing)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git: &staticFetcher{
			files: map[string][]byte{ownershipPath: values},
			rev:   "rev1",
		},
	}

	return rec, cl, ov
}

func reconcileOwnership(t *testing.T, rec *OctoVaultReconciler, cl client.Client, ov *octovaultv1alpha1.OctoVault) (reconcile.Result, octovaultv1alpha1.OctoVault) {
	t.Helper()

	ctx := context.Background()
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	res, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))

	return res, updated
}

func TestOctoVault_ExistingUnownedConfigMap_IsNotOverwritten(t *testing.T) {

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ownershipTarget, Namespace: ownershipNS},
		Data:       map[string]string{"keep": "me"},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	res, updated := reconcileOwnership(t, rec, cl, ov)

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason)
	assert.Equal(t, DefaultPollInterval, res.RequeueAfter, "must back off to poll interval, not hot-loop")

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, &cm))
	assert.Equal(t, map[string]string{"keep": "me"}, cm.Data)
	assert.Empty(t, cm.OwnerReferences)
}

func TestOctoVault_SecretOwnedByAnotherOctoVault_IsNotOverwritten(t *testing.T) {

	ctrlTrue := true
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ownershipTarget,
			Namespace: ownershipNS,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: octovaultv1alpha1.GroupVersion.String(),
				Kind:       "OctoVault",
				Name:       "someone-else",
				UID:        types.UID("other-uid"),
				Controller: &ctrlTrue,
			}},
		},
		Data: map[string][]byte{"keep": []byte("me")},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleSecretYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)

	assert.Equal(t, octovaultv1alpha1.OVPhaseFailed, updated.Status.Phase)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason)

	var sec corev1.Secret
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, &sec))
	assert.Equal(t, map[string][]byte{"keep": []byte("me")}, sec.Data)
	require.Len(t, sec.OwnerReferences, 1)
	assert.Equal(t, types.UID("other-uid"), sec.OwnerReferences[0].UID)
}

// 삭제 후 같은 이름으로 다시 만든 OctoVault 는 이전에 남겨 둔 대상을 이어받아야 한다.
// 남겨진 대상은 같은 이름의 OctoVault 라도 adopt 없이는 이어받지 않는다(이름만으로는 덮어쓸 수 없다).
func TestOctoVault_RetainedTarget_WithoutAdopt_IsNotAdopted(t *testing.T) {

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			Annotations: map[string]string{
				AnnoOVRetainedBy: ownershipNS + "/ov-ownership",
				AnnoOVOwnerFull:  ownershipNS + "/ov-ownership",
			},
		},
		Data: map[string]string{"old": "data"},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, &cm))
	assert.Equal(t, map[string]string{"old": "data"}, cm.Data, "the retained target must not be overwritten")
}

// adopt 어노테이션이 붙은 남겨진 대상은 이어받고, adopt 는 한 번 쓰인 뒤 사라진다.
func TestOctoVault_RetainedTarget_WithAdopt_IsAdopted(t *testing.T) {

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			Annotations: map[string]string{
				AnnoOVRetainedBy: ownershipNS + "/ov-ownership",
				AnnoOVAdopt:      "true",
			},
		},
		Data: map[string]string{"old": "data"},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, &cm))
	assert.True(t, metav1.IsControlledBy(&cm, &updated), "controller ref must point at the new OctoVault")
	assert.NotContains(t, cm.Annotations, AnnoOVRetainedBy)
	assert.NotContains(t, cm.Annotations, AnnoOVAdopt, "adopt is consumed")
	assert.Equal(t, "bar", cm.Data["foo"])
}

// --cascade=orphan 처럼 ownerRef 만 사라진 대상도 adopt 를 붙이면 이어받는다.
func TestOctoVault_OrphanedTargetWithAdopt_IsAdopted(t *testing.T) {

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			Annotations: map[string]string{AnnoOVOwnerFull: ownershipNS + "/ov-ownership", AnnoOVAdopt: "true"},
		},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleSecretYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var sec corev1.Secret
	require.NoError(t, cl.Get(context.Background(), client.ObjectKey{Name: ownershipTarget, Namespace: ownershipNS}, &sec))
	assert.Equal(t, string(updated.UID), targetOwnerUID(&sec), "the OctoVault must own the adopted target")
	assert.Equal(t, "s3cr3t", string(sec.Data["token"]), "the adopted target must carry the synced data")
}

// targetOwnerUID 대상을 소유한 OctoVault 의 UID. 없으면 "".
func targetOwnerUID(obj metav1.Object) string {
	if ref := metav1.GetControllerOf(obj); ref != nil {

		return string(ref.UID)
	}

	return ""
}

// 다른 주체가 controller 인 대상은 adopt 가 있어도 가져오지 않는다.
func TestOctoVault_ControlledTargetWithAdopt_IsNotAdopted(t *testing.T) {

	ctrlTrue := true
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: ownershipTarget, Namespace: ownershipNS,
			Annotations: map[string]string{AnnoOVAdopt: "true"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment", Name: "other", UID: types.UID("other-uid"), Controller: &ctrlTrue,
			}},
		},
	}
	rec, cl, ov := newOwnershipReconciler(t, sampleConfigMapYAML, existing)

	_, updated := reconcileOwnership(t, rec, cl, ov)
	assert.Equal(t, "TargetNotOwned", updated.Status.Conditions[0].Reason)
}

// 삭제(파이널라이저가 대상을 남김) → 같은 이름으로 재생성 → 다시 동기화되는 전체 흐름.
func TestOctoVault_DeleteAndRecreate_ResumesManagingTarget(t *testing.T) {

	ctx := context.Background()
	const path = "values/recreate.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	require.NoError(t, cl.Delete(ctx, &current))
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(cl.Get(ctx, key, &current)), "the OctoVault must be gone after its finalizer ran")

	// 남겨진 대상을 다시 관리하려면 그 대상을 수정할 수 있는 사람이 adopt 를 붙인다.
	var retained corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &retained))
	retained.Annotations[AnnoOVAdopt] = "true"
	require.NoError(t, cl.Update(ctx, &retained))

	recreated := ov.DeepCopy()
	recreated.ResourceVersion = ""
	recreated.UID = types.UID("recreated-uid")
	require.NoError(t, cl.Create(ctx, recreated))

	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &cm))
	ctrlRef := metav1.GetControllerOf(&cm)
	require.NotNil(t, ctrlRef, "the target must have a controller again")
	assert.Equal(t, types.UID("recreated-uid"), ctrlRef.UID, "the controller must be the recreated OctoVault")
	assert.NotContains(t, cm.Annotations, AnnoOVRetainedBy)
}
