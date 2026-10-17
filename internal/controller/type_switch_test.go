package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
