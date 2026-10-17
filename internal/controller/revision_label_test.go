package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// fetcher 가 revision 을 주지 않으면 내용 해시로 대신하는데, 이 값은 라벨 값으로도 쓰이므로
// 라벨 규칙을 지켜야 한다. fake client 는 라벨을 검증하지 않으므로 직접 확인한다.
func TestOctoVault_FallbackRevision_IsValidLabelValue(t *testing.T) {

	ctx := context.Background()
	const path = "values/rev.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: ""})

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &cm))

	rev := cm.Labels["reconcile.octovault.it/revision"]
	require.NotEmpty(t, rev)
	assert.Empty(t, validation.IsValidLabelValue(rev), "revision label %q must be a valid label value", rev)
}
