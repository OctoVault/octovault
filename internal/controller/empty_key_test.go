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

// 빈 data.key 는 values.yaml 을 고치기 전까지 재시도해도 결과가 같으므로
// err 없이 poll 주기로 물러나야 한다. err 를 함께 반환하면 RequeueAfter 가 무시되고
// 5ms 부터 시작하는 백오프로 재시도한다.

var emptyKeySecretYAML = []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: ""
      value: x
`)

func TestOctoVault_Secret_EmptyKey_BacksOffWithoutError(t *testing.T) {

	ctx := context.Background()
	const path = "values/empty-key.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: emptyKeySecretYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	res, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	assert.Equal(t, DefaultPollInterval, res.RequeueAfter)

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &updated))
	assert.Equal(t, "InvalidData", updated.Status.Conditions[0].Reason)
}
