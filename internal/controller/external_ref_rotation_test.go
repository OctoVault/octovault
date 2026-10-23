package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	awsps "github.com/octovault/octovault/internal/aws/parameter_store"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// 외부 시크릿이 같은 값으로 새 버전이 되면 데이터 해시는 그대로지만 status.externalRefs 는 갱신돼야 한다.

type versionedParamProvider struct {
	version int64
}

func (p *versionedParamProvider) GetParameter(ctx context.Context, name string, withDecryption bool) ([]byte, awsps.Meta, error) {
	return []byte("same-value"), awsps.Meta{Version: p.version}, nil
}

func (p *versionedParamProvider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {
	return value, nil
}

var singleParameterYAML = []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: TOKEN
      type: AwsParameterStore
      name: /p/token
`)

func TestOctoVault_ExternalRefVersionChange_IsRecorded(t *testing.T) {

	ctx := context.Background()
	const path = "values/rotation.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: singleParameterYAML}, rev: "rev1"})
	ps := &versionedParamProvider{version: 1}
	rec.AwsPS = ps
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	get := func() octovaultv1alpha1.OctoVault {
		var o octovaultv1alpha1.OctoVault
		require.NoError(t, cl.Get(ctx, key, &o))

		return o
	}

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	first := get()
	require.Len(t, first.Status.ExternalRefs, 1)
	require.Equal(t, "1", first.Status.ExternalRefs[0].VersionID)

	ps.version = 2
	_, err = rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
	require.NoError(t, err)
	second := get()

	assert.Equal(t, first.Status.AppliedDataHash, second.Status.AppliedDataHash, "value did not change")
	assert.Equal(t, "2", second.Status.ExternalRefs[0].VersionID)
	assert.Contains(t, second.Status.ExternalRefsSummary, "@2")
}
