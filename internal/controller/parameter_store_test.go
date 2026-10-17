package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	awsps "github.com/octovault/octovault/internal/aws/parameter_store"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// values.yaml 의 withDecryption 이 Parameter Store 호출까지 전달돼야 한다.

type recordingParamProvider struct {
	calls map[string]bool // name -> withDecryption
}

func (p *recordingParamProvider) GetParameter(ctx context.Context, name string, withDecryption bool) ([]byte, awsps.Meta, error) {

	p.calls[name] = withDecryption

	return []byte("value-of-" + name), awsps.Meta{Version: 7, Type: "SecureString"}, nil
}

func (p *recordingParamProvider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {
	return value, nil
}

var parameterStoreYAML = []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: DEFAULTED
      type: AwsParameterStore
      name: /p/defaulted
    - key: PLAIN
      type: AwsParameterStore
      name: /p/plain
      withDecryption: false
    - key: DECRYPTED
      type: AwsParameterStore
      name: /p/decrypted
      withDecryption: true
`)

func TestOctoVault_ParameterStore_WithDecryption_IsPassedThrough(t *testing.T) {

	ctx := context.Background()
	const path = "values/ps.yaml"

	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: parameterStoreYAML}, rev: "rev1"})
	ps := &recordingParamProvider{calls: map[string]bool{}}
	rec.AwsPS = ps

	_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}})
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{
		"/p/defaulted": true,
		"/p/plain":     false,
		"/p/decrypted": true,
	}, ps.calls)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Spec.TargetName, Namespace: ov.Namespace}, &sec))
	assert.Equal(t, []byte("value-of-/p/plain"), sec.Data["PLAIN"])

	var updated octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}, &updated))
	assert.Equal(t, octovaultv1alpha1.OVPhaseSynced, updated.Status.Phase)
}
