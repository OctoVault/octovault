package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// 설치된 CRD 가 allowedNamespaces 를 모르면 시작하지 않아야 한다(옛 CRD 에서는 제한이 조용히 풀린다).
func TestVerifyCRDs(t *testing.T) {

	env := &envtest.Environment{
		BinaryAssetsDirectory: firstEnvtestBinaryDir(),
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {

		skipOrFailEnvtest(t, err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	ctx := context.Background()
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	require.NoError(t, verifyCRDs(ctx, c), "the CRDs from this repository are current")

	// 옛 CRD 를 흉내 내 allowedNamespaces 를 스키마에서 지운다.
	crd := &unstructured.Unstructured{}
	crd.SetGroupVersionKind(crdGVK)
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: octoRepositoryCRD}, crd))

	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for i, v := range versions {
		m := v.(map[string]interface{})
		unstructured.RemoveNestedField(m, allowedNamespacesSchemaPath...)
		versions[i] = m
	}
	require.NoError(t, unstructured.SetNestedSlice(crd.Object, versions, "spec", "versions"))
	require.NoError(t, c.Update(ctx, crd))

	err = verifyCRDs(ctx, c)
	require.True(t, errors.Is(err, errStaleCRD), "a stale CRD must be reported: %v", err)

	// 실행 중에 옛 CRD 가 다시 적용되면 주기 확인이 매니저를 멈춘다.
	watchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = watchCRDs(c, 10*time.Millisecond)(watchCtx)
	require.True(t, errors.Is(err, errStaleCRD), "the periodic re-check must stop the manager: %v", err)
}
