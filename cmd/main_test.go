package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/octovault/octovault/internal/controller"
)

// Secret 캐시는 라벨이 붙은 Secret 만 담고, 클라이언트 조회는 라벨과 무관하게 동작해야 한다.
func TestSecretCacheIsLabelScoped(t *testing.T) {

	env := &envtest.Environment{BinaryAssetsDirectory: firstEnvtestBinaryDir()}
	cfg, err := env.Start()
	if err != nil {

		t.Skipf("envtest unavailable (run 'make setup-envtest'): %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Cache:                  secretCacheOptions(),
		Client:                 secretClientOptions(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	labelled := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "labelled", Namespace: "default",
		Labels: map[string]string{controller.LabelRepo: controller.LabelRepoTrue},
	}}
	plain := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "default"}}
	require.NoError(t, direct.Create(ctx, labelled))
	require.NoError(t, direct.Create(ctx, plain))

	var got corev1.Secret
	require.NoError(t, mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(plain), &got),
		"unlabelled Secrets must still be readable through the manager client")

	assert.Eventually(t, func() bool {
		var list corev1.SecretList
		if err := mgr.GetCache().List(ctx, &list, client.InNamespace("default")); err != nil {

			return false
		}

		return len(list.Items) == 1 && list.Items[0].Name == "labelled"
	}, 10*time.Second, 100*time.Millisecond, "cache must hold only labelled Secrets")
}

func firstEnvtestBinaryDir() string {

	base := filepath.Join("..", "bin", "k8s")
	entries, err := os.ReadDir(base)
	if err != nil {

		return ""
	}

	for _, e := range entries {
		if e.IsDir() {

			return filepath.Join(base, e.Name())
		}
	}

	return ""
}
