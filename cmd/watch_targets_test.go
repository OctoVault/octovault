package main

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	"github.com/octovault/octovault/internal/controller"
)

type mapFetcher struct {
	mu    sync.Mutex
	files map[string][]byte
	calls atomic.Int32
}

func (m *mapFetcher) Fetch(ctx context.Context, org, repo, path, ref, token string) ([]byte, []byte, string, error) {

	m.calls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.files[path], nil, "rev1", nil
}

func (m *mapFetcher) set(path string, b []byte) {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.files[path] = b
}

// 대상 ConfigMap/Secret 이 지워지면 poll 주기(여기선 60m)를 기다리지 않고 바로 다시 만들어져야 한다.
func TestDeletedTargetsAreRestoredByWatch(t *testing.T) {

	env := &envtest.Environment{
		BinaryAssetsDirectory: firstEnvtestBinaryDir(),
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}
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

	targetSecrets, err := newTargetSecretCache(mgr)
	require.NoError(t, err)

	fetcher := &mapFetcher{files: map[string][]byte{
		"cm.yaml":  []byte("metadata:\n  type: ConfigMap\nspec:\n  data:\n    - key: a\n      value: b\n"),
		"sec.yaml": []byte("metadata:\n  type: Secret\nspec:\n  data:\n    - key: a\n      value: b\n"),
	}}

	require.NoError(t, (&controller.OctoVaultReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor("octovault"),
		Git:           fetcher,
		TargetSecrets: targetSecrets,
	}).SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()

	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	require.NoError(t, direct.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cred", Namespace: "default"},
		Data:       map[string][]byte{"password": []byte("tok")},
	}))
	require.NoError(t, direct.Create(ctx, &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "org"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:   "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{Name: "cred", Namespace: "default"},
		},
	}))

	for _, tc := range []struct {
		path   string
		target client.Object
	}{
		{path: "cm.yaml", target: &corev1.ConfigMap{}},
		{path: "sec.yaml", target: &corev1.Secret{}},
	} {
		name := "out-" + tc.path[:len(tc.path)-len(".yaml")]
		require.NoError(t, direct.Create(ctx, &octovaultv1alpha1.OctoVault{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: octovaultv1alpha1.OctoVaultSpec{
				OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "org"},
				Repository:        "test-repo",
				Path:              tc.path,
				TargetName:        name,
				PollInterval:      "60m",
			},
		}))

		key := client.ObjectKey{Name: name, Namespace: "default"}
		exists := func() bool { return direct.Get(ctx, key, tc.target) == nil }

		require.Eventually(t, exists, 20*time.Second, 100*time.Millisecond, "%s must be created", name)
		uid := tc.target.GetUID()

		require.NoError(t, direct.Delete(ctx, tc.target))
		require.Eventually(t, func() bool {

			return exists() && tc.target.GetUID() != uid
		}, 20*time.Second, 100*time.Millisecond, "%s must be recreated without waiting for the poll interval", name)
	}

	// 다른 주체가 붙인 라벨은 reconcile 을 일으키지 않아야 한다(webhook 과의 덮어쓰기 루프 방지).
	cmKey := client.ObjectKey{Name: "out-cm", Namespace: "default"}
	var cm corev1.ConfigMap
	require.Eventually(t, func() bool { return direct.Get(ctx, cmKey, &cm) == nil }, 20*time.Second, 100*time.Millisecond)
	time.Sleep(time.Second) // 앞선 재생성으로 인한 reconcile 이 끝나기를 기다린다
	before := fetcher.calls.Load()

	cm.Labels["injected-by-webhook"] = "yes"
	require.NoError(t, direct.Update(ctx, &cm))
	time.Sleep(2 * time.Second)
	require.Equal(t, before, fetcher.calls.Load(), "a foreign label must not trigger a reconcile")

	// 데이터를 손으로 바꾸면 바로 되돌린다.
	require.NoError(t, direct.Get(ctx, cmKey, &cm))
	cm.Data["a"] = "edited"
	require.NoError(t, direct.Update(ctx, &cm))
	require.Eventually(t, func() bool {
		return direct.Get(ctx, cmKey, &cm) == nil && cm.Data["a"] == "b"
	}, 20*time.Second, 100*time.Millisecond,
		"a hand edit to managed data must be reverted without waiting for the poll interval")

	// Secret 에서 ConfigMap 으로 바꾸면, 남은 Secret 은 메타데이터 캐시로 확인해 지워진다.
	secKey := client.ObjectKey{Name: "out-sec", Namespace: "default"}
	fetcher.set("sec.yaml", []byte("metadata:\n  type: ConfigMap\nspec:\n  data:\n    - key: a\n      value: b\n"))

	var ov octovaultv1alpha1.OctoVault
	require.NoError(t, direct.Get(ctx, secKey, &ov))
	ov.Spec.PollInterval = "61m" // spec 을 바꿔 바로 reconcile 하게 한다
	require.NoError(t, direct.Update(ctx, &ov))

	require.Eventually(t, func() bool {
		secretGone := apierrors.IsNotFound(direct.Get(ctx, secKey, &corev1.Secret{}))
		configMapThere := direct.Get(ctx, secKey, &corev1.ConfigMap{}) == nil

		return secretGone && configMapThere
	}, 20*time.Second, 100*time.Millisecond, "the previous Secret must be deleted after switching to ConfigMap")
}
