package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

func TestPollIntervalOf(t *testing.T) {

	of := func(v string) time.Duration {
		return pollIntervalOf(&octovaultv1alpha1.OctoVault{Spec: octovaultv1alpha1.OctoVaultSpec{PollInterval: v}})
	}

	assert.Equal(t, DefaultPollInterval, of(""))
	assert.Equal(t, 90*time.Second, of("90s"))
	assert.Equal(t, 90*time.Minute, of("1h30m"))
	assert.Equal(t, MinPollInterval, of("5s"), "values below the minimum are raised")
	assert.Equal(t, MinPollInterval, of("0s"), "0s is below the minimum, not unset")
	assert.Equal(t, DefaultPollInterval, of("garbage"))
}

// 해석할 수 없는 pollInterval 은 reconcile 마다가 아니라 한 번만 로그로 남긴다.
func TestOctoVault_UnparsablePollInterval_IsLoggedOnce(t *testing.T) {

	var lines []string
	ctx := logf.IntoContext(context.Background(), funcr.New(func(prefix, args string) {
		if strings.Contains(args, "spec.pollInterval cannot be parsed") {

			lines = append(lines, args)
		}
	}, funcr.Options{}))

	const path = "values/poll.yaml"
	rec, cl, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: sampleConfigMapYAML}, rev: "rev1"})
	key := client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}

	var current octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, key, &current))
	current.Spec.PollInterval = "9999999999h"
	require.NoError(t, cl.Update(ctx, &current))

	for range 3 {
		res, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		require.NoError(t, err)
		assert.Equal(t, DefaultPollInterval, res.RequeueAfter)
	}

	assert.Len(t, lines, 1)
}
