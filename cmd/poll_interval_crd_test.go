package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

// CRD 가 s/m/h 단위의 pollInterval 을 받아들이고, 그 외 형식은 거부해야 한다.
func TestPollIntervalCRDValidation(t *testing.T) {

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

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	for i, tc := range []struct {
		value string
		ok    bool
	}{
		{"90s", true}, {"5m", true}, {"1h30m", true},
		{"500ms", false}, {"5", false}, {"1d", false},
	} {
		err := c.Create(context.Background(), &octovaultv1alpha1.OctoVault{
			ObjectMeta: metav1.ObjectMeta{Name: "ov-" + string(rune('a'+i)), Namespace: "default"},
			Spec: octovaultv1alpha1.OctoVaultSpec{
				OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: "org"},
				Repository:        "repo",
				Path:              "values.yaml",
				TargetName:        "out",
				PollInterval:      tc.value,
			},
		})
		assert.Equal(t, tc.ok, err == nil, "pollInterval %q: err=%v", tc.value, err)
	}
}
