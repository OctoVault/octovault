package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

// config/samples 의 매니페스트는 CRD 검증을 통과해야 하고, OctoVault 의 repository owner 는
// 참조하는 OctoRepository 의 organization 과 맞아야 한다(맞지 않으면 RepositoryOwnerMismatch 로 실패한다).
func TestSamplesAreValidAndConsistent(t *testing.T) {

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

	ctx := context.Background()
	require.NoError(t, c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "devops"}}))

	files, err := filepath.Glob(filepath.Join("..", "config", "samples", "*.yaml"))
	require.NoError(t, err)

	orgs := map[string]string{}
	var vaults []octovaultv1alpha1.OctoVault
	for _, f := range files {
		if filepath.Base(f) == "kustomization.yaml" {

			continue
		}

		raw, err := os.ReadFile(f)
		require.NoError(t, err)

		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
		for {
			var u unstructured.Unstructured
			err := dec.Decode(&u.Object)
			if err == io.EOF {
				break
			}

			require.NoError(t, err, f)

			if len(u.Object) == 0 {

				continue
			}

			// 같은 이름의 샘플이 여러 파일에 있을 수 있으므로 생성 대신 덮어쓴다.
			obj := u.DeepCopy()
			if err := c.Create(ctx, obj); err != nil {

				require.NoError(t, client.IgnoreAlreadyExists(err), "%s: %s/%s", f, u.GetKind(), u.GetName())
			}

			switch u.GetKind() {
			case "OctoRepository":
				org, _, _ := unstructured.NestedString(u.Object, "spec", "organization")
				if prev, ok := orgs[u.GetName()]; ok {

					assert.Equal(t, prev, org, "%s: OctoRepository %q defined with different organizations", f, u.GetName())
				}

				orgs[u.GetName()] = org
			case "OctoVault":
				var ov octovaultv1alpha1.OctoVault
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), &ov), f)
				vaults = append(vaults, ov)
			}
		}
	}

	require.NotEmpty(t, vaults)
	for _, ov := range vaults {
		org, ok := orgs[ov.Spec.OctoRepositoryRef.Name]
		require.True(t, ok, "OctoVault %s references unknown OctoRepository %q", ov.Name, ov.Spec.OctoRepositoryRef.Name)

		owner, _, found := strings.Cut(ov.Spec.Repository, "/")
		if found {

			assert.True(t, strings.EqualFold(owner, strings.TrimPrefix(org, "github.com/")),
				"OctoVault %s: repository owner %q does not match organization %q", ov.Name, owner, org)
		}
	}
}
