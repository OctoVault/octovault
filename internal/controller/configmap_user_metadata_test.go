package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// __analysis/2_METADATA.md > Red Task List > 3. ConfigMap 생성 - 사용자 labels/annotations 반영

var sampleConfigMapWithMetaYAML = []byte(`
metadata:
  type: ConfigMap
  labels:
    team: backend
    env: production
  annotations:
    foo: bar
    owner: devops-team
spec:
  data:
    - key: setting
      value: value1
`)

var sampleConfigMapWithSystemKeyOverrideYAML = []byte(`
metadata:
  type: ConfigMap
  labels:
    app.kubernetes.io/managed-by: evil-override
    octovault.it/owner-ns: injected-ns
    custom-label: allowed
  annotations:
    octovault.it/owner: injected-owner
    reconcile.octovault.it/data-hash: fake-hash
    safe-anno: allowed-value
spec:
  data:
    - key: k
      value: v
`)

func newConfigMapUserMetaReconciler(t *testing.T, yaml []byte) (*OctoVaultReconciler, client.Client, *octovaultv1alpha1.OctoVault) {
	t.Helper()

	const (
		ns        = "devops"
		orepoName = "orepo-meta-test"
		credName  = "orepo-meta-cred"
		ovName    = "ov-cm-meta-test"
		targetCM  = "my-cm-with-meta"
		path      = "values/cm-meta.yaml"
	)

	scheme := newScheme(t)

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credName, Namespace: ns},
		StringData: map[string]string{"password": "dummy"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: orepoName},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/test-org",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name: credName, Namespace: ns,
			},
		},
	}
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{Name: ovName, Namespace: ns},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: orepoName},
			Repository:        "test-org/test-repo",
			Path:              path,
			TargetName:        targetCM,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git: &staticFetcher{
			files: map[string][]byte{path: yaml},
			rev:   "abc123",
		},
	}

	return rec, cl, ov
}

func TestOctoVault_ConfigMap_UserLabels_AreIncluded(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 3. ConfigMap 생성 - 사용자 labels/annotations 반영
	// values.yaml에 metadata.labels가 있을 때 생성된 ConfigMap의 ObjectMeta.Labels에 포함됨

	ctx := context.Background()
	rec, cl, ov := newConfigMapUserMetaReconciler(t, sampleConfigMapWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-cm-with-meta"}, &cm))

	assert.Equal(t, "backend", cm.Labels["team"], "user label 'team' should be in ConfigMap labels")
	assert.Equal(t, "production", cm.Labels["env"], "user label 'env' should be in ConfigMap labels")
}

func TestOctoVault_ConfigMap_UserAnnotations_AreIncluded(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 3. ConfigMap 생성 - 사용자 labels/annotations 반영
	// values.yaml에 metadata.annotations가 있을 때 생성된 ConfigMap의 ObjectMeta.Annotations에 포함됨

	ctx := context.Background()
	rec, cl, ov := newConfigMapUserMetaReconciler(t, sampleConfigMapWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-cm-with-meta"}, &cm))

	assert.Equal(t, "bar", cm.Annotations["foo"], "user annotation 'foo' should be in ConfigMap annotations")
	assert.Equal(t, "devops-team", cm.Annotations["owner"], "user annotation 'owner' should be in ConfigMap annotations")
}

func TestOctoVault_ConfigMap_SystemLabels_AlwaysPresent(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 3. ConfigMap 생성 - 사용자 labels/annotations 반영
	// 시스템 labels(app.kubernetes.io/managed-by, octovault.it/*)는 사용자 값과 무관하게 항상 존재함

	ctx := context.Background()
	rec, cl, ov := newConfigMapUserMetaReconciler(t, sampleConfigMapWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-cm-with-meta"}, &cm))

	assert.Equal(t, "octovault", cm.Labels[LabelManagedBy], "system label 'app.kubernetes.io/managed-by' must always be present")
	assert.NotEmpty(t, cm.Labels[LabelOVOwnerNS], "system label 'octovault.it/owner-ns' must always be present")
	assert.NotEmpty(t, cm.Labels[LabelOVOwnerName], "system label 'octovault.it/owner-name' must always be present")
}

func TestOctoVault_ConfigMap_SystemLabels_NotOverriddenByUser(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 3. ConfigMap 생성 - 사용자 labels/annotations 반영
	// 사용자가 시스템 키와 동일한 키를 지정해도 시스템 값이 유지됨

	ctx := context.Background()
	rec, cl, ov := newConfigMapUserMetaReconciler(t, sampleConfigMapWithSystemKeyOverrideYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-cm-with-meta"}, &cm))

	// 시스템 값이 유지되어야 함 (사용자가 덮어쓰기 시도해도)
	assert.Equal(t, "octovault", cm.Labels[LabelManagedBy], "system label must not be overridden by user")
	assert.NotEqual(t, "injected-ns", cm.Labels[LabelOVOwnerNS], "user must not override octovault.it/owner-ns")
	assert.NotEqual(t, "injected-owner", cm.Annotations[AnnoOVOwnerFull], "user must not override octovault.it/owner annotation")
	assert.NotEqual(t, "fake-hash", cm.Annotations["reconcile.octovault.it/data-hash"], "user must not override reconcile annotation")

	// 예약되지 않은 사용자 키는 포함되어야 함
	assert.Equal(t, "allowed", cm.Labels["custom-label"], "non-reserved user label should be included")
	assert.Equal(t, "allowed-value", cm.Annotations["safe-anno"], "non-reserved user annotation should be included")
}
