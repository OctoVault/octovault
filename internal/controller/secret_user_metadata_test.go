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

// __analysis/2_METADATA.md > Red Task List > 4. Secret 생성 - 사용자 labels/annotations 반영

var sampleSecretWithMetaYAML = []byte(`
metadata:
  type: Secret
  labels:
    team: security
    env: staging
  annotations:
    purpose: api-credentials
    managed-by-team: platform
spec:
  data:
    - key: token
      type: Text
      value: s3cr3t
`)

var sampleSecretWithSystemKeyOverrideYAML = []byte(`
metadata:
  type: Secret
  labels:
    app.kubernetes.io/managed-by: evil-override
    octovault.it/owner-name: injected-name
    safe-label: allowed
  annotations:
    octovault.it/owner: injected-owner
    reconcile.octovault.it/data-hash: fake-hash
    safe-anno: allowed-value
spec:
  data:
    - key: password
      type: Text
      value: topsecret
`)

func newSecretUserMetaReconciler(t *testing.T, yaml []byte) (*OctoVaultReconciler, client.Client, *octovaultv1alpha1.OctoVault) {
	t.Helper()

	const (
		ns        = "devops"
		orepoName = "orepo-secret-meta-test"
		credName  = "orepo-secret-meta-cred"
		ovName    = "ov-secret-meta-test"
		targetSec = "my-secret-with-meta"
		path      = "values/secret-meta.yaml"
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
			TargetName:        targetSec,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git: &staticFetcher{
			files: map[string][]byte{path: yaml},
			rev:   "deadbeef",
		},
	}

	return rec, cl, ov
}

func TestOctoVault_Secret_UserLabels_AreIncluded(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 4. Secret 생성 - 사용자 labels/annotations 반영
	// values.yaml에 metadata.labels가 있을 때 생성된 Secret의 ObjectMeta.Labels에 포함됨

	ctx := context.Background()
	rec, cl, ov := newSecretUserMetaReconciler(t, sampleSecretWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-secret-with-meta"}, &sec))

	assert.Equal(t, "security", sec.Labels["team"], "user label 'team' should be in Secret labels")
	assert.Equal(t, "staging", sec.Labels["env"], "user label 'env' should be in Secret labels")
}

func TestOctoVault_Secret_UserAnnotations_AreIncluded(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 4. Secret 생성 - 사용자 labels/annotations 반영
	// values.yaml에 metadata.annotations가 있을 때 생성된 Secret의 ObjectMeta.Annotations에 포함됨

	ctx := context.Background()
	rec, cl, ov := newSecretUserMetaReconciler(t, sampleSecretWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-secret-with-meta"}, &sec))

	assert.Equal(t, "api-credentials", sec.Annotations["purpose"], "user annotation 'purpose' should be in Secret annotations")
	assert.Equal(t, "platform", sec.Annotations["managed-by-team"], "user annotation 'managed-by-team' should be in Secret annotations")
}

func TestOctoVault_Secret_SystemLabels_AlwaysPresent(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 4. Secret 생성 - 사용자 labels/annotations 반영
	// 시스템 labels/annotations는 항상 보존됨

	ctx := context.Background()
	rec, cl, ov := newSecretUserMetaReconciler(t, sampleSecretWithMetaYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-secret-with-meta"}, &sec))

	assert.Equal(t, "octovault", sec.Labels[LabelManagedBy], "system label 'app.kubernetes.io/managed-by' must always be present")
	assert.NotEmpty(t, sec.Labels[LabelOVOwnerNS], "system label 'octovault.it/owner-ns' must always be present")
	assert.NotEmpty(t, sec.Labels[LabelOVOwnerName], "system label 'octovault.it/owner-name' must always be present")
	assert.NotEmpty(t, sec.Annotations[AnnoOVOwnerFull], "system annotation 'octovault.it/owner' must always be present")
}

func TestOctoVault_Secret_SystemLabels_NotOverriddenByUser(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 4. Secret 생성 - 사용자 labels/annotations 반영
	// 사용자가 시스템 키 덮어쓰기 시도해도 시스템 값 유지됨

	ctx := context.Background()
	rec, cl, ov := newSecretUserMetaReconciler(t, sampleSecretWithSystemKeyOverrideYAML)

	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "my-secret-with-meta"}, &sec))

	// 시스템 값이 유지되어야 함 (사용자가 덮어쓰기 시도해도)
	assert.Equal(t, "octovault", sec.Labels[LabelManagedBy], "system label must not be overridden by user")
	assert.NotEqual(t, "injected-name", sec.Labels[LabelOVOwnerName], "user must not override octovault.it/owner-name")
	assert.NotEqual(t, "injected-owner", sec.Annotations[AnnoOVOwnerFull], "user must not override octovault.it/owner annotation")
	assert.NotEqual(t, "fake-hash", sec.Annotations["reconcile.octovault.it/data-hash"], "user must not override reconcile annotation")

	// 예약되지 않은 사용자 키는 포함되어야 함
	assert.Equal(t, "allowed", sec.Labels["safe-label"], "non-reserved user label should be included")
	assert.Equal(t, "allowed-value", sec.Annotations["safe-anno"], "non-reserved user annotation should be included")
}
