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

// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신

// --- 업데이트 시나리오용 YAML 픽스처 ---

var updateV1ConfigMapYAML = []byte(`
metadata:
  type: ConfigMap
  labels:
    version: v1
    team: alpha
  annotations:
    release: first
spec:
  data:
    - key: setting
      value: initial
`)

var updateV2ConfigMapYAML = []byte(`
metadata:
  type: ConfigMap
  labels:
    version: v2
    team: beta
  annotations:
    release: second
spec:
  data:
    - key: setting
      value: initial
`)

var updateNoLabelsConfigMapYAML = []byte(`
metadata:
  type: ConfigMap
spec:
  data:
    - key: setting
      value: initial
`)

var updateV1SecretYAML = []byte(`
metadata:
  type: Secret
  labels:
    version: v1
  annotations:
    release: first
spec:
  data:
    - key: token
      type: Text
      value: secret1
`)

var updateNoLabelsSecretYAML = []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: token
      type: Text
      value: secret1
`)

// --- 헬퍼 ---

func newUpdateMetaReconciler(t *testing.T, path string, fetcher *staticFetcher) (*OctoVaultReconciler, client.Client, *octovaultv1alpha1.OctoVault) {
	t.Helper()

	const (
		ns        = "devops"
		orepoName = "orepo-update-meta"
		credName  = "orepo-update-meta-cred"
		ovName    = "ov-update-meta"
		target    = "target-resource"
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
			TargetName:        target,
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git:      fetcher,
	}

	return rec, cl, ov
}

func TestOctoVault_ConfigMap_Labels_AreUpdated_OnNextReconcile(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신
	// values.yaml의 metadata.labels가 변경된 후 Reconcile 시 기존 ConfigMap의 labels가 갱신됨

	ctx := context.Background()
	const path = "values/cm-update.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: updateV1ConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)

	// 1차 Reconcile: v1 labels로 ConfigMap 생성
	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &cm))
	require.Equal(t, "v1", cm.Labels["version"])
	require.Equal(t, "alpha", cm.Labels["team"])

	// values.yaml 변경: v2 labels로 교체
	fetcher.files[path] = updateV2ConfigMapYAML
	fetcher.rev = "rev2"

	// 2차 Reconcile: labels 갱신 확인
	_, err = rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &updated))

	assert.Equal(t, "v2", updated.Labels["version"], "label 'version' should be updated to v2")
	assert.Equal(t, "beta", updated.Labels["team"], "label 'team' should be updated to beta")
	assert.Equal(t, "second", updated.Annotations["release"], "annotation 'release' should be updated")
}

func TestOctoVault_ConfigMap_UserLabels_RemovedWhenNotInValues(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신
	// values.yaml에서 metadata.labels 전체 제거 후 Reconcile 시 이전 사용자 labels가 제거됨 (시스템 labels 유지)

	ctx := context.Background()
	const path = "values/cm-remove-labels.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: updateV1ConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)

	// 1차 Reconcile: user labels 있음
	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &cm))
	require.Equal(t, "v1", cm.Labels["version"], "precondition: v1 label should exist after first reconcile")

	// values.yaml에서 labels 완전 제거
	fetcher.files[path] = updateNoLabelsConfigMapYAML
	fetcher.rev = "rev2"

	// 2차 Reconcile
	_, err = rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &updated))

	// 사용자 labels 제거됨
	assert.NotContains(t, updated.Labels, "version", "removed user label 'version' must not persist")
	assert.NotContains(t, updated.Labels, "team", "removed user label 'team' must not persist")

	// 시스템 labels 유지됨
	assert.Equal(t, "octovault", updated.Labels[LabelManagedBy], "system label must be preserved after user labels removal")
	assert.NotEmpty(t, updated.Labels[LabelOVOwnerNS], "system label owner-ns must be preserved")
}

func TestOctoVault_ConfigMap_UserAnnotations_RemovedWhenNotInValues(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신
	// values.yaml에서 metadata.annotations 전체 제거 후 Reconcile 시 이전 사용자 annotations가 제거됨 (시스템 annotations 유지)

	ctx := context.Background()
	const path = "values/cm-remove-annos.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: updateV1ConfigMapYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)

	// 1차 Reconcile: user annotations 있음
	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &cm))
	require.Equal(t, "first", cm.Annotations["release"], "precondition: annotation should exist after first reconcile")

	// values.yaml에서 annotations 완전 제거
	fetcher.files[path] = updateNoLabelsConfigMapYAML
	fetcher.rev = "rev2"

	// 2차 Reconcile
	_, err = rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &updated))

	// 사용자 annotations 제거됨
	assert.NotContains(t, updated.Annotations, "release", "removed user annotation 'release' must not persist")

	// 시스템 annotations 유지됨
	assert.NotEmpty(t, updated.Annotations[AnnoOVOwnerFull], "system annotation octovault.it/owner must be preserved")
	assert.NotEmpty(t, updated.Annotations["reconcile.octovault.it/data-hash"], "system annotation data-hash must be preserved")
}

func TestOctoVault_Secret_UserAnnotations_RemovedWhenNotInValues(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신
	// values.yaml에서 metadata.annotations 전체 제거 후 Reconcile 시 이전 사용자 annotations가 제거됨 (시스템 annotations 유지)

	ctx := context.Background()
	const path = "values/secret-remove-annos.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: updateV1SecretYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)

	// 1차 Reconcile: user annotations 있음
	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &sec))
	require.Equal(t, "first", sec.Annotations["release"], "precondition: annotation should exist after first reconcile")

	// values.yaml에서 annotations 완전 제거
	fetcher.files[path] = updateNoLabelsSecretYAML
	fetcher.rev = "rev2"

	// 2차 Reconcile
	_, err = rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &updated))

	// 사용자 annotations 제거됨
	assert.NotContains(t, updated.Annotations, "release", "removed user annotation 'release' must not persist on Secret")

	// 시스템 annotations 유지됨
	assert.NotEmpty(t, updated.Annotations[AnnoOVOwnerFull], "system annotation octovault.it/owner must be preserved on Secret")
	assert.NotEmpty(t, updated.Annotations["reconcile.octovault.it/data-hash"], "system annotation data-hash must be preserved on Secret")
}

func TestOctoVault_Secret_UserLabels_RemovedWhenNotInValues(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 5. 업데이트 - labels/annotations 갱신
	// values.yaml에서 metadata.labels 전체 제거 후 Reconcile 시 이전 사용자 labels가 제거됨 (시스템 labels 유지)

	ctx := context.Background()
	const path = "values/secret-remove-labels.yaml"

	fetcher := &staticFetcher{
		files: map[string][]byte{path: updateV1SecretYAML},
		rev:   "rev1",
	}
	rec, cl, ov := newUpdateMetaReconciler(t, path, fetcher)

	// 1차 Reconcile: user labels 있음
	_, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &sec))
	require.Equal(t, "v1", sec.Labels["version"], "precondition: user label should exist after first reconcile")

	// values.yaml에서 labels 완전 제거
	fetcher.files[path] = updateNoLabelsSecretYAML
	fetcher.rev = "rev2"

	// 2차 Reconcile
	_, err = rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace},
	})
	require.NoError(t, err)

	var updated corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ov.Namespace, Name: "target-resource"}, &updated))

	// 사용자 labels 제거됨
	assert.NotContains(t, updated.Labels, "version", "removed user label 'version' must not persist on Secret")

	// 시스템 labels 유지됨
	assert.Equal(t, "octovault", updated.Labels[LabelManagedBy], "system label must be preserved after user labels removal on Secret")
}
