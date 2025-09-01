package controller

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// --- 테스트용 고정 Fetcher ----------------------------------------------------

type staticFetcher struct {
	files map[string][]byte // key: path (e.g. "test/resources/configmap-values.yaml")
	rev   string
}

func (f *staticFetcher) Fetch(ctx context.Context, org, repo, path, ref, token string) ([]byte, []byte, string, error) {
	if b, ok := f.files[path]; ok {
		return b, nil, f.rev, nil
	}
	// not found → 컨트롤러에서 rev==""면 sha256 폴백 사용
	return nil, nil, "", nil
}

// --- 샘플 values.yaml ---------------------------------------------------------

var sampleConfigMapYAML = []byte(`
metadata:
  type: ConfigMap
spec:
  data:
    - key: foo
      value: bar
    - key: hello
      value: world
`)

var sampleSecretYAML = []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: token
      type: Text
      value: s3cr3t
    - key: another
      value: xyz
`)

// ------------------------------------------------------------------------------

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, octovaultv1alpha1.AddToScheme(s))
	return s
}

func newFakeClient(t *testing.T, scheme *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&octovaultv1alpha1.OctoVault{}).
		WithObjects(objs...).
		Build()
}

func TestOctoVault_Reconcile_ConfigMap_Success(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	ns := "devops"
	orepoName := "octorepository-sample"
	credName := "octorepository-sample-credentials"

	// 준비: 자격증명 Secret (네임스페이스 리소스)
	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      credName,
			Namespace: ns,
		},
		StringData: map[string]string{
			"password": "dummy",
		},
	}

	// CredentialsRef 는 NamespacedObjectRef 로 비춰짐(네임스페이스 포함)
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: orepoName,
		},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/dev-whoan",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      credName,
				Namespace: ns,
			},
		},
	}

	// OctoVault: 네임스페이스 리소스
	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "configmap-test",
			Namespace: ns,
		},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: orepoName},
			Repository:        "dev-whoan/octovault",
			Path:              "test/resources/configmap-values.yaml",
			TargetName:        "my-configmap",
			// PollInterval 비우면 1m 기본
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git: &staticFetcher{
			files: map[string][]byte{
				"test/resources/configmap-values.yaml": sampleConfigMapYAML,
			},
			rev: "cafebabe1234567",
		},
	}

	// 실행
	res, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ns},
	})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	// 결과 확인: ConfigMap 생성/내용
	var cm corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: "my-configmap"}, &cm))
	require.Equal(t, "bar", cm.Data["foo"])
	require.Equal(t, "world", cm.Data["hello"])

	// 상태 확인: Phase, Type, Rev, Hash
	var got octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ns}, &got))
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, got.Status.Phase)
	require.Equal(t, string(octovaultv1alpha1.OutputConfigMap), got.Status.ResolvedType)
	require.NotEmpty(t, got.Status.AppliedDataHash)
	require.NotEmpty(t, got.Status.ObservedRevision) // 커밋 SHA or sha256:xxxx
	require.WithinDuration(t, time.Now(), got.Status.LastSyncedTime.Time, 5*time.Second)
}

func TestOctoVault_Reconcile_Secret_Success(t *testing.T) {
	ctx := context.Background()
	scheme := newScheme(t)

	ns := "devops"
	orepoName := "octorepository-sample"
	credName := "octorepository-sample-credentials"

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      credName,
			Namespace: ns,
		},
		StringData: map[string]string{
			"password": "dummy",
		},
	}

	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: orepoName,
		},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/dev-whoan",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      credName,
				Namespace: ns,
			},
		},
	}

	ov := &octovaultv1alpha1.OctoVault{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-test",
			Namespace: ns,
		},
		Spec: octovaultv1alpha1.OctoVaultSpec{
			OctoRepositoryRef: octovaultv1alpha1.LocalObjectRef{Name: orepoName},
			Repository:        "dev-whoan/octovault",
			Path:              "test/resources/secret-values.yaml",
			TargetName:        "my-secret",
		},
	}

	cl := newFakeClient(t, scheme, cred, orepo, ov)
	rec := &OctoVaultReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
		Git: &staticFetcher{
			files: map[string][]byte{
				"test/resources/secret-values.yaml": sampleSecretYAML,
			},
			rev: "deadbeefcafebabe",
		},
	}

	// 실행
	res, err := rec.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ns},
	})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	// 결과 확인: Secret 생성/내용
	var sec corev1.Secret
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: "my-secret"}, &sec))
	require.Equal(t, corev1.SecretTypeOpaque, sec.Type)
	require.Equal(t, []byte("s3cr3t"), sec.Data["token"])
	require.Equal(t, []byte("xyz"), sec.Data["another"])

	// 상태 확인
	var got octovaultv1alpha1.OctoVault
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: ov.Name, Namespace: ns}, &got))
	require.Equal(t, octovaultv1alpha1.OVPhaseSynced, got.Status.Phase)
	require.Equal(t, string(octovaultv1alpha1.OutputSecret), got.Status.ResolvedType)
	require.NotEmpty(t, got.Status.AppliedDataHash)
	require.NotEmpty(t, got.Status.ObservedRevision)
}
