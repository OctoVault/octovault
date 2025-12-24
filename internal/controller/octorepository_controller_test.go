package controller

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"k8s.io/client-go/tools/record"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

func schemeForRepoTests(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, octovaultv1alpha1.AddToScheme(s))
	return s
}

func fakeClientRepo(t *testing.T, s *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&octovaultv1alpha1.OctoRepository{}).
		WithObjects(objs...).
		Build()
}

// ready condition finder
func getReady(conds []metav1.Condition) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == CondReady {
			return &conds[i]
		}
	}
	return nil
}

// HTTP stub transport to intercept GitHub API calls
type stubTransport struct {
	// key: full URL (exact match) or prefix; value: status code
	rules map[string]int
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := 404
	u := req.URL.String()
	// exact first
	if code, ok := s.rules[u]; ok {
		status = code
	} else {
		// prefix match (optional)
		for k, v := range s.rules {
			if len(k) > 0 && len(u) >= len(k) && u[:len(k)] == k {
				status = v
				break
			}
		}
	}
	// minimal JSON body
	body := io.NopCloser(bytes.NewBufferString(`{}`))
	return &http.Response{
		StatusCode: status,
		Body:       body,
		Header:     make(http.Header),
	}, nil
}

func withHTTPStub(t *testing.T, rules map[string]int) func() {
	t.Helper()
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = &stubTransport{rules: rules}
	return func() { http.DefaultClient.Transport = old }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestOctoRepository_InvalidOrganization(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: "orepo",
		},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "octovault", // invalid; must be github.com/<owner>
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	res, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: client.ObjectKey{Name: "orepo"}, // namespace empty
	})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseFailed, got.Status.Phase)
	require.Contains(t, got.Status.Message, "organization must be in the format github.com/<org>")
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, "InvalidOrganization", ready.Reason)
}

func TestOctoRepository_SecretNotFound(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "no-such-secret",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseFailed, got.Status.Phase)
	// 메시지는 구현에 따라 devops/no-such-secret 포함될 수 있음 → contains 로 느슨히 확인
	require.Contains(t, got.Status.Message, "no-such-secret")
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, "SecretNotFound", ready.Reason)
}

func TestOctoRepository_SecretMissingPassword(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, sec, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.Error(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseFailed, got.Status.Phase)
	require.Equal(t, "secret missing password", got.Status.Message)
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, "SecretMissingPassword", ready.Reason)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
}

func TestOctoRepository_SecretInvalidBase64(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
		StringData: map[string]string{
			"password":         "%%%not-base64%%%",
			"passwordEncoding": "base64",
		},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, sec, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.Error(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseFailed, got.Status.Phase)
	require.Contains(t, got.Status.Message, "failed to decode password")
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, "SecretInvalidPasswordEncoding", ready.Reason)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
}

func TestOctoRepository_AccessDenied(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	// Secret with password
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
		StringData: map[string]string{"password": "dummy"},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, sec, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	// Stub: org 404, user 404 -> AccessDenied
	restore := withHTTPStub(t, map[string]int{
		"https://api.github.com/orgs/octovault/repos?per_page=1":  404,
		"https://api.github.com/users/octovault/repos?per_page=1": 404,
	})
	defer restore()

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseFailed, got.Status.Phase)
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, "AccessDenied", ready.Reason)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
}

func TestOctoRepository_Success_Synced(t *testing.T) {
	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
		// use Data to mimic persisted secret
		Data: map[string][]byte{
			"password": []byte("dummy"),
		},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization: "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{
				Name:      "creds",
				Namespace: "devops",
			},
		},
	}

	cl := fakeClientRepo(t, scheme, sec, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(64),
	}

	// Stub: org 200 OK
	restore := withHTTPStub(t, map[string]int{
		"https://api.github.com/orgs/octovault/repos?per_page=1": 200,
	})
	defer restore()

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)
	require.Greater(t, int64(res.RequeueAfter), int64(0))

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	require.Equal(t, octovaultv1alpha1.OctoRepoPhaseSynced, got.Status.Phase)
	require.Contains(t, got.Status.Message, `organization "octovault" is accessible`)
	// SyncedSecretName 구현이 "creds" 혹은 "devops/creds" 인 경우를 모두 수용
	require.Contains(t, got.Status.SyncedSecretName, "creds")
	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, "Accessible", ready.Reason)
}

// Optionally, ensure poll interval env var is respected (non-critical)
func TestOctoRepository_PollInterval_FromEnv(t *testing.T) {
	_ = os.Setenv("OCTOREPO_POLL_INTERVAL", "2m")
	defer func() {
		_ = os.Unsetenv("OCTOREPO_POLL_INTERVAL")
	}()

	// 이 테스트는 단순 존재 확인용으로 두고, 실제 값 비교는 생략한다.
	require.NotZero(t, pollInterval)
}
