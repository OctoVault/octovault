package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
	ghclient "github.com/octovault/octovault/internal/github"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// public 저장소로 제한된 토큰은 Ready 로 두되, 이유와 경고 이벤트로 알려야 한다.

type fixedChecker struct {
	result ghclient.AccessResult
}

func (c fixedChecker) CheckAccess(ctx context.Context, org, pwd string) (ghclient.AccessResult, error) {
	return c.result, nil
}

func TestOctoRepository_PublicOnlyToken_IsFlagged(t *testing.T) {

	ctx := context.Background()
	scheme := schemeForRepoTests(t)

	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "devops"},
		Data:       map[string][]byte{"password": []byte("dummy")},
	}
	orepo := &octovaultv1alpha1.OctoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: "orepo"},
		Spec: octovaultv1alpha1.OctoRepositorySpec{
			Organization:   "github.com/octovault",
			CredentialsRef: octovaultv1alpha1.NamespacedObjectRef{Name: "creds", Namespace: "devops"},
		},
	}

	recorder := record.NewFakeRecorder(64)
	cl := fakeClientRepo(t, scheme, sec, orepo)
	r := &OctoRepositoryReconciler{
		Client:   cl,
		Scheme:   scheme,
		Recorder: recorder,
		Checker:  fixedChecker{result: ghclient.AccessResult{LimitedToPublic: true}},
	}

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "orepo"}})
	require.NoError(t, err)

	var got octovaultv1alpha1.OctoRepository
	require.NoError(t, cl.Get(ctx, client.ObjectKey{Name: "orepo"}, &got))
	assert.Equal(t, octovaultv1alpha1.OctoRepoPhaseSynced, got.Status.Phase)

	ready := getReady(got.Status.Conditions)
	require.NotNil(t, ready)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, "AccessibleLimitedToPublic", ready.Reason)
	assert.Contains(t, got.Status.Message, `lacks the "repo" scope`)

	warned := false
	for len(recorder.Events) > 0 {
		if e := <-recorder.Events; strings.HasPrefix(e, "Warning AccessibleLimitedToPublic") {

			warned = true
		}
	}
	assert.True(t, warned, "a Warning event must be emitted")
}
