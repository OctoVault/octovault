package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type countingReader struct {
	client.Reader
	err   error
	calls int
}

func (r *countingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {

	r.calls++

	return r.err
}

func TestGetCredentialSecret(t *testing.T) {

	ctx := context.Background()
	key := types.NamespacedName{Namespace: "ns", Name: "cred"}
	notFound := apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "cred")

	t.Run("cache hit skips the API server", func(t *testing.T) {
		cached, direct := &countingReader{}, &countingReader{}
		assert.NoError(t, getCredentialSecret(ctx, cached, direct, key, &corev1.Secret{}))
		assert.Equal(t, 0, direct.calls)
	})

	t.Run("cache miss falls back to the API server", func(t *testing.T) {
		cached, direct := &countingReader{err: notFound}, &countingReader{}
		assert.NoError(t, getCredentialSecret(ctx, cached, direct, key, &corev1.Secret{}))
		assert.Equal(t, 1, direct.calls)
	})

	t.Run("other cache errors are returned", func(t *testing.T) {
		boom := errors.New("boom")
		cached, direct := &countingReader{err: boom}, &countingReader{}
		assert.ErrorIs(t, getCredentialSecret(ctx, cached, direct, key, &corev1.Secret{}), boom)
		assert.Equal(t, 0, direct.calls)
	})

	t.Run("nil cache uses the API server", func(t *testing.T) {
		direct := &countingReader{}
		assert.NoError(t, getCredentialSecret(ctx, nil, direct, key, &corev1.Secret{}))
		assert.Equal(t, 1, direct.calls)
	})
}
