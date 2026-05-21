package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// __analysis/2_METADATA.md > Red Task List > 2. mergeLabels / mergeAnnotations 순수 함수

func TestMergeLabels(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 2. mergeLabels / mergeAnnotations 순수 함수

	t.Run("user map에 있는 키가 merged map에 포함됨", func(t *testing.T) {
		system := map[string]string{"app.kubernetes.io/managed-by": "octovault"}
		user := map[string]string{"team": "backend", "env": "prod"}

		got := mergeLabels(system, user)

		assert.Equal(t, "backend", got["team"])
		assert.Equal(t, "prod", got["env"])
	})

	t.Run("system map의 키가 user map의 동일 키를 덮어씀 (system 우선)", func(t *testing.T) {
		system := map[string]string{"app.kubernetes.io/managed-by": "octovault"}
		user := map[string]string{"app.kubernetes.io/managed-by": "attacker"}

		got := mergeLabels(system, user)

		assert.Equal(t, "octovault", got["app.kubernetes.io/managed-by"])
	})

	t.Run("user map이 nil이어도 system map만 반환되어 panic 없음", func(t *testing.T) {
		system := map[string]string{"app.kubernetes.io/managed-by": "octovault"}

		require.NotPanics(t, func() {
			got := mergeLabels(system, nil)
			assert.Equal(t, "octovault", got["app.kubernetes.io/managed-by"])
		})
	})

	t.Run("system map이 nil이어도 user map만 반환됨", func(t *testing.T) {
		user := map[string]string{"team": "backend"}

		require.NotPanics(t, func() {
			got := mergeLabels(nil, user)
			assert.Equal(t, "backend", got["team"])
		})
	})

	t.Run("system map과 user map 모두 nil이어도 panic 없이 빈 map 반환됨", func(t *testing.T) {
		require.NotPanics(t, func() {
			got := mergeLabels(nil, nil)
			assert.NotNil(t, got)
		})
	})

	t.Run("octovault.it/ prefix 키는 user map에서 제거됨", func(t *testing.T) {
		system := map[string]string{"octovault.it/owner-ns": "default"}
		user := map[string]string{
			"octovault.it/owner-ns": "injected",
			"safe-key":              "safe-val",
		}

		got := mergeLabels(system, user)

		assert.Equal(t, "default", got["octovault.it/owner-ns"])
		assert.Equal(t, "safe-val", got["safe-key"])
	})

	t.Run("reconcile.octovault.it/ prefix 키는 user map에서 제거됨", func(t *testing.T) {
		system := map[string]string{"reconcile.octovault.it/revision": "abc123"}
		user := map[string]string{
			"reconcile.octovault.it/revision": "tampered",
			"my-label":                        "my-value",
		}

		got := mergeLabels(system, user)

		assert.Equal(t, "abc123", got["reconcile.octovault.it/revision"])
		assert.Equal(t, "my-value", got["my-label"])
	})

	t.Run("app.kubernetes.io/ prefix 키는 user map에서 제거됨", func(t *testing.T) {
		system := map[string]string{"app.kubernetes.io/managed-by": "octovault"}
		user := map[string]string{
			"app.kubernetes.io/managed-by": "evil",
			"custom-label":                 "ok",
		}

		got := mergeLabels(system, user)

		assert.Equal(t, "octovault", got["app.kubernetes.io/managed-by"])
		assert.Equal(t, "ok", got["custom-label"])
	})
}

func TestMergeAnnotations(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 2. mergeLabels / mergeAnnotations 순수 함수

	t.Run("user annotation이 merged map에 포함됨", func(t *testing.T) {
		system := map[string]string{"octovault.it/owner": "default/my-ov"}
		user := map[string]string{"foo": "bar", "team": "backend"}

		got := mergeAnnotations(system, user)

		assert.Equal(t, "bar", got["foo"])
		assert.Equal(t, "backend", got["team"])
	})

	t.Run("system annotation이 user annotation의 동일 키를 덮어씀 (system 우선)", func(t *testing.T) {
		system := map[string]string{"octovault.it/owner": "default/my-ov"}
		user := map[string]string{"octovault.it/owner": "injected"}

		got := mergeAnnotations(system, user)

		assert.Equal(t, "default/my-ov", got["octovault.it/owner"])
	})

	t.Run("user map이 nil이어도 system annotation만 반환되어 panic 없음", func(t *testing.T) {
		system := map[string]string{"reconcile.octovault.it/data-hash": "sha256abc"}

		require.NotPanics(t, func() {
			got := mergeAnnotations(system, nil)
			assert.Equal(t, "sha256abc", got["reconcile.octovault.it/data-hash"])
		})
	})

	t.Run("system map이 nil이어도 user annotation만 반환됨", func(t *testing.T) {
		user := map[string]string{"foo": "bar"}

		require.NotPanics(t, func() {
			got := mergeAnnotations(nil, user)
			assert.Equal(t, "bar", got["foo"])
		})
	})

	t.Run("octovault.it/ prefix annotation 키는 user map에서 무시됨", func(t *testing.T) {
		system := map[string]string{"octovault.it/owner": "default/my-ov"}
		user := map[string]string{
			"octovault.it/owner": "evil-override",
			"safe-anno":          "safe-value",
		}

		got := mergeAnnotations(system, user)

		assert.Equal(t, "default/my-ov", got["octovault.it/owner"])
		assert.Equal(t, "safe-value", got["safe-anno"])
	})

	t.Run("reconcile.octovault.it/ prefix annotation 키는 user map에서 무시됨", func(t *testing.T) {
		system := map[string]string{"reconcile.octovault.it/data-hash": "realHash"}
		user := map[string]string{
			"reconcile.octovault.it/data-hash": "fakeHash",
			"custom-anno":                      "val",
		}

		got := mergeAnnotations(system, user)

		assert.Equal(t, "realHash", got["reconcile.octovault.it/data-hash"])
		assert.Equal(t, "val", got["custom-anno"])
	})

	t.Run("annotation 값이 빈 문자열인 user 항목도 merged map에 포함됨", func(t *testing.T) {
		system := map[string]string{}
		user := map[string]string{"empty-val": ""}

		got := mergeAnnotations(system, user)

		val, ok := got["empty-val"]
		assert.True(t, ok)
		assert.Equal(t, "", val)
	})
}
