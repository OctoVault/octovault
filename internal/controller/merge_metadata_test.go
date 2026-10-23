package controller

import (
	"context"
	"strings"
	"testing"

	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

	t.Run("annotation 값이 빈 문자열인 user 항목도 merged map에 포함됨", func(t *testing.T) {
		system := map[string]string{}
		user := map[string]string{"empty-val": ""}

		got := mergeAnnotations(system, user)

		val, ok := got["empty-val"]
		assert.True(t, ok)
		assert.Equal(t, "", val)
	})
}

func TestMergeMap_DropsReservedUserKeys(t *testing.T) {

	user := map[string]string{
		"octovault.it/retained-from":       "ns/other",
		"octovault.it/repository":          "true",
		"reconcile.octovault.it/data-hash": "forged",
		"team":                             "a",
		"example.com/octovault.it":         "ok",
		"notoctovault.it/key":              "ok",
	}

	got := mergeMap(map[string]string{"reconcile.octovault.it/data-hash": "real"}, user)

	assert.Equal(t, map[string]string{
		"reconcile.octovault.it/data-hash": "real",
		"team":                             "a",
		"example.com/octovault.it":         "ok",
		"notoctovault.it/key":              "ok",
	}, got)
}

// values.yaml 의 octovault.it 키는 무시하되, 한 번은 알려야 한다.
func TestOctoVault_ReservedKeysInValues_AreReportedOnce(t *testing.T) {

	ctx := context.Background()
	const path = "values/reserved.yaml"
	values := []byte(`
metadata:
  type: ConfigMap
  labels:
    octovault.it/repository: "true"
  annotations:
    octovault.it/retained-from: other/ov
spec:
  data:
    - key: foo
      value: bar
`)

	rec, _, ov := newUpdateMetaReconciler(t, path, &staticFetcher{files: map[string][]byte{path: values}, rev: "rev1"})
	recorder := rec.Recorder.(*record.FakeRecorder)
	req := reconcile.Request{NamespacedName: client.ObjectKey{Name: ov.Name, Namespace: ov.Namespace}}

	warnings := func() int {
		n := 0
		for len(recorder.Events) > 0 {
			if e := <-recorder.Events; strings.HasPrefix(e, "Warning ReservedKeysIgnored") {

				n++
				assert.Contains(t, e, "octovault.it/repository,octovault.it/retained-from")
			}
		}

		return n
	}

	for range 3 {
		_, err := rec.Reconcile(ctx, req)
		require.NoError(t, err)
	}

	assert.Equal(t, 1, warnings(), "reported once, not on every poll")
}
