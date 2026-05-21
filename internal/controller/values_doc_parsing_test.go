package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// __analysis/2_METADATA.md > Red Task List > 1. valuesDoc 파싱 - Annotations/Labels 필드 인식

func TestValuesDocParsing_AnnotationsAndLabels(t *testing.T) {
	// __analysis/2_METADATA.md > Red Task List > 1. valuesDoc 파싱 - Annotations/Labels 필드 인식

	t.Run("metadata.annotations가 있는 values.yaml 파싱 시 Annotations map이 채워짐", func(t *testing.T) {
		input := []byte(`
metadata:
  type: Secret
  annotations:
    foo: bar
    team: backend
spec:
  data:
    - key: token
      value: s3cr3t
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		require.Equal(t, "bar", doc.Metadata.Annotations["foo"])
		require.Equal(t, "backend", doc.Metadata.Annotations["team"])
	})

	t.Run("metadata.labels가 있는 values.yaml 파싱 시 Labels map이 채워짐", func(t *testing.T) {
		input := []byte(`
metadata:
  type: ConfigMap
  labels:
    john: doe
    env: production
spec:
  data:
    - key: setting
      value: val
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		require.Equal(t, "doe", doc.Metadata.Labels["john"])
		require.Equal(t, "production", doc.Metadata.Labels["env"])
	})

	t.Run("metadata.annotations와 metadata.labels가 모두 있을 때 둘 다 채워짐", func(t *testing.T) {
		input := []byte(`
metadata:
  type: Secret
  annotations:
    foo: bar
  labels:
    john: doe
spec:
  data:
    - key: x
      value: y
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		require.Equal(t, "bar", doc.Metadata.Annotations["foo"])
		require.Equal(t, "doe", doc.Metadata.Labels["john"])
	})

	t.Run("metadata.annotations 필드가 없어도 파싱 오류 없이 nil map으로 처리됨", func(t *testing.T) {
		input := []byte(`
metadata:
  type: ConfigMap
spec:
  data:
    - key: k
      value: v
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		require.Nil(t, doc.Metadata.Annotations)
	})

	t.Run("metadata.labels 필드가 없어도 파싱 오류 없이 nil map으로 처리됨", func(t *testing.T) {
		input := []byte(`
metadata:
  type: Secret
spec:
  data:
    - key: k
      value: v
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		require.Nil(t, doc.Metadata.Labels)
	})

	t.Run("metadata.annotations와 metadata.labels가 모두 없어도 파싱 오류 없음", func(t *testing.T) {
		input := []byte(`
metadata:
  type: ConfigMap
spec:
  data: []
`)
		var doc valuesDoc
		err := yaml.Unmarshal(input, &doc)

		require.NoError(t, err)
		require.Nil(t, doc.Metadata.Annotations)
		require.Nil(t, doc.Metadata.Labels)
	})

	t.Run("annotations 값이 빈 문자열인 경우 허용됨", func(t *testing.T) {
		input := []byte(`
metadata:
  type: ConfigMap
  annotations:
    empty-val: ""
spec:
  data: []
`)
		var doc valuesDoc
		require.NoError(t, yaml.Unmarshal(input, &doc))

		val, ok := doc.Metadata.Annotations["empty-val"]
		require.True(t, ok)
		require.Equal(t, "", val)
	})
}
