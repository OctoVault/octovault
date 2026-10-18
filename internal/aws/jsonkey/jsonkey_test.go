package jsonkey

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {

	doc := []byte(`{"a":{"b":"str","n":3,"o":{"x":true}}}`)

	got, err := Extract(doc, "a.b")
	require.NoError(t, err)
	require.Equal(t, "str", string(got))

	got, err = Extract(doc, "a.o")
	require.NoError(t, err)
	require.JSONEq(t, `{"x":true}`, string(got))

	got, err = Extract(doc, "a.n")
	require.NoError(t, err)
	require.Equal(t, "3", string(got))

	_, err = Extract(doc, "a.missing")
	require.ErrorContains(t, err, `json key "missing" not found`)

	_, err = Extract(doc, "a.b.c")
	require.ErrorContains(t, err, "non-object")

	_, err = Extract([]byte("not json"), "a")
	require.ErrorContains(t, err, "parse json")

	_, err = Extract(doc, " ")
	require.ErrorContains(t, err, "jsonKey required")
}

// 큰 정수가 float64 를 거치면 자릿수가 깨진다(예: 2^53 초과 ID, 계정 번호).
func TestExtract_KeepsNumberPrecision(t *testing.T) {

	doc := []byte(`{"id":12345678901234567890,"nested":{"n":9007199254740993,"f":1.50}}`)

	got, err := Extract(doc, "id")
	require.NoError(t, err)
	require.Equal(t, "12345678901234567890", string(got))

	got, err = Extract(doc, "nested")
	require.NoError(t, err)
	require.JSONEq(t, `{"n":9007199254740993,"f":1.50}`, string(got))
	// JSONEq 는 1.50 과 1.5 를 같게 보므로 원문 표기는 따로 확인한다.
	require.Contains(t, string(got), "9007199254740993")
	require.Contains(t, string(got), "1.50")

	got, err = Extract(doc, "nested.f")
	require.NoError(t, err)
	require.Equal(t, "1.50", string(got))

	for _, trailing := range []string{`{"a":"b"} trailing`, `{"a":"b"} {"a":"c"}`} {
		_, err = Extract([]byte(trailing), "a")
		require.ErrorContains(t, err, "parse json", trailing)
	}
}
