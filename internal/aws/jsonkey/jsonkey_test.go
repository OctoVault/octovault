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
