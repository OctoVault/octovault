package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPositiveIntEnv(t *testing.T) {

	const key = "OCTOVAULT_TEST_POSITIVE_INT"

	t.Setenv(key, "")
	n, ok := positiveIntEnv(key, 7)
	assert.Equal(t, 7, n)
	assert.True(t, ok, "unset is not an error")

	for _, bad := range []string{"0", "-3", "lots", "2e+06"} {
		t.Setenv(key, bad)
		n, ok := positiveIntEnv(key, 7)
		assert.Equal(t, 7, n, bad)
		assert.False(t, ok, "%q must be reported", bad)
	}

	t.Setenv(key, " 4096 ")
	n, ok = positiveIntEnv(key, 7)
	assert.Equal(t, 4096, n)
	assert.True(t, ok)
}
