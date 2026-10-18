package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPositiveIntEnv(t *testing.T) {

	const key = "OCTOVAULT_TEST_POSITIVE_INT"

	t.Setenv(key, "")
	assert.Equal(t, 7, positiveIntEnv(key, 7))

	for _, bad := range []string{"0", "-3", "lots"} {
		t.Setenv(key, bad)
		assert.Equal(t, 7, positiveIntEnv(key, 7), bad)
	}

	t.Setenv(key, " 4096 ")
	assert.Equal(t, 4096, positiveIntEnv(key, 7))
}
