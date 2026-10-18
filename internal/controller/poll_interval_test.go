package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

func TestPollIntervalOf(t *testing.T) {

	of := func(v string) time.Duration {
		return pollIntervalOf(&octovaultv1alpha1.OctoVault{Spec: octovaultv1alpha1.OctoVaultSpec{PollInterval: v}})
	}

	assert.Equal(t, DefaultPollInterval, of(""))
	assert.Equal(t, 90*time.Second, of("90s"))
	assert.Equal(t, 90*time.Minute, of("1h30m"))
	assert.Equal(t, MinPollInterval, of("5s"), "values below the minimum are raised")
	assert.Equal(t, MinPollInterval, of("0s"), "0s is below the minimum, not unset")
	assert.Equal(t, DefaultPollInterval, of("garbage"))
}
