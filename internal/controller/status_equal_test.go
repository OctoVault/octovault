package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

func TestStatusEqualOV_ExternalRefsNilAndEmptyStagesAreEqual(t *testing.T) {

	ref := func(stages []string) octovaultv1alpha1.OctoVaultStatus {
		return octovaultv1alpha1.OctoVaultStatus{
			ExternalRefs: []octovaultv1alpha1.ExternalRefStatus{{Provider: "AwsSecretsManager", Name: "s", VersionID: "1", VersionStages: stages}},
		}
	}

	assert.True(t, statusEqualOV(ref(nil), ref([]string{})))
	assert.False(t, statusEqualOV(ref([]string{"AWSCURRENT"}), ref([]string{"AWSPREVIOUS"})))
}

func TestSortedCopy(t *testing.T) {

	in := []string{"AWSPREVIOUS", "AWSCURRENT"}
	assert.Equal(t, []string{"AWSCURRENT", "AWSPREVIOUS"}, sortedCopy(in))
	assert.Equal(t, []string{"AWSPREVIOUS", "AWSCURRENT"}, in, "the input is not modified")
	assert.Nil(t, sortedCopy(nil))
}
