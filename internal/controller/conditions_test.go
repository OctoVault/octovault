package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUpsertReadyCondition_DoesNotMutateInput(t *testing.T) {

	prev := []metav1.Condition{{Type: CondReady, Status: metav1.ConditionTrue, Reason: "Synced", Message: "ok"}}

	next := upsertReadyCondition(prev, metav1.ConditionFalse, "FetchFailed", "boom")

	assert.Equal(t, "Synced", prev[0].Reason, "input must not change")
	assert.Equal(t, "FetchFailed", next[0].Reason)
	assert.False(t, readyConditionEqual(prev, next))
}

func TestUpsertReadyCondition_KeepsTransitionTimeWhenUnchanged(t *testing.T) {

	then := metav1.NewTime(metav1.Now().Add(-3600e9))
	prev := []metav1.Condition{{Type: CondReady, Status: metav1.ConditionTrue, Reason: "Synced", Message: "ok", LastTransitionTime: then}}

	next := upsertReadyCondition(prev, metav1.ConditionTrue, "Synced", "ok")

	assert.Equal(t, then, next[0].LastTransitionTime)
}

func TestReadyConditionEqual(t *testing.T) {

	ready := metav1.Condition{Type: CondReady, Status: metav1.ConditionTrue, Reason: "Synced", Message: "ok"}
	other := metav1.Condition{Type: "Other", Status: metav1.ConditionTrue}

	assert.True(t, readyConditionEqual(nil, nil))
	assert.True(t, readyConditionEqual([]metav1.Condition{other}, nil), "no Ready on either side")
	assert.False(t, readyConditionEqual([]metav1.Condition{ready}, nil))
	assert.True(t, readyConditionEqual([]metav1.Condition{ready}, []metav1.Condition{other, ready}))

	changed := ready
	changed.Message = "different"
	assert.False(t, readyConditionEqual([]metav1.Condition{ready}, []metav1.Condition{changed}))
}
