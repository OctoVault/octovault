package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// upsertReadyCondition Ready condition 을 넣거나 갱신한 새 슬라이스를 반환한다.
//
// 입력 슬라이스는 건드리지 않는다. 제자리에서 고치면 호출자가 들고 있는 이전 상태까지
// 바뀌어, 이전/다음 상태를 비교하는 statusEqual 류가 변경을 감지하지 못한다.
// LastTransitionTime 은 Status, Reason, Message 중 하나라도 바뀔 때만 갱신한다.
func upsertReadyCondition(conds []metav1.Condition, status metav1.ConditionStatus, reason, msg string) []metav1.Condition {

	out := append([]metav1.Condition(nil), conds...)
	now := metav1.Now()
	for i := range out {
		if out[i].Type != CondReady {

			continue
		}

		if out[i].Status != status || out[i].Reason != reason || out[i].Message != msg {

			out[i].Status = status
			out[i].Reason = reason
			out[i].Message = msg
			out[i].LastTransitionTime = now
		}

		return out
	}

	return append(out, metav1.Condition{
		Type:               CondReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: now,
	})
}

// readyConditionEqual 두 condition 목록의 Ready 가 Status, Reason, Message 기준으로 같은지 본다.
func readyConditionEqual(a, b []metav1.Condition) bool {

	ar := meta.FindStatusCondition(a, CondReady)
	br := meta.FindStatusCondition(b, CondReady)
	if ar == nil || br == nil {

		return ar == br
	}

	return ar.Status == br.Status && ar.Reason == br.Reason && ar.Message == br.Message
}
