package controller

import (
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// 대상 리소스 watch 가 반응할 변경만 고른다.
//
// 모든 변경에 반응하면, values.yaml 에 없는 라벨/어노테이션을 붙이는 다른 주체(mutating webhook,
// Kyverno 등)와 "컨트롤러가 지움 → 상대가 다시 붙임 → watch 이벤트 → 다시 지움" 루프가 큐 속도로
// 돈다. 그래서 컨트롤러가 책임지는 부분이 바뀐 경우에만 reconcile 한다. 그 밖의 메타데이터 변경은
// 이전처럼 poll 주기에 맞춘다. 삭제와 생성은 항상 반응한다.

// systemLabelKeys / systemAnnotationKeys 컨트롤러가 직접 관리하는 키.
var (
	systemLabelKeys = []string{
		LabelManagedBy, LabelOVOwnerNS, LabelOVOwnerName,
		"reconcile.octovault.it/managed-by", "reconcile.octovault.it/owner", "reconcile.octovault.it/revision",
	}
	systemAnnotationKeys = []string{"reconcile.octovault.it/data-hash", AnnoOVOwnerFull}
)

func targetEventFilter[T client.Object]() predicate.TypedFuncs[T] {
	return predicate.TypedFuncs[T]{
		UpdateFunc: func(e event.TypedUpdateEvent[T]) bool {
			return targetChanged(e.ObjectOld, e.ObjectNew)
		},
	}
}

// targetChanged 컨트롤러가 되돌려야 하는 변경인지 본다.
func targetChanged(oldObj, newObj client.Object) bool {
	if controllerUID(oldObj) != controllerUID(newObj) {

		return true
	}

	if !sameKeys(oldObj.GetLabels(), newObj.GetLabels(), systemLabelKeys) ||
		!sameKeys(oldObj.GetAnnotations(), newObj.GetAnnotations(), systemAnnotationKeys) {

		return true
	}

	// Secret 은 메타데이터만 watch 하므로 데이터 변경은 여기서 보이지 않는다(poll 주기에 맞춘다).
	oldCM, okOld := oldObj.(*corev1.ConfigMap)
	newCM, okNew := newObj.(*corev1.ConfigMap)
	if okOld && okNew {

		return !reflect.DeepEqual(oldCM.Data, newCM.Data) || !reflect.DeepEqual(oldCM.BinaryData, newCM.BinaryData)
	}

	return false
}

func controllerUID(obj client.Object) string {
	if ref := metav1.GetControllerOf(obj); ref != nil {

		return string(ref.UID)
	}

	return ""
}

func sameKeys(a, b map[string]string, keys []string) bool {
	for _, k := range keys {
		if a[k] != b[k] {

			return false
		}
	}

	return true
}
