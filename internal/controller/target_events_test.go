package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestTargetChanged(t *testing.T) {

	ctrlTrue := true
	base := func() *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Labels:          map[string]string{LabelManagedBy: "octovault", "team": "a"},
				Annotations:     map[string]string{"reconcile.octovault.it/data-hash": "h1"},
				OwnerReferences: []metav1.OwnerReference{{UID: types.UID("ov"), Controller: &ctrlTrue}},
			},
			Data: map[string]string{"k": "v"},
		}
	}

	foreignLabel := base()
	foreignLabel.Labels["injected-by-webhook"] = "yes"
	assert.False(t, targetChanged(base(), foreignLabel), "labels the controller does not own must not trigger a reconcile")

	foreignAnno := base()
	foreignAnno.Annotations["policy.example.com/checked"] = "passed"
	assert.False(t, targetChanged(base(), foreignAnno))

	sysLabel := base()
	sysLabel.Labels[LabelManagedBy] = "someone-else"
	assert.True(t, targetChanged(base(), sysLabel))

	sysAnno := base()
	sysAnno.Annotations["reconcile.octovault.it/data-hash"] = "h2"
	assert.True(t, targetChanged(base(), sysAnno))

	data := base()
	data.Data["k"] = "edited"
	assert.True(t, targetChanged(base(), data))

	orphaned := base()
	orphaned.OwnerReferences = nil
	assert.True(t, targetChanged(base(), orphaned))
}

// Secret 은 메타데이터만 watch 한다. system 라벨을 바꾸거나 managed-by 를 떼면 바로 반응해야 한다.
// (managed-by 를 떼면 라벨로 범위를 좁힌 캐시에서는 삭제 이벤트로도 보이는데, 삭제는 항상 반응한다.)
func TestTargetChanged_SecretMetadata(t *testing.T) {

	ctrlTrue := true
	base := func() *metav1.PartialObjectMetadata {
		return &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Labels:          map[string]string{LabelManagedBy: "octovault", LabelOVOwnerName: "app"},
				OwnerReferences: []metav1.OwnerReference{{UID: types.UID("ov"), Controller: &ctrlTrue}},
			},
		}
	}

	editedOwner := base()
	editedOwner.Labels[LabelOVOwnerName] = "someone-else"
	assert.True(t, targetChanged(base(), editedOwner))

	unmanaged := base()
	delete(unmanaged.Labels, LabelManagedBy)
	assert.True(t, targetChanged(base(), unmanaged))

	foreign := base()
	foreign.Labels["injected"] = "yes"
	assert.False(t, targetChanged(base(), foreign))

	assert.True(t, targetEventFilter[*metav1.PartialObjectMetadata]().Delete(event.TypedDeleteEvent[*metav1.PartialObjectMetadata]{Object: base()}),
		"deletes (including dropping out of the label-scoped cache) always reconcile")
}
