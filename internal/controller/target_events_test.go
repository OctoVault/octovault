package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
