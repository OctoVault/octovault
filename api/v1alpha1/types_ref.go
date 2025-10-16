package v1alpha1

// NamespacedObjectRef references a namespaced object (e.g. Secret).
type NamespacedObjectRef struct {
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// LocalObjectRef is a reference to a local object, such as a Secret or ConfigMap.
type LocalObjectRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:required
	Name string `json:"name"`
}
