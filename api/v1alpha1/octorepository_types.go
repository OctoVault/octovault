/*
Copyright 2025 octovault.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const (
	OctoRepoPhasePending string = "Pending"
	OctoRepoPhaseSynced  string = "Synced"
	OctoRepoPhaseFailed  string = "Failed"
)

// OctoRepositorySpec defines the desired state of OctoRepository
type OctoRepositorySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// Organization is the GitHub organization or user that owns the repository.
	// +kubebuilder:validation:Pattern=^github\.com\/[A-Za-z0-9_.-]+$
	Organization string `json:"organization"`

	// CredentialsRef is a reference to the Secret Object which stores credentials to GitHub repository.
	// +kubebuilder:validation:Required
	CredentialsRef NamespacedObjectRef `json:"credentialsRef"`
}

// OctoRepositoryStatus defines the observed state of OctoRepository.
type OctoRepositoryStatus struct {

	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Phase            string             `json:"phase,omitempty"` // Pending | Synced | Failed
	Message          string             `json:"message,omitempty"`
	Conditions       []metav1.Condition `json:"conditions,omitempty"`
	SyncedSecretName string             `json:"syncedSecretName,omitempty"`
	LastCheckedTime  *metav1.Time       `json:"lastCheckedTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=orepo;or
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Owner",type=string,JSONPath=`.spec.organization`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.credentialsRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// OctoRepository is the connection for the GItHub repository.
type OctoRepository struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of OctoRepository
	// +required
	Spec OctoRepositorySpec `json:"spec"`

	// status defines the observed state of OctoRepository
	// +optional
	Status OctoRepositoryStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// OctoRepositoryList contains a list of OctoRepository
type OctoRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctoRepository `json:"items"`
}

func init() {

	SchemeBuilder.Register(&OctoRepository{}, &OctoRepositoryList{})
}
