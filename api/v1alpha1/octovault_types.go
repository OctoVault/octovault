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
	OVPhasePending string = "Pending"
	OVPhaseSynced  string = "Synced"
	OVPhaseFailed  string = "Failed"
)

type OutputType string

const (
	OutputConfigMap OutputType = "ConfigMap"
	OutputSecret    OutputType = "Secret"
)

// ExternalRefStatus 외부 소스(AWS SM 등)의 버전/스테이지 정보를 표시
type ExternalRefStatus struct {
	// Provider 예: "AwsSecretsManager"
	// +optional
	Provider string `json:"provider,omitempty"`

	// Name 외부 시크릿 식별자
	// +optional
	Name string `json:"name,omitempty"`

	// VersionID 현재 사용된 버전
	// +optional
	VersionID string `json:"versionID,omitempty"`

	// VersionStages 예) ["AWSCURRENT"]
	// +optional
	VersionStages []string `json:"versionStages,omitempty"`

	// Key OctoVault values.yaml의 data.key (어떤 키가 이 외부 ref를 사용했는지)
	// +optional
	Key string `json:"key,omitempty"`
}

// OctoVaultSpec defines the desired state of OctoVault
type OctoVaultSpec struct {
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// GitHub 자격 증명 소스 (OctoRepository)
	// +kubebuilder:validation:Required
	OctoRepositoryRef LocalObjectRef `json:"octoRepositoryRef"`

	// 저장소 이름: "org/repo" 사용
	// +kubebuilder:validation:Pattern=^([A-Za-z0-9_.-]+)(\/[A-Za-z0-9_.-]+)?$
	Repository string `json:"repository"`

	// values.yaml 위치 ("path/to/values.yaml")
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=^.*\.ya?ml$
	// +kubebuilder:validation:Required
	Path string `json:"path"`

	// +optional
	// +kubebuilder:validation:Pattern=^[A-Za-z0-9._\/\-]+$
	GitRef string `json:"gitRef,omitempty"`

	// 적용 대상 리소스 이름/네임스페이스
	// +kubebuilder:validation:MinLength=1
	TargetName string `json:"targetName"`
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// 폴링 간격 분 단위 (Default: 1m)
	// +optional
	// +kubebuilder:default="1m"
	// +kubebuilder:validation:Pattern=^([0-9]+(m))+$
	PollInterval string `json:"pollInterval,omitempty"`
}

// OctoVaultStatus defines the observed state of OctoVault.
type OctoVaultStatus struct {
	// +optional
	Phase string `json:"phase,omitempty"`

	// +optional
	Message string `json:"message,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	LastSyncedTime *metav1.Time `json:"lastSyncedTime,omitempty"`

	// +optional
	ObservedRevision string `json:"observedRevision,omitempty"`

	// +optional
	AppliedDataHash string `json:"appliedDataHash,omitempty"`

	// +optional
	ResolvedType string `json:"resolvedType,omitempty"` // ConfigMap | Secret

	// +optional
	ObservedRef string `json:"observedRef,omitempty"`

	// 외부 참조들의 현재 버전/스테이지 정보
	// +optional
	ExternalRefs []ExternalRefStatus `json:"externalRefs,omitempty"`

	// 출력용 요약 문자열 (printer column)
	// +optional
	ExternalRefsSummary string `json:"externalRefsSummary,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=ov;ovl
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="OctoRepositoryRef",type=string,JSONPath=`.spec.octoRepositoryRef.name`
// +kubebuilder:printcolumn:name="Repo",type=string,JSONPath=`.spec.repository`
// +kubebuilder:printcolumn:name="Ref",type=string,JSONPath=`.spec.observedRef`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.status.resolvedType`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targetName`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Rev",type=string,JSONPath=`.status.observedRevision`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// OctoVault is the Schema for the octovaults API
type OctoVault struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of OctoVault
	// +required
	Spec OctoVaultSpec `json:"spec"`

	// status defines the observed state of OctoVault
	// +optional
	Status OctoVaultStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true
// OctoVaultList contains a list of OctoVault
type OctoVaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OctoVault `json:"items"`
}

func init() {

	SchemeBuilder.Register(&OctoVault{}, &OctoVaultList{})
}
