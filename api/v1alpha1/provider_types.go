package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProviderSpec configures one notification/log destination.
type ProviderSpec struct {
	// Type selects the wire format used to talk to Address.
	// +kubebuilder:validation:Enum=discord;loki;generic-webhook
	Type string `json:"type"`

	// Address is the destination URL, given directly.
	// +optional
	Address string `json:"address,omitempty"`

	// SecretRef names a same-namespace Secret whose "address" key holds the
	// destination URL, for a webhook URL that shouldn't be spec-visible.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Provider is where Alerts and AuditSinks send to: Discord, Loki, or a
// generic webhook. It has no status: nothing reconciles it, it is read
// when an event fires.
type Provider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProviderSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ProviderList contains a list of Provider.
type ProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Provider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Provider{}, &ProviderList{})
}
