package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuditSinkSpec defines where a Decoy's full, unfiltered audit stream is
// shipped -- unlike Alert, every event is forwarded (no notability filter).
type AuditSinkSpec struct {
	// ProviderRef selects a Provider in this namespace to ship events to.
	// A "discord" Provider is rejected: a chat webhook is the wrong shape
	// for a high-volume log stream.
	ProviderRef ProviderReference `json:"providerRef"`

	// Targets lists which Decoy(s) this AuditSink ships audit events for.
	// Empty means every Decoy -- the intended shape for a single-decoy
	// deployment, where one AuditSink covers the sole decoy without naming it.
	// +optional
	Targets []DecoyTarget `json:"targets,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.type`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuditSink ships a Decoy's full audit event stream to a Provider such
// as Loki, for continuous analysis rather than discrete alerts. It has no
// status: nothing reconciles it, it is read when an event fires.
type AuditSink struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AuditSinkSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AuditSinkList contains a list of AuditSink.
type AuditSinkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuditSink `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AuditSink{}, &AuditSinkList{})
}
