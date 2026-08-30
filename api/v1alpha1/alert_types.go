package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AlertEventType is one kind of event an Alert can fire on.
// +kubebuilder:validation:Enum=PodJoin;AuditActivity
type AlertEventType string

const (
	// AlertEventPodJoin fires when a Pod joins or leaves a Decoy via
	// the honeypod.io/join annotation.
	AlertEventPodJoin AlertEventType = "PodJoin"
	// AlertEventAuditActivity fires on notable activity against a Decoy,
	// filtered so the honeypot's own internal traffic doesn't alert.
	AlertEventAuditActivity AlertEventType = "AuditActivity"
)

// AlertSpec defines what an Alert notifies on, and where.
type AlertSpec struct {
	// ProviderRef selects a same-namespace Provider to send notifications to.
	ProviderRef ProviderReference `json:"providerRef"`

	// Targets lists which Decoy(s) this Alert watches. Empty means every
	// Decoy -- the intended shape for a single-decoy deployment, where one
	// Alert covers the sole decoy without naming it.
	// +optional
	Targets []DecoyTarget `json:"targets,omitempty"`

	// EventTypes to notify on. Defaults to both PodJoin and
	// AuditActivity.
	// +optional
	EventTypes []AlertEventType `json:"eventTypes,omitempty"`

	// IncludeAll alerts on every audit event, including the honeypot's own
	// internal traffic. Off by default, since that traffic is constant and
	// would drown out a real intruder. ExcludeVerbs and ExcludeResources
	// still apply on top.
	// +optional
	IncludeAll bool `json:"includeAll,omitempty"`

	// ExcludeVerbs lists audit verbs (e.g. "watch") to always drop from
	// AuditActivity, on top of the built-in heuristic.
	// +optional
	ExcludeVerbs []string `json:"excludeVerbs,omitempty"`

	// ExcludeResources lists API resources to always drop from
	// AuditActivity, on top of the built-in heuristic. Each entry is
	// "resource" (any subresource) or "resource/subresource" (e.g. "pods",
	// "pods/log").
	// +optional
	ExcludeResources []string `json:"excludeResources,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.providerRef.type`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Alert notifies a Provider when a Pod is joined by a Decoy, or when
// something notable happens inside one. It has no status: nothing
// reconciles it, it is read when an event fires.
type Alert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AlertSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AlertList contains a list of Alert.
type AlertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Alert `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Alert{}, &AlertList{})
}
