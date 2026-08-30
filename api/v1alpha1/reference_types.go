package v1alpha1

import corev1 "k8s.io/api/core/v1"

// ProviderReference selects a same-namespace Provider by its spec.type
// (discord/loki/generic-webhook), with an optional override for which
// Secret holds its destination address -- lets one Provider (e.g.
// "discord") be reused by multiple Alerts/AuditSinks that each need a
// different webhook, without a separate Provider object per secret.
type ProviderReference struct {
	// Type matches the target Provider's spec.type. Exactly one Provider
	// of this type must exist in the namespace.
	Type string `json:"type"`

	// SecretRef, if set, overrides the Provider's own spec.secretRef --
	// this Secret's "address" key is used instead.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`
}

// DecoyTarget names one Decoy, or every Decoy in a namespace,
// that an Alert or AuditSink applies to.
type DecoyTarget struct {
	// Name of the Decoy, or "*" for every Decoy in Namespace.
	Name string `json:"name"`

	// Namespace the Decoy is in. Defaults to the Alert/AuditSink's own
	// namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}
