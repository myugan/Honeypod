package notifier

import (
	"strings"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/auditwebhook"
)

// AuditFilter is one Alert's notability rules for AuditActivity.
type AuditFilter struct {
	// IncludeAll skips the built-in heuristic below entirely.
	IncludeAll bool
	// ExcludeVerbs are verbs dropped in addition to the built-in heuristic.
	ExcludeVerbs []string
	// ExcludeResources are "resource" or "resource/subresource" entries
	// dropped in addition to the built-in heuristic.
	ExcludeResources []string
}

// FilterFromAlertSpec builds an AuditFilter from an Alert's own spec fields.
func FilterFromAlertSpec(spec honeypodv1alpha1.AlertSpec) AuditFilter {
	return AuditFilter{
		IncludeAll:       spec.IncludeAll,
		ExcludeVerbs:     spec.ExcludeVerbs,
		ExcludeResources: spec.ExcludeResources,
	}
}

// IsNotableAuditEvent reports whether ev is worth a discrete Alert
// notification under filter. The built-in heuristic (unless
// filter.IncludeAll) drops the decoy's own internal traffic: kube-apiserver
// housekeeping and kubelet-shim's seeding and heartbeats, all of which run
// under a system: identity, while anyone holding the decoy token appears as
// kubernetes-admin. Status subresource writes and lease renewals are dropped
// too, since they are pure heartbeat noise whoever makes them.
// filter.ExcludeVerbs/ExcludeResources apply on top, regardless of
// IncludeAll. AuditSink ignores all of this and ships every event
// unfiltered.
func IsNotableAuditEvent(ev auditwebhook.Event, filter AuditFilter) bool {
	if !filter.IncludeAll {
		if strings.HasPrefix(ev.User.Username, "system:") {
			return false
		}
		if ev.ObjectRef == nil {
			return false
		}
		if ev.ObjectRef.Subresource == "status" {
			return false
		}
		if ev.ObjectRef.Resource == "leases" {
			return false
		}
	}
	for _, v := range filter.ExcludeVerbs {
		if v == ev.Verb {
			return false
		}
	}
	for _, pattern := range filter.ExcludeResources {
		if matchesResourcePattern(pattern, ev.ObjectRef) {
			return false
		}
	}
	return true
}

// matchesResourcePattern matches ref against one ExcludeResources entry,
// written as "resource" or "resource/subresource".
func matchesResourcePattern(pattern string, ref *auditwebhook.ObjectRef) bool {
	if ref == nil {
		return false
	}
	resource, subresource, hasSub := strings.Cut(pattern, "/")
	if ref.Resource != resource {
		return false
	}
	return !hasSub || ref.Subresource == subresource
}
