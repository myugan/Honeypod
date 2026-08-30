// Package metrics defines Decoy's own Prometheus metrics and registers
// them on controller-runtime's global registry, so they are served from the
// same /metrics endpoint (the manager's metrics server, :8080 by default)
// as the built-in controller_runtime_reconcile_* and workqueue_* families.
//
// Registration happens once, in this package's init, via MustRegister on
// that shared registry -- importing this package from more than one place
// is safe (init runs once per process), and a second explicit Register of
// the same collector is the only way to hit a duplicate-registration error.
//
// Series for a specific Decoy are labelled namespace/name and must be
// removed with DeleteDecoy when that Decoy is deleted, or the
// endpoint keeps advertising decoys that no longer exist.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// phases mirrors api/v1alpha1's DecoyPhase values. Kept as strings here
// so this package stays import-free of the API types (and so SetPhase can
// zero the rows for every known phase, whichever one is current).
var phases = []string{"Pending", "Ready", "Failed"}

var (
	// ReconcileErrors counts failed reconciles per Decoy. The built-in
	// controller_runtime_reconcile_errors_total counts the same failures
	// but only per controller, so it can't say which decoy is failing.
	ReconcileErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypod_reconcile_errors_total",
		Help: "Total failed reconciles per Decoy. Each is also recorded on the Decoy's Ready condition.",
	}, []string{"namespace", "name"})

	// Phase is a one-hot gauge of each Decoy's status.phase: the row
	// matching the current phase is 1, the other phase rows are 0.
	Phase = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "honeypod_phase",
		Help: "Current phase of each Decoy: 1 on the row matching status.phase (Pending, Ready, or Failed), 0 on the others.",
	}, []string{"namespace", "name", "phase"})

	// JoinedPods is the number of real Pods currently mirrored into each
	// Decoy via the honeypod.io/join annotation.
	JoinedPods = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "honeypod_joined_pods",
		Help: "Number of real Pods currently mirrored into each Decoy via the honeypod.io/join annotation.",
	}, []string{"namespace", "name"})

	// AuditEvents counts every audit event received from a Decoy's
	// inner kube-apiserver, including the decoy's own housekeeping
	// traffic. Compare with AttackerRequests for the filtered view.
	AuditEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypod_audit_events_received_total",
		Help: "Total audit events received from each Decoy's inner apiserver, including the decoy's own housekeeping traffic.",
	}, []string{"namespace", "name"})

	// AttackerRequests counts only notable audit events -- requests made
	// under a non-system identity, i.e. someone holding the decoy token.
	// It is the metric to alert on: any increase means a trap was touched.
	AttackerRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "honeypod_attacker_requests_total",
		Help: "Total notable (attacker-attributed) audit events per Decoy; the same count surfaced by status.intrusionActivity.requestCount.",
	}, []string{"namespace", "name"})

	// ActivityFlushErrors counts failed attacker-activity status writes.
	// These are retried on the next flush interval, so a nonzero rate means
	// status.intrusionActivity is lagging, not lost.
	ActivityFlushErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "honeypod_activity_flush_errors_total",
		Help: "Total failed flushes of attacker-activity counters to Decoy status; each is retried on the next flush interval.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ReconcileErrors,
		Phase,
		JoinedPods,
		AuditEvents,
		AttackerRequests,
		ActivityFlushErrors,
	)
}

// SetPhase records kt's current phase one-hot: exactly one phase row per
// Decoy reads 1 after this call, so `sum by (phase)` counts decoys per
// phase without double counting phase transitions.
func SetPhase(namespace, name, phase string) {
	for _, p := range phases {
		v := 0.0
		if p == phase {
			v = 1
		}
		Phase.WithLabelValues(namespace, name, p).Set(v)
	}
}

// DeleteDecoy drops every per-Decoy series for a deleted Decoy.
// Called from the reconciler when the object is gone; without it the
// /metrics endpoint keeps advertising (and alerting on) deleted decoys.
func DeleteDecoy(namespace, name string) {
	match := prometheus.Labels{"namespace": namespace, "name": name}
	ReconcileErrors.DeletePartialMatch(match)
	Phase.DeletePartialMatch(match)
	JoinedPods.DeletePartialMatch(match)
	AuditEvents.DeletePartialMatch(match)
	AttackerRequests.DeletePartialMatch(match)
}
