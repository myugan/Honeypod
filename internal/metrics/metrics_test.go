package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// gatherFamilies returns the set of metric-family names currently exposed
// by controller-runtime's registry -- i.e. what a scrape of /metrics would
// serve.
func gatherFamilies(t *testing.T) map[string]bool {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gathering controller-runtime registry: %v", err)
	}
	names := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	return names
}

// TestRegisteredOnControllerRuntimeRegistry proves every honeypod_* family
// is served from the same registry as controller-runtime's built-ins, so
// they all appear on the manager's one /metrics endpoint.
func TestRegisteredOnControllerRuntimeRegistry(t *testing.T) {
	// Counters/gauges with labels only appear in a Gather once at least
	// one child series exists; touch each family first.
	ReconcileErrors.WithLabelValues("reg-test", "kt").Add(0)
	SetPhase("reg-test", "kt", "Pending")
	JoinedPods.WithLabelValues("reg-test", "kt").Set(0)
	AuditEvents.WithLabelValues("reg-test", "kt").Add(0)
	AttackerRequests.WithLabelValues("reg-test", "kt").Add(0)
	ActivityFlushErrors.Add(0)
	defer DeleteDecoy("reg-test", "kt")

	names := gatherFamilies(t)
	for _, want := range []string{
		"honeypod_reconcile_errors_total",
		"honeypod_phase",
		"honeypod_joined_pods",
		"honeypod_audit_events_received_total",
		"honeypod_attacker_requests_total",
		"honeypod_activity_flush_errors_total",
	} {
		if !names[want] {
			t.Errorf("metric family %q not gathered from controller-runtime registry", want)
		}
	}
}

// TestNoDuplicateRegistration proves each collector is registered exactly
// once: a second Register of the same collector must come back as
// AlreadyRegisteredError (it is already there), never as a silent success
// (it was missing) or a different error (it collides with something else).
func TestNoDuplicateRegistration(t *testing.T) {
	for name, c := range map[string]prometheus.Collector{
		"honeypod_reconcile_errors_total":      ReconcileErrors,
		"honeypod_phase":                       Phase,
		"honeypod_joined_pods":                 JoinedPods,
		"honeypod_audit_events_received_total": AuditEvents,
		"honeypod_attacker_requests_total":     AttackerRequests,
		"honeypod_activity_flush_errors_total": ActivityFlushErrors,
	} {
		err := ctrlmetrics.Registry.Register(c)
		var are prometheus.AlreadyRegisteredError
		if !errors.As(err, &are) {
			t.Errorf("re-registering %s: want AlreadyRegisteredError, got %v", name, err)
		}
	}
}

// TestSetPhaseIsOneHot proves exactly one phase row is 1 after SetPhase,
// and that a later transition flips the rows rather than leaving two set.
func TestSetPhaseIsOneHot(t *testing.T) {
	defer DeleteDecoy("phase-test", "kt")

	SetPhase("phase-test", "kt", "Pending")
	for phase, want := range map[string]float64{"Pending": 1, "Ready": 0, "Failed": 0} {
		if got := testutil.ToFloat64(Phase.WithLabelValues("phase-test", "kt", phase)); got != want {
			t.Errorf("after SetPhase(Pending): phase %s = %v, want %v", phase, got, want)
		}
	}

	SetPhase("phase-test", "kt", "Ready")
	for phase, want := range map[string]float64{"Pending": 0, "Ready": 1, "Failed": 0} {
		if got := testutil.ToFloat64(Phase.WithLabelValues("phase-test", "kt", phase)); got != want {
			t.Errorf("after SetPhase(Ready): phase %s = %v, want %v", phase, got, want)
		}
	}
}

// TestDeleteDecoyDropsAllSeries proves deletion removes every series
// carrying that Decoy's labels, across all per-Decoy families, and
// leaves other Decoys' series alone.
func TestDeleteDecoyDropsAllSeries(t *testing.T) {
	defer DeleteDecoy("del-test", "other")

	ReconcileErrors.WithLabelValues("del-test", "kt").Inc()
	SetPhase("del-test", "kt", "Ready")
	JoinedPods.WithLabelValues("del-test", "kt").Set(3)
	AuditEvents.WithLabelValues("del-test", "kt").Add(7)
	AttackerRequests.WithLabelValues("del-test", "kt").Add(2)
	AttackerRequests.WithLabelValues("del-test", "other").Add(5)

	DeleteDecoy("del-test", "kt")

	for name, vec := range map[string]*prometheus.CounterVec{
		"honeypod_reconcile_errors_total":      ReconcileErrors,
		"honeypod_audit_events_received_total": AuditEvents,
		"honeypod_attacker_requests_total":     AttackerRequests,
	} {
		if n := vec.DeletePartialMatch(prometheus.Labels{"namespace": "del-test", "name": "kt"}); n != 0 {
			t.Errorf("%s: %d series for deleted Decoy survived DeleteDecoy", name, n)
		}
	}
	if n := Phase.DeletePartialMatch(prometheus.Labels{"namespace": "del-test", "name": "kt"}); n != 0 {
		t.Errorf("honeypod_phase: %d series for deleted Decoy survived DeleteDecoy", n)
	}
	if n := JoinedPods.DeletePartialMatch(prometheus.Labels{"namespace": "del-test", "name": "kt"}); n != 0 {
		t.Errorf("honeypod_joined_pods: %d series for deleted Decoy survived DeleteDecoy", n)
	}

	// The unrelated series must still be there with its value intact.
	if got := testutil.ToFloat64(AttackerRequests.WithLabelValues("del-test", "other")); got != 5 {
		t.Errorf("unrelated series disturbed by DeleteDecoy: got %v, want 5", got)
	}
}
