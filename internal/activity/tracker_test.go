package activity

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/metrics"
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := honeypodv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestTracker_AccumulatesAndFlushes covers the whole path: several attacker
// requests accumulate in memory, then one flush writes a single status
// summary with the count, first/last seen, and last source IP.
func TestTracker_AccumulatesAndFlushes(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "decoy", Namespace: "kt"}}
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(kt).WithStatusSubresource(kt).Build()
	tr := New(c)

	t0 := time.Now()
	tr.Record("kt", "decoy", "203.0.113.7", t0)
	tr.Record("kt", "decoy", "203.0.113.7", t0.Add(time.Second))
	tr.Record("kt", "decoy", "198.51.100.9", t0.Add(2*time.Second))

	tr.flush(context.Background())

	var got honeypodv1alpha1.Decoy
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kt", Name: "decoy"}, &got); err != nil {
		t.Fatal(err)
	}
	a := got.Status.IntrusionActivity
	if a == nil {
		t.Fatal("expected IntrusionActivity to be written")
	}
	if a.RequestCount != 3 {
		t.Fatalf("expected 3 requests, got %d", a.RequestCount)
	}
	if a.LastSourceIP != "198.51.100.9" {
		t.Fatalf("expected the most recent source IP, got %q", a.LastSourceIP)
	}
	if a.FirstSeen == nil || a.LastSeen == nil || a.LastSeen.Before(a.FirstSeen) {
		t.Fatalf("first/last seen must be set and ordered, got %+v / %+v", a.FirstSeen, a.LastSeen)
	}
}

// TestTracker_FlushIsNoopWhenClean confirms a second flush with no new
// activity does not rewrite status (nothing dirty).
func TestTracker_FlushIsNoopWhenClean(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "kt"}}
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(kt).WithStatusSubresource(kt).Build()
	tr := New(c)

	tr.Record("kt", "d", "", time.Now())
	tr.flush(context.Background())

	var first honeypodv1alpha1.Decoy
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "kt", Name: "d"}, &first)
	rv := first.ResourceVersion

	tr.flush(context.Background()) // nothing dirty

	var second honeypodv1alpha1.Decoy
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "kt", Name: "d"}, &second)
	if second.ResourceVersion != rv {
		t.Fatal("a clean flush must not rewrite status")
	}
}

// TestTracker_PrunesDeletedDecoy covers the memory bound: a decoy deleted
// while its counter is dirty must be dropped from the map on the next flush,
// not retried forever.
func TestTracker_PrunesDeletedDecoy(t *testing.T) {
	// No object in the client, so writeStatus gets NotFound.
	c := fake.NewClientBuilder().WithScheme(scheme(t)).Build()
	tr := New(c)

	tr.Record("kt", "gone", "", time.Now())
	if len(tr.counters) != 1 {
		t.Fatalf("expected 1 counter, got %d", len(tr.counters))
	}
	tr.flush(context.Background())
	if len(tr.counters) != 0 {
		t.Fatalf("a deleted decoy's counter must be pruned, still have %d", len(tr.counters))
	}
}

// TestTracker_CountSurvivesRestart covers the additive write: a fresh
// tracker (as after a manager restart) whose in-memory count starts at zero
// must add its new requests to the already-persisted total, not reset it.
func TestTracker_CountSurvivesRestart(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	kt := &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "kt"},
		Status: honeypodv1alpha1.DecoyStatus{
			IntrusionActivity: &honeypodv1alpha1.IntrusionActivity{
				FirstSeen: &past, LastSeen: &past, RequestCount: 5,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(kt).WithStatusSubresource(kt).Build()

	tr := New(c) // fresh, as after a restart
	tr.Record("kt", "d", "203.0.113.1", time.Now())
	tr.Record("kt", "d", "203.0.113.1", time.Now())
	tr.flush(context.Background())

	var got honeypodv1alpha1.Decoy
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kt", Name: "d"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.IntrusionActivity.RequestCount != 7 {
		t.Fatalf("expected 5 persisted + 2 new = 7, got %d", got.Status.IntrusionActivity.RequestCount)
	}
	if !got.Status.IntrusionActivity.FirstSeen.Equal(&past) {
		t.Fatalf("firstSeen must be preserved across restart, got %v", got.Status.IntrusionActivity.FirstSeen)
	}

	// A second flush with no new activity must not double-count.
	tr.flush(context.Background())
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "kt", Name: "d"}, &got)
	if got.Status.IntrusionActivity.RequestCount != 7 {
		t.Fatalf("a clean flush must not change the count, got %d", got.Status.IntrusionActivity.RequestCount)
	}
}

// TestTracker_RecordIncrementsMetric covers the Prometheus side of Record:
// each recorded attacker request bumps honeypod_attacker_requests_total for
// exactly that Decoy.
func TestTracker_RecordIncrementsMetric(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "metric-decoy", Namespace: "kt-metrics"}}
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(kt).WithStatusSubresource(kt).Build()
	tr := New(c)
	defer metrics.DeleteDecoy("kt-metrics", "metric-decoy")

	before := testutil.ToFloat64(metrics.AttackerRequests.WithLabelValues("kt-metrics", "metric-decoy"))
	tr.Record("kt-metrics", "metric-decoy", "203.0.113.7", time.Now())
	tr.Record("kt-metrics", "metric-decoy", "203.0.113.7", time.Now())
	after := testutil.ToFloat64(metrics.AttackerRequests.WithLabelValues("kt-metrics", "metric-decoy"))
	if after != before+2 {
		t.Fatalf("honeypod_attacker_requests_total: got %v, want %v", after, before+2)
	}
}
