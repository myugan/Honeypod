// Package activity tracks attacker traffic against each Decoy and
// flushes a summary to the Decoy's status, so `kubectl get decoys`
// shows which traps have been triggered without anyone reading the audit
// log.
package activity

import (
	"context"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/metrics"
)

type counter struct {
	firstSeen    time.Time
	lastSeen     time.Time
	count        int64 // total requests seen by this process
	flushed      int64 // how many of those are already reflected in status
	lastSourceIP string
	dirty        bool
}

// Tracker accumulates attacker activity in memory and periodically flushes
// it to Decoy status. Recording is cheap (a map bump under a lock) so it
// can run on the hot audit path; the expensive status writes are batched by
// Run's flush loop and only touch Decoys whose counters changed.
type Tracker struct {
	client client.Client

	mu       sync.Mutex
	counters map[types.NamespacedName]*counter
}

func New(c client.Client) *Tracker {
	return &Tracker{client: c, counters: map[types.NamespacedName]*counter{}}
}

// Record notes one attacker request against a decoy. Call it only for events
// that represent attacker traffic (notifier.IsNotableAuditEvent), not the
// decoy's own housekeeping.
func (t *Tracker) Record(namespace, name, sourceIP string, when time.Time) {
	key := types.NamespacedName{Namespace: namespace, Name: name}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.counters[key]
	if c == nil {
		c = &counter{firstSeen: when}
		t.counters[key] = c
	}
	if c.firstSeen.IsZero() {
		c.firstSeen = when
	}
	if when.After(c.lastSeen) {
		c.lastSeen = when
	}
	c.count++
	if sourceIP != "" {
		c.lastSourceIP = sourceIP
	}
	c.dirty = true
	metrics.AttackerRequests.WithLabelValues(namespace, name).Inc()
}

// Run flushes dirty counters to status every interval until ctx is done.
func (t *Tracker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// ctx is already cancelled here; a flush with it would fail
			// every write and silently drop the not-yet-persisted tail of
			// the counters. Give the final flush its own short deadline.
			finalCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.flush(finalCtx)
			cancel()
			return
		case <-ticker.C:
			t.flush(ctx)
		}
	}
}

func (t *Tracker) flush(ctx context.Context) {
	// Snapshot the dirty entries under the lock, then do the API writes
	// without holding it, so Record never blocks on the apiserver.
	type pending struct {
		key types.NamespacedName
		c   counter
	}
	var todo []pending
	t.mu.Lock()
	for key, c := range t.counters {
		if c.dirty {
			todo = append(todo, pending{key, *c})
			c.dirty = false
		}
	}
	t.mu.Unlock()

	for _, p := range todo {
		err := t.writeStatus(ctx, p.key, p.c)
		switch {
		case err == nil:
			// Mark the delta we just wrote as flushed, so the next flush
			// only adds requests seen since. Guarded because Record may
			// have bumped count further while the write was in flight.
			t.mu.Lock()
			if cur := t.counters[p.key]; cur != nil {
				cur.flushed = p.c.count
			}
			t.mu.Unlock()
		case apierrors.IsNotFound(err):
			// The decoy was deleted. Drop its counter so the map does not
			// grow forever across many short-lived Decoys.
			t.mu.Lock()
			delete(t.counters, p.key)
			t.mu.Unlock()
		default:
			// Transient error: re-mark dirty so the next flush retries.
			metrics.ActivityFlushErrors.Inc()
			t.mu.Lock()
			if cur := t.counters[p.key]; cur != nil {
				cur.dirty = true
			}
			t.mu.Unlock()
		}
	}
}

func (t *Tracker) writeStatus(ctx context.Context, key types.NamespacedName, c counter) error {
	// Add only the requests seen since the last successful flush, so the
	// total survives a manager restart: after a restart the in-memory
	// counter starts at zero, and adding its delta to the already-persisted
	// status count keeps the running total instead of resetting it to 1.
	delta := c.count - c.flushed
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var kt honeypodv1alpha1.Decoy
		if err := t.client.Get(ctx, key, &kt); err != nil {
			return err
		}
		prev := kt.Status.IntrusionActivity
		last := metav1.NewTime(c.lastSeen)
		next := &honeypodv1alpha1.IntrusionActivity{
			LastSeen:     &last,
			RequestCount: delta,
			LastSourceIP: c.lastSourceIP,
		}
		if prev != nil {
			next.RequestCount += prev.RequestCount
			// Keep the earliest firstSeen ever recorded.
			if prev.FirstSeen != nil {
				next.FirstSeen = prev.FirstSeen
			}
		}
		if next.FirstSeen == nil {
			first := metav1.NewTime(c.firstSeen)
			next.FirstSeen = &first
		}
		kt.Status.IntrusionActivity = next
		return t.client.Status().Update(ctx, &kt)
	})
}
