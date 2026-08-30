package kubeletshim

import (
	"context"
	"errors"
	"testing"
)

// TestPruneSeeded_RetriesFailedDelete proves a prune delete that fails
// transiently is retried on the next pass rather than being forgotten -- the
// object would otherwise stay stranded in the decoy forever.
func TestPruneSeeded_RetriesFailedDelete(t *testing.T) {
	sh := &Shim{seededPrev: map[string]func(context.Context) error{}}
	ctx := context.Background()

	attempts := 0
	failing := func(context.Context) error {
		attempts++
		return errors.New("transient")
	}

	// Pass 1: the object is seeded.
	sh.seededCur = map[string]func(context.Context) error{"Pod|ns|gone": failing}
	sh.pruneSeeded(ctx)
	if attempts != 0 {
		t.Fatalf("a still-desired object must not be deleted, got %d attempts", attempts)
	}

	// Pass 2: dropped from the seed -> prune attempts a delete, which fails.
	sh.seededCur = map[string]func(context.Context) error{}
	sh.pruneSeeded(ctx)
	if attempts != 1 {
		t.Fatalf("expected one delete attempt, got %d", attempts)
	}

	// Pass 3: still dropped -> the failed delete must be retried.
	sh.seededCur = map[string]func(context.Context) error{}
	sh.pruneSeeded(ctx)
	if attempts != 2 {
		t.Fatalf("a failed prune must be retried next pass, got %d attempts", attempts)
	}
}

// TestPruneSeeded_ForgetsAfterSuccess proves a successful prune stops
// retrying, so the tracking map does not grow without bound.
func TestPruneSeeded_ForgetsAfterSuccess(t *testing.T) {
	sh := &Shim{seededPrev: map[string]func(context.Context) error{}}
	ctx := context.Background()

	attempts := 0
	ok := func(context.Context) error {
		attempts++
		return nil
	}

	sh.seededCur = map[string]func(context.Context) error{"Pod|ns|gone": ok}
	sh.pruneSeeded(ctx)

	sh.seededCur = map[string]func(context.Context) error{}
	sh.pruneSeeded(ctx) // deletes successfully
	sh.seededCur = map[string]func(context.Context) error{}
	sh.pruneSeeded(ctx) // must not delete again

	if attempts != 1 {
		t.Fatalf("expected exactly one successful delete, got %d", attempts)
	}
	if len(sh.seededPrev) != 0 {
		t.Fatalf("tracking map must be empty after a successful prune, got %v", sh.seededPrev)
	}
}
