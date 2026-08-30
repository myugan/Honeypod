package kubeletshim

import (
	"bytes"
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

// sessionLog records one exec/attach session to the shim's own stdout, so an
// operator inspecting a sprung decoy (kubectl logs <pod> -c kubelet-shim)
// sees what the attacker actually did. The initial command is already in the
// audit trail's /exec URI, but an interactive `exec -it ... sh` only records
// "sh" there -- everything typed inside the shell (ls, cat /etc/shadow, curl
// to an exfil host) lives nowhere else. A pty echoes typed input back into
// its output, so teeing stdout captures the full transcript, commands and
// their results together.
type sessionLog struct {
	target string // "namespace/pod"
	prefix string
	start  time.Time

	mu      sync.Mutex
	pending []byte
	bytes   int
}

func newSessionLog(namespace, pod, container string, tty bool, command []string) *sessionLog {
	shape := "exec"
	if tty {
		shape = "exec-tty"
	}
	target := namespace + "/" + pod
	log.Printf("[honeypod exec] session start %s (%s) %s command=%q",
		target, container, shape, strings.Join(command, " "))
	return &sessionLog{
		target: target,
		prefix: "[honeypod exec] " + target + " | ",
		start:  time.Now(),
	}
}

// tee wraps w so everything written through it is also recorded. A nil
// sessionLog (recording disabled) returns w untouched.
func (s *sessionLog) tee(w io.Writer) io.Writer {
	if s == nil || w == nil {
		return w
	}
	return io.MultiWriter(w, s)
}

func (s *sessionLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytes += len(p)
	s.pending = append(s.pending, p...)
	// Emit one log line per complete output line, so live `kubectl logs -f`
	// on the decoy shows the session as it happens. Carriage returns and a
	// trailing incomplete line are held back until they complete.
	for {
		i := bytes.IndexByte(s.pending, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(s.pending[:i]), "\r")
		s.pending = s.pending[i+1:]
		if line != "" {
			log.Print(s.prefix + line)
		}
	}
	// A line with no newline must not grow the buffer without bound: an
	// attacker running `cat /dev/zero` (or dumping a huge binary) would
	// otherwise OOM the shim. Flush and reset once the pending line passes
	// a cap; the transcript stays faithful, just line-wrapped.
	if len(s.pending) > maxPendingLine {
		log.Print(s.prefix + strings.TrimRight(string(s.pending), "\r"))
		s.pending = s.pending[:0]
	}
	return len(p), nil
}

// maxPendingLine caps how much output with no newline is buffered before it
// is flushed as one line.
const maxPendingLine = 8 << 10

// done flushes any final partial line and logs the session summary.
func (s *sessionLog) done(exitCode int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tail := strings.TrimRight(string(s.pending), "\r\n"); tail != "" {
		log.Print(s.prefix + tail)
	}
	s.pending = nil
	log.Printf("[honeypod exec] session end %s exit=%d bytes=%d duration=%s",
		s.target, exitCode, s.bytes, time.Since(s.start).Round(time.Millisecond))
}
