//go:build linux

package kubeletshim

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MaskProcessTitle overwrites this process's argv memory -- what
// /proc/self/cmdline (and so `ps`, `cat /proc/1/cmdline`) shows -- and its
// comm with procTitle, so an exec session inside a decoy that inspects PID 1
// sees a benign "/pause" instead of "/kubelet-shim --seed=...". Call it after
// flags are parsed into config; nothing re-reads os.Args afterwards.
//
// The argv/environ block the kernel exposes as /proc/self/cmdline is the
// contiguous, writable region the strings in os.Args already alias, so writing
// over it is the standard setproctitle technique -- no new privileges needed,
// which matters under the exec container's dropped-capabilities hardening.
func MaskProcessTitle() {
	if len(os.Args) == 0 {
		return
	}
	total := 0
	for _, a := range os.Args {
		total += len(a) + 1 // each arg plus its NUL separator
	}
	buf := unsafe.Slice(unsafe.StringData(os.Args[0]), total)
	writeTitle(buf, procTitle)

	// comm is capped at 15 bytes by the kernel; use the basename.
	comm := procTitle
	for i := len(procTitle) - 1; i >= 0; i-- {
		if procTitle[i] == '/' {
			comm = procTitle[i+1:]
			break
		}
	}
	if len(comm) > 15 {
		comm = comm[:15]
	}
	_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(unsafe.StringData(comm+"\x00"))), 0, 0, 0)
}
