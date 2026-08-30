//go:build linux

package kubeletshim

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// isolatedCmd builds the exec command for an isolated session
// (spec.execIsolation): it re-execs the shim with --exec-init inside a fresh
// PID/mount/UTS namespace, so RunExecInit sets the session up and execs the
// target. `ps` and /proc/1 then show only that session, and each pod has its
// own hostname. Requires CAP_SYS_ADMIN (granted only when execIsolation is set).
func (sh *Shim) isolatedCmd(ctx context.Context, args []string, sandbox execSandbox, podName string) *exec.Cmd {
	// Point a shadowed command (hostname, uname) straight at the sandbox
	// script, so a one-shot `kubectl exec -- uname` never depends on PATH
	// resolution inside the re-exec'd child -- falling through to the real
	// binary would leak the host's kernel/hostname. An interactive shell that
	// types the command itself still resolves it via PATH, which
	// newExecSandbox makes traversable for the dropped uid.
	args = append([]string(nil), args...)
	if len(args) > 0 && sandbox.overrides[args[0]] {
		args[0] = filepath.Join(sandbox.dir, args[0])
	}
	reexec := append([]string{"--exec-init"}, args...)
	cmd := exec.CommandContext(ctx, "/proc/self/exe", reexec...)
	env := append([]string(nil), sandbox.env...)
	env = append(env, "HONEYPOD_EXEC_HOSTNAME="+podName)
	// Under the minimal (busybox/alpine) profile, present an Alpine
	// /etc/os-release so `cat /etc/os-release` doesn't read the shim's debian
	// base. The init bind-mounts it inside the session's own mount namespace.
	if sh.cfg.ExecProfile == execProfileMinimal && sandbox.dir != "" {
		osrel := sandbox.dir + "/os-release"
		if err := os.WriteFile(osrel, []byte(alpineOSRelease), 0o644); err == nil {
			env = append(env, "HONEYPOD_EXEC_OSRELEASE="+osrel)
		}
	}
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS,
		Unshareflags: syscall.CLONE_NEWNS,
	}
	return cmd
}

const alpineOSRelease = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3
PRETTY_NAME="Alpine Linux v3.20"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
`

// RunExecInit is the child side of an isolated exec session, run via the shim
// re-execing itself with --exec-init inside the new namespaces. It sets the
// session's hostname, mounts a fresh /proc (so the new PID namespace is what
// `ps` sees), optionally bind-mounts a per-profile /etc/os-release, then execs
// the real target command. args is the target: args[0] the command, args[1:]
// its arguments.
func RunExecInit(args []string) {
	if len(args) == 0 {
		os.Exit(1)
	}
	if hn := os.Getenv("HONEYPOD_EXEC_HOSTNAME"); hn != "" {
		_ = unix.Sethostname([]byte(hn))
	}
	// Don't let our mounts propagate back to the host mount namespace.
	_ = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
	// Fresh /proc reflects this new PID namespace, so `ps` and /proc/1 show
	// only this session, not the shim or other concurrent sessions.
	_ = unix.Mount("proc", "/proc", "proc", 0, "")
	if osrel := os.Getenv("HONEYPOD_EXEC_OSRELEASE"); osrel != "" {
		_ = unix.Mount(osrel, "/etc/os-release", "", unix.MS_BIND, "")
	}

	// Clean the HONEYPOD_EXEC_* markers so the target's own `env` never shows
	// them.
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HONEYPOD_EXEC_") {
			continue
		}
		env = append(env, kv)
	}

	// The namespace/mount setup above needed root (effective CAP_SYS_ADMIN).
	// Drop to the image's app uid before running the attacker's command, so
	// `id`/`whoami` in the session read as a normal user and the shell itself
	// holds no capabilities -- setup is privileged, the session is not.
	const appUID = 1000
	_ = unix.Setgroups([]int{appUID})
	_ = unix.Setgid(appUID)
	_ = unix.Setuid(appUID)

	path := args[0]
	if resolved, err := exec.LookPath(path); err == nil {
		path = resolved
	}
	_ = syscall.Exec(path, args, env)
	// Exec only returns on failure -- e.g. the binary doesn't exist.
	os.Exit(127)
}
