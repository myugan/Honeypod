package kubeletshim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/creack/pty"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	"k8s.io/apimachinery/pkg/util/remotecommand"
)

// terminalSize mirrors k8s.io/client-go/tools/remotecommand.TerminalSize
// (same field names, no JSON tags there either) -- defined locally instead
// of importing that package just for this one struct, which would pull in
// its websocket-fallback dependency for nothing this codebase uses.
type terminalSize struct {
	Width  uint16
	Height uint16
}

// Exec requests reach here as kubectl -> inner kube-apiserver -> kubelet
// proxy -> this endpoint, over the real kubelet HTTP API shape. The shim
// only plays the kubelet role; pod lookup is a real client-go Get against
// the inner apiserver.
//
// `kubectl exec` runs a real process, a real /bin/sh with real binaries.
// There is no container per fake Pod: every session, whichever Pod the
// client thinks it reached, lands in this same sandbox container. It is
// held by execSandboxSecurityContext (all capabilities dropped, non-root,
// no privilege escalation, seccomp), the pod's NetworkPolicy (no egress
// beyond DNS and the operator's audit-webhook receiver), and optionally
// spec.runtimeClassName such as gVisor.
//
// `kubectl logs` and `attach` stay fabricated. A fake Pod's declared image
// never runs, so there is no real output to stream.
const serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// Exec profiles (see Config.ExecProfile / spec.execProfile).
const (
	execProfileShell      = "shell"
	execProfileMinimal    = "minimal"
	execProfileDistroless = "distroless"
)

// shellPath is the real shell run for an interactive `kubectl exec -it`
// session with no explicit command under the default "shell" profile.
const shellPath = "/bin/sh"

// busyboxShellPath is the busybox shell used under the "minimal" profile; the
// image installs busybox and its applet symlinks at busyboxBinDir. The dir
// lives under /usr/lib rather than at the root: a top-level "/busybox-bin"
// showed up in `ls /`, which no real alpine/busybox image has and which gave
// the profile away immediately.
const (
	busyboxBinDir    = "/usr/lib/busybox"
	busyboxShellPath = busyboxBinDir + "/sh"
)

// shellFor returns the interactive shell for the configured exec profile.
func (sh *Shim) shellFor() string {
	if sh.cfg.ExecProfile == execProfileMinimal {
		return busyboxShellPath
	}
	return shellPath
}

func (sh *Shim) handleExec(w http.ResponseWriter, r *http.Request) {
	sh.handleStream(w, r, "exec")
}

func (sh *Shim) handleAttach(w http.ResponseWriter, r *http.Request) {
	sh.handleStream(w, r, "attach")
}

// handleStream drives one exec or attach session end to end: pod/container
// lookup (via a real client-go Get against the inner apiserver), protocol
// negotiation + SPDY upgrade, stream collection, running the session, and
// reporting completion (with a v4-protocol exit code) on the error stream.
func (sh *Shim) handleStream(w http.ResponseWriter, r *http.Request, mode string) {
	ns, name, container := r.PathValue("ns"), r.PathValue("pod"), r.PathValue("container")

	p, err := sh.client.CoreV1().Pods(ns).Get(r.Context(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		w.WriteHeader(http.StatusNotFound)
		writeStatus(w, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeStatus(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}

	if container != "" && !hasContainer(*p, container) {
		w.WriteHeader(http.StatusBadRequest)
		writeStatus(w, http.StatusBadRequest, "BadRequest", fmt.Sprintf("container %q not found in pod %q", container, name))
		return
	}
	if container == "" && len(p.Spec.Containers) > 0 {
		container = p.Spec.Containers[0].Name
	}

	q := r.URL.Query()
	if _, err := httpstream.Handshake(r, w, remotecommand.SupportedStreamingProtocols); err != nil {
		return
	}

	wantStdin := q.Get("input") == "1" || q.Get("stdin") == "true"
	wantStdout := q.Get("output") == "1" || q.Get("stdout") == "true"
	wantStderr := q.Get("stderr") == "true" || q.Get("error") == "1"
	tty := q.Get("tty") == "1" || q.Get("tty") == "true"
	command := q["command"]

	expected := 1 // the error stream is always created
	if wantStdin {
		expected++
	}
	if wantStdout {
		expected++
	}
	if wantStderr && !tty {
		expected++
	}
	if tty {
		expected++ // resize stream
	}

	streamCh := make(chan httpstream.Stream)
	upgrader := spdy.NewResponseUpgrader()
	conn := upgrader.UpgradeResponse(w, r, func(stream httpstream.Stream, _ <-chan struct{}) error {
		streamCh <- stream
		return nil
	})
	if conn == nil {
		return
	}
	defer conn.Close()
	conn.SetIdleTimeout(remotecommand.DefaultStreamCreationTimeout)

	streams := map[string]httpstream.Stream{}
	deadline := time.After(remotecommand.DefaultStreamCreationTimeout)
	var resizeStream httpstream.Stream
collect:
	for len(streams) < expected {
		select {
		case st := <-streamCh:
			t := st.Headers().Get(corev1.StreamType)
			if t == corev1.StreamTypeResize {
				resizeStream = st
			}
			streams[t] = st
		case <-deadline:
			break collect
		}
	}

	errStream := streams[corev1.StreamTypeError]
	stdinStream := streams[corev1.StreamTypeStdin]
	stdoutStream := streams[corev1.StreamTypeStdout]
	stderrStream := streams[corev1.StreamTypeStderr]

	// Distroless profile: the pod's image has no shell or binaries, so a real
	// distroless pod fails an exec at the runtime with an "executable file not
	// found" error and no process ever starts. Reproduce exactly that -- which
	// is also the most contained option, since nothing runs. attach/logs are
	// unaffected (already fabricated).
	if mode == "exec" && (sh.cfg.ExecProfile == execProfileDistroless || containerLacksShell(*p, container)) {
		cmdName := "sh"
		if len(command) > 0 {
			cmdName = command[0]
		}
		writeExecNotFound(errStream, cmdName)
		for _, st := range []httpstream.Stream{stdoutStream, stderrStream, errStream} {
			if st != nil {
				_ = st.Close()
			}
		}
		return
	}

	exitCode := sh.runSession(r.Context(), *p, container, mode, command, tty, stdinStream, stdoutStream, stderrStream, resizeStream)

	writeExecStatus(errStream, exitCode)
	for _, st := range []httpstream.Stream{stdoutStream, stderrStream, errStream} {
		if st != nil {
			_ = st.Close()
		}
	}
}

// shellLessImages are upstream images that ship no shell and no coreutils --
// just the one static binary. Matched by repository prefix, so any tag or
// digest of them counts.
//
// This matters because a decoy seeds the standard kube-system pods, and every
// control-plane image in that set is distroless. Serving them the same real
// Debian shell every other pod gets made `kubectl exec etcd-<node> -n
// kube-system -- sh` succeed, which no real cluster can do: it is a
// one-command, zero-ambiguity answer to "is this a honeypot". Refusing the
// exec the way the real runtime does is both faithful and strictly more
// contained, since no process starts at all.
//
// Matching on the image rather than on a flag in the seed is deliberate: the
// coredns pods are created by the decoy's own real kube-controller-manager
// from a Deployment, never passing through the seed at all, and a user's own
// spec.fakePods can name a distroless image too. The image is the one thing
// every such pod carries.
var shellLessImages = []string{
	"registry.k8s.io/etcd",
	"registry.k8s.io/kube-apiserver",
	"registry.k8s.io/kube-controller-manager",
	"registry.k8s.io/kube-scheduler",
	"registry.k8s.io/coredns",
	"registry.k8s.io/pause",
	"registry.k8s.io/metrics-server",
	"gcr.io/distroless/",
	"coredns/coredns",
}

// containerLacksShell reports whether the container an exec session is
// targeting runs an image with no shell in it. An unnamed container means the
// pod's first, matching how handleStream defaults it.
func containerLacksShell(p corev1.Pod, container string) bool {
	for _, c := range p.Spec.Containers {
		if container != "" && c.Name != container {
			continue
		}
		for _, prefix := range shellLessImages {
			if strings.HasPrefix(c.Image, prefix) {
				return true
			}
		}
		return false
	}
	return false
}

// runSession runs one real (exec) or fabricated (attach) session and
// returns the exit code.
func (sh *Shim) runSession(ctx context.Context, p corev1.Pod, container, mode string, command []string, tty bool, stdin io.Reader, stdout, stderr io.Writer, resize httpstream.Stream) int {
	if mode == "attach" {
		// No real process was ever started for a FakePod's declared image
		// (there is nothing real to attach to), so this is the one place
		// that's still a canned response: the same lines `kubectl logs`
		// would show.
		lines := sh.podLogLines(p)
		if stdout != nil {
			_, _ = io.WriteString(stdout, strings.Join(lines, "\n")+"\n")
		}
		return 0
	}

	args := command
	if len(args) == 0 {
		args = []string{sh.shellFor()}
	}

	sandbox, err := sh.newExecSandbox(p.Name)
	if err == nil {
		defer sandbox.cleanup()
	}

	var rec *sessionLog
	if sh.cfg.RecordExecSessions {
		rec = newSessionLog(p.Namespace, p.Name, container, tty, args)
	}

	var exitCode int
	if tty {
		exitCode = sh.runPTYSession(ctx, args, sandbox, p.Name, stdin, rec.tee(stdout), resize)
	} else {
		exitCode = sh.runPipeSession(ctx, args, sandbox, p.Name, stdin, rec.tee(stdout), rec.tee(stderr))
	}
	rec.done(exitCode)
	return exitCode
}

// buildExecCmd builds the exec command for one session: an isolated,
// re-exec'd command in its own namespaces when spec.execIsolation is on, or a
// plain command (with the hostname/uname shadow applied) otherwise.
func (sh *Shim) buildExecCmd(ctx context.Context, args []string, sandbox execSandbox, podName string) *exec.Cmd {
	if sh.cfg.ExecIsolation {
		return sh.isolatedCmd(ctx, args, sandbox, podName)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = sandbox.env
	sandbox.applyOverride(cmd, args[0])
	return cmd
}

// runPTYSession runs a real interactive session under a pseudo-terminal, so
// the real shell (not this code) handles line editing, history, and
// signals (Ctrl-C/Ctrl-D) exactly like a real container would.
func (sh *Shim) runPTYSession(ctx context.Context, args []string, sandbox execSandbox, podName string, stdin io.Reader, stdout io.Writer, resize httpstream.Stream) int {
	cmd := sh.buildExecCmd(ctx, args, sandbox, podName)

	f, err := pty.Start(cmd)
	if err != nil {
		if stdout != nil {
			_, _ = io.WriteString(stdout, fmt.Sprintf("%s: %s\r\n", args[0], execErrorMessage(err)))
		}
		return exitCodeFor(err)
	}
	defer f.Close()

	if resize != nil {
		go applyResizes(resize, f)
	}

	done := make(chan struct{})
	if stdin != nil {
		go func() {
			_, _ = io.Copy(f, stdin)
		}()
	}
	go func() {
		if stdout != nil {
			_, _ = io.Copy(stdout, f)
		}
		close(done)
	}()

	err = cmd.Wait()
	<-done
	return exitCodeFor(err)
}

// runPipeSession runs a real one-shot command (no tty), the shape a plain
// `kubectl exec pod -- cmd` uses.
func (sh *Shim) runPipeSession(ctx context.Context, args []string, sandbox execSandbox, podName string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := sh.buildExecCmd(ctx, args, sandbox, podName)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil && isCommandNotFound(err) && stderr != nil {
		_, _ = io.WriteString(stderr, fmt.Sprintf("%s: command not found\n", args[0]))
	}
	return exitCodeFor(err)
}

// execSandbox is the per-session real environment for an exec session: this
// container's own real env, plus a real per-target-Pod `hostname` command
// (a temp script on PATH ahead of the base image's own hostname binary) so
// `hostname`/`env`'s HOSTNAME reports the target Pod's own name, not
// kubelet-shim's own real pod name -- every exec session shares this one
// real container regardless of which decoy Pod a client thinks it's
// talking to, so without this override `hostname` would be an immediate
// tell.
type execSandbox struct {
	env       []string
	dir       string
	overrides map[string]bool // command names shadowed by a script in dir
	cleanup   func()
}

// kernelRelease/kernelVersionText are the believable kernel a decoy reports,
// matching a real Ubuntu 24.04 node (see the OSImage the shim sets on each
// Node). Used both by the `uname` shadow in an exec session and by the node's
// status.nodeInfo.kernelVersion, so the two never contradict -- and so
// neither leaks the real host node's kernel (nor, under gVisor, gVisor's own
// telltale kernel string).
const (
	kernelRelease     = "6.8.0-45-generic"
	kernelVersionText = "#45-Ubuntu SMP PREEMPT_DYNAMIC Mon Jul 15 12:00:00 UTC 2024"
)

// applyOverride points cmd at the sandbox's own shadow script instead of the
// real binary ambient PATH resolution found, when the command being run is one
// the sandbox shadows (hostname, uname). Safe to call even if newExecSandbox
// failed (overrides is then empty, so this is a no-op).
func (s execSandbox) applyOverride(cmd *exec.Cmd, name string) {
	if s.overrides[name] {
		cmd.Path = filepath.Join(s.dir, name)
	}
}

// newExecSandbox builds one exec session's real environment. The `hostname`
// override only helps a one-shot `kubectl exec pod -- hostname` (Go's
// exec.Command resolves the binary via the *ambient* PATH at construction
// time, before cmd.Env takes effect, hence applyOverride's explicit
// cmd.Path swap); a real interactive shell typing `hostname` itself
// resolves it by searching PATH at runtime, so prepending the sandbox
// directory to PATH here is what catches that case.
// The directory name is deliberately neutral. It lands at the front of
// PATH, where `env` inside an exec session prints it back to whoever is
// looking, so anything project-branded there (it used to be
// "honeypod-exec-") hands the attacker the answer the rest of this file
// works to withhold. A bare numeric temp name is what MkdirTemp produces
// with an empty prefix.
func (sh *Shim) newExecSandbox(podName string) (execSandbox, error) {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return execSandbox{env: sh.decoyExecEnv(dir, podName), cleanup: func() {}}, err
	}
	// MkdirTemp creates 0700. Under execIsolation the shim runs as root but the
	// session drops to the app uid, which then could not traverse the dir: the
	// PATH lookup would skip the shadows and fall through to the REAL uname,
	// leaking the host kernel. Nothing secret lives here (a pod name and a
	// kernel string), so make it traversable.
	_ = os.Chmod(dir, 0o755)
	overrides := map[string]bool{}
	write := func(name, body string) error {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			return err
		}
		overrides[name] = true
		return nil
	}

	// hostname -> the target pod's own name (every session shares this one
	// real container, so an un-shadowed hostname would be a tell).
	hostnameScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q\n", podName)
	// uname -> a believable kernel, so `uname -a`/`-r` never leak the real
	// host node's kernel (nor, under gVisor, gVisor's own).
	unameScript := fmt.Sprintf(`#!/bin/sh
case "$1" in
""|-s) echo Linux ;;
-r) echo %[2]q ;;
-m|-p|-i) echo x86_64 ;;
-o) echo GNU/Linux ;;
-n) echo %[1]q ;;
-v) echo %[3]q ;;
-a) echo "Linux %[1]s %[2]s %[3]s x86_64 x86_64 x86_64 GNU/Linux" ;;
*) echo Linux ;;
esac
`, podName, kernelRelease, kernelVersionText)

	if err := write("hostname", hostnameScript); err != nil {
		_ = os.RemoveAll(dir)
		return execSandbox{env: sh.decoyExecEnv("", podName), cleanup: func() {}}, err
	}
	_ = write("uname", unameScript) // best-effort; hostname is the load-bearing one

	return execSandbox{
		env:       sh.decoyExecEnv(dir, podName),
		dir:       dir,
		overrides: overrides,
		cleanup:   func() { _ = os.RemoveAll(dir) },
	}, nil
}

// decoyExecEnv builds the environment an exec session sees. It is NOT the
// shim's own os.Environ(), which would leak the real host cluster -- most
// damagingly KUBERNETES_SERVICE_HOST/PORT pointing at the real apiserver (a
// pivot, and an env/token mismatch tell). Instead its KUBERNETES_* family
// points at THIS decoy's own apiserver Service, consistent with the mounted
// decoy token. sandboxDir, when set, leads PATH so the command shadows resolve.
func (sh *Shim) decoyExecEnv(sandboxDir, podName string) []string {
	// Under the "minimal" (busybox) profile only busybox applets are on PATH,
	// so a command that busybox doesn't provide resolves to "not found" --
	// exactly like a real alpine/busybox image. Otherwise the full set.
	base := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if sh.cfg.ExecProfile == execProfileMinimal {
		base = busyboxBinDir
	}
	path := base
	if sandboxDir != "" {
		path = sandboxDir + ":" + base
	}
	env := []string{
		"PATH=" + path,
		"HOME=/root",
		"HOSTNAME=" + podName,
		"TERM=xterm",
		"KUBERNETES_SERVICE_HOST=" + sh.cfg.NodeInternalIP,
	}
	if sh.cfg.KubernetesServicePort > 0 {
		port := strconv.Itoa(int(sh.cfg.KubernetesServicePort))
		tcpAddr := fmt.Sprintf("tcp://%s:%s", sh.cfg.NodeInternalIP, port)
		env = append(env,
			"KUBERNETES_SERVICE_PORT="+port,
			"KUBERNETES_SERVICE_PORT_HTTPS="+port,
			"KUBERNETES_PORT="+tcpAddr,
			"KUBERNETES_PORT_"+port+"_TCP="+tcpAddr,
			"KUBERNETES_PORT_"+port+"_TCP_PROTO=tcp",
			"KUBERNETES_PORT_"+port+"_TCP_PORT="+port,
			"KUBERNETES_PORT_"+port+"_TCP_ADDR="+sh.cfg.NodeInternalIP,
		)
	}
	return env
}

// applyResizes reads TerminalSize messages off the resize stream and
// applies them to the pty, so a real terminal client resizing its window
// actually reflows the real shell's output.
func applyResizes(resize httpstream.Stream, f *os.File) {
	dec := json.NewDecoder(resize)
	for {
		var size terminalSize
		if err := dec.Decode(&size); err != nil {
			return
		}
		_ = pty.Setsize(f, &pty.Winsize{Rows: size.Height, Cols: size.Width})
	}
}

// exitCodeFor extracts a real process exit code, defaulting to 0 for a nil
// error (success) and 127 for "no such file" (command not found), matching
// a real shell's own convention.
func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if isCommandNotFound(err) {
		return 127
	}
	return 1
}

// isCommandNotFound reports whether err is the requested binary not
// existing at all (exec.Error, from PATH lookup) or not being runnable
// (os.PathError, e.g. permission denied/not a file) -- as opposed to the
// command running and exiting non-zero.
func isCommandNotFound(err error) bool {
	var execErr *exec.Error
	var pathErr *os.PathError
	return errors.As(err, &execErr) || errors.As(err, &pathErr)
}

// execErrorMessage renders the same "command not found" text a real shell
// prints, rather than a raw Go error, when the requested binary doesn't
// exist in this sandbox.
func execErrorMessage(err error) string {
	if isCommandNotFound(err) {
		return "command not found"
	}
	return err.Error()
}

// podLogLines recovers the FakePod's LogLines from the in-memory map
// populated at seed time (see setLogLines in kubeletshim.go) -- kept out of
// the served Pod object's own annotations, which anyone with the decoy
// token can read back verbatim.
//
// When no logLines were configured, this fabricates one plausible startup
// line from the pod's own (also fabricated) container image string rather
// than a generic "no output produced" -- still zero real execution or
// network access, just a slightly less obviously-empty default. logLines,
// when set, always wins; the image-derived line is only the fallback.
func (sh *Shim) podLogLines(p corev1.Pod) []string {
	if lines, ok := sh.getLogLines(p.Namespace, p.Name); ok && len(lines) > 0 {
		return lines
	}
	if len(p.Spec.Containers) > 0 && p.Spec.Containers[0].Image != "" {
		return []string{fmt.Sprintf("Starting %s...", p.Spec.Containers[0].Image)}
	}
	return []string{fmt.Sprintf("%s: no output produced", p.Name)}
}

// handleLogs serves the kubelet's /containerLogs/{ns}/{pod}/{container}
// endpoint, which real kube-apiserver proxies `kubectl logs` to.
func (sh *Shim) handleLogs(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("ns"), r.PathValue("pod")
	p, err := sh.client.CoreV1().Pods(ns).Get(r.Context(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		w.WriteHeader(http.StatusNotFound)
		writeStatus(w, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeStatus(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	for _, l := range sh.podLogLines(*p) {
		fmt.Fprintln(w, l)
	}
}

func hasContainer(p corev1.Pod, name string) bool {
	for _, c := range p.Spec.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// writeExecStatus writes the v4-streaming-protocol completion status to the
// error stream and closes it.
func writeExecStatus(errStream httpstream.Stream, exitCode int) {
	if errStream == nil {
		return
	}
	status := metav1.Status{Status: metav1.StatusSuccess}
	if exitCode != 0 {
		status = metav1.Status{
			Status:  metav1.StatusFailure,
			Message: fmt.Sprintf("command terminated with non-zero exit code: %d", exitCode),
			Reason:  remotecommand.NonZeroExitCodeReason,
			Details: &metav1.StatusDetails{
				Causes: []metav1.StatusCause{
					{Type: remotecommand.ExitCodeCauseType, Message: strconv.Itoa(exitCode)},
				},
			},
		}
	}
	b, err := json.Marshal(status)
	if err == nil {
		_, _ = errStream.Write(b)
	}
}

// writeExecNotFound writes the exec-failure status a real container runtime
// returns when the requested binary does not exist in the image -- the
// verbatim shape `kubectl exec` surfaces for a distroless pod, so the
// error an attacker sees is indistinguishable from a genuine one.
func writeExecNotFound(errStream httpstream.Stream, cmd string) {
	if errStream == nil {
		return
	}
	// Match the real runtime error a distroless pod returns verbatim, as an
	// InternalError status (not a non-zero-exit one) so kubectl renders it as
	// "error: Internal error occurred: ... executable file not found in
	// $PATH", exactly like a genuine distroless exec -- not "command
	// terminated with exit code N", which no shell-less image produces.
	msg := fmt.Sprintf("error executing command in container: failed to exec in container: failed to start exec: OCI runtime exec failed: exec failed: unable to start container process: exec: %q: executable file not found in $PATH: unknown", cmd)
	status := metav1.Status{
		Status:  metav1.StatusFailure,
		Message: msg,
		Reason:  metav1.StatusReasonInternalError,
	}
	if b, err := json.Marshal(status); err == nil {
		_, _ = errStream.Write(b)
	}
}

func writeStatus(w http.ResponseWriter, code int, reason, message string) {
	w.Header().Set("Content-Type", "application/json")
	st := metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   "Failure",
		Message:  message,
		Reason:   metav1.StatusReason(reason),
		Code:     int32(code),
	}
	if st.Message == "" {
		st.Message = reason
	}
	_ = json.NewEncoder(w).Encode(st)
}
