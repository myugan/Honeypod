package kubeletshim

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestDecoyExecEnv_NoHostLeak proves an exec session's environment points at
// THIS decoy's own apiserver, not the real host cluster, and does not inherit
// the shim process's own os.Environ() (which would leak the real
// KUBERNETES_SERVICE_HOST and any operator-injected vars). This is both a
// fingerprinting fix and a pivot-prevention one.
func TestDecoyExecEnv_NoHostLeak(t *testing.T) {
	// A value only present in the real process env must never appear.
	t.Setenv("HONEYPOD_SECRET_MARKER", "leak-me")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1") // pretend real cluster

	k := &Shim{cfg: Config{NodeInternalIP: "10.96.7.7", KubernetesServicePort: 6443}}
	env := k.decoyExecEnv("/tmp/sbox", "checkout-api-xyz")

	m := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	if _, leaked := m["HONEYPOD_SECRET_MARKER"]; leaked {
		t.Error("exec env leaked a variable from the shim's own os.Environ()")
	}
	if m["KUBERNETES_SERVICE_HOST"] != "10.96.7.7" {
		t.Errorf("KUBERNETES_SERVICE_HOST must point at the decoy (10.96.7.7), got %q", m["KUBERNETES_SERVICE_HOST"])
	}
	if m["KUBERNETES_SERVICE_PORT"] != "6443" {
		t.Errorf("KUBERNETES_SERVICE_PORT must be the decoy port 6443, got %q", m["KUBERNETES_SERVICE_PORT"])
	}
	if m["HOSTNAME"] != "checkout-api-xyz" {
		t.Errorf("HOSTNAME must be the target pod name, got %q", m["HOSTNAME"])
	}
	if !strings.HasPrefix(m["PATH"], "/tmp/sbox:") {
		t.Errorf("sandbox dir must lead PATH, got %q", m["PATH"])
	}
}

// TestExecProfile_Selection proves the exec environment follows the
// configured profile: the shell binary and the PATH change between the full
// "shell" profile and the busybox "minimal" one.
func TestExecProfile_Selection(t *testing.T) {
	shellSh := (&Shim{cfg: Config{ExecProfile: "shell"}}).shellFor()
	if shellSh != "/bin/sh" {
		t.Errorf("shell profile must use /bin/sh, got %q", shellSh)
	}
	minSh := (&Shim{cfg: Config{ExecProfile: "minimal"}}).shellFor()
	if minSh != busyboxShellPath {
		t.Errorf("minimal profile must use the busybox shell, got %q", minSh)
	}

	// PATH under minimal contains only the busybox applet dir (plus the
	// per-session sandbox dir); the full profile keeps the standard dirs.
	minEnv := (&Shim{cfg: Config{ExecProfile: "minimal", NodeInternalIP: "10.0.0.1"}}).decoyExecEnv("/tmp/s", "p")
	var minPath string
	for _, kv := range minEnv {
		if strings.HasPrefix(kv, "PATH=") {
			minPath = kv
		}
	}
	if !strings.Contains(minPath, busyboxBinDir) || strings.Contains(minPath, "/usr/bin") {
		t.Errorf("minimal PATH must be busybox-only, got %q", minPath)
	}
}

// TestRunPipeSession_RealCommand covers a real (non-tty) exec session end
// to end: a real process actually runs, real stdout/exit code come back,
// and a nonexistent binary gets a real shell's "not found"/127, the same
// shape as before but for real now instead of a canned string.
func TestRunPipeSession_RealCommand(t *testing.T) {
	k := &Shim{cfg: Config{NodeInternalIP: "10.96.9.9", KubernetesServicePort: 6443}}
	ctx := context.Background()
	sandbox, err := k.newExecSandbox("test-pod-name")
	if err != nil {
		t.Fatalf("newExecSandbox: %v", err)
	}
	defer sandbox.cleanup()

	t.Run("real command runs for real", func(t *testing.T) {
		var out bytes.Buffer
		code := k.runPipeSession(ctx, []string{"echo", "hello", "world"}, sandbox, "test-pod-name", nil, &out, nil)
		if code != 0 || strings.TrimSpace(out.String()) != "hello world" {
			t.Fatalf("echo: got out=%q code=%d", out.String(), code)
		}
	})

	t.Run("exit code passes through for real", func(t *testing.T) {
		code := k.runPipeSession(ctx, []string{"sh", "-c", "exit 7"}, sandbox, "test-pod-name", nil, nil, nil)
		if code != 7 {
			t.Fatalf("expected exit 7, got %d", code)
		}
	})

	t.Run("unknown binary is not found, exit 127", func(t *testing.T) {
		var stderr bytes.Buffer
		code := k.runPipeSession(ctx, []string{"definitely-not-a-real-binary"}, sandbox, "test-pod-name", nil, nil, &stderr)
		if code != 127 {
			t.Fatalf("expected exit 127, got %d (stderr=%q)", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "not found") {
			t.Fatalf("expected a \"not found\" message, got %q", stderr.String())
		}
	})

	t.Run("hostname is overridden to the target pod's own name", func(t *testing.T) {
		var out bytes.Buffer
		code := k.runPipeSession(ctx, []string{"hostname"}, sandbox, "test-pod-name", nil, &out, nil)
		if code != 0 || strings.TrimSpace(out.String()) != "test-pod-name" {
			t.Fatalf("hostname: expected \"test-pod-name\", got out=%q code=%d", out.String(), code)
		}
	})

	t.Run("hostname is overridden inside a real shell too (PATH search)", func(t *testing.T) {
		var out bytes.Buffer
		code := k.runPipeSession(ctx, []string{"sh", "-c", "hostname"}, sandbox, "test-pod-name", nil, &out, nil)
		if code != 0 || strings.TrimSpace(out.String()) != "test-pod-name" {
			t.Fatalf("sh -c hostname: expected \"test-pod-name\", got out=%q code=%d", out.String(), code)
		}
	})

	t.Run("uname is shadowed to a believable kernel, not the host's", func(t *testing.T) {
		var out bytes.Buffer
		code := k.runPipeSession(ctx, []string{"uname", "-r"}, sandbox, "test-pod-name", nil, &out, nil)
		if code != 0 || strings.TrimSpace(out.String()) != kernelRelease {
			t.Fatalf("uname -r: expected %q, got out=%q code=%d", kernelRelease, out.String(), code)
		}
	})
}

// TestPodLogLines_Fallback covers the three-way precedence: explicit
// logLines (set via setLogLines, not a served annotation -- see its doc
// comment) always wins; absent that, fall back to a fabricated line
// derived from the pod's own (also fabricated) container image, never real
// output; absent even an image, fall back to the generic message.
func TestPodLogLines_Fallback(t *testing.T) {
	k := &Shim{logLines: map[string][]string{}}

	t.Run("explicit logLines wins", func(t *testing.T) {
		lines := []string{"2026-08-25T00:00:00Z INFO listening on :8080"}
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "checkout-api-abc"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "checkout-api:1.4.2"}}},
		}
		k.setLogLines(p.Namespace, p.Name, lines)
		got := k.podLogLines(p)
		if !reflect.DeepEqual(got, lines) {
			t.Fatalf("expected explicit logLines %v, got %v", lines, got)
		}
	})

	t.Run("falls back to image-derived line when logLines unset", func(t *testing.T) {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "payments-worker-def"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "internal-registry.zeno.local/checkout-api:1.4.2"}}},
		}
		got := k.podLogLines(p)
		want := []string{"Starting internal-registry.zeno.local/checkout-api:1.4.2..."}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("expected image-derived fallback %v, got %v", want, got)
		}
	})

	t.Run("falls back to generic message with no logLines and no containers", func(t *testing.T) {
		p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "no-image-worker-ghi"}}
		got := k.podLogLines(p)
		want := []string{"no-image-worker-ghi: no output produced"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("expected generic fallback %v, got %v", want, got)
		}
	})
}

// TestNewExecSandbox_NoIdentityLeak guards the environment an exec session
// hands back to whoever is inside it. The sandbox dir goes to the front of
// PATH so an interactive shell's own `hostname` lookup finds the override,
// which means `env` (or `echo $PATH`) inside the session prints that path
// straight back to an attacker. It used to be named "honeypod-exec-*",
// naming the trap in the one place the rest of exec.go works hardest to
// keep quiet.
func TestNewExecSandbox_NoIdentityLeak(t *testing.T) {
	k := &Shim{}
	sandbox, err := k.newExecSandbox("checkout-api")
	if err != nil {
		t.Fatalf("building sandbox: %v", err)
	}
	defer sandbox.cleanup()

	var pathVar string
	for _, kv := range sandbox.env {
		if strings.HasPrefix(kv, "PATH=") {
			pathVar = kv
		}
	}
	if pathVar == "" {
		t.Fatal("expected the sandbox to export a PATH")
	}
	if !strings.Contains(pathVar, sandbox.dir) {
		t.Fatalf("expected the shadow dir on PATH, got %q", pathVar)
	}
	for _, bad := range append(forbiddenIdentityStrings, "shim") {
		if strings.Contains(strings.ToLower(pathVar), bad) {
			t.Fatalf("PATH contains the identifying substring %q: %s", bad, pathVar)
		}
		if strings.Contains(strings.ToLower(sandbox.dir), bad) {
			t.Fatalf("the shadow dir contains the identifying substring %q: %s", bad, sandbox.dir)
		}
	}
}

// TestContainerLacksShell covers the single most conclusive fingerprint a
// decoy could hand over: every kube-system pod a decoy seeds runs an
// upstream control-plane image, and all of those are distroless. Serving
// them the same real Debian shell every other pod gets made `kubectl exec
// etcd-<node> -n kube-system -- sh` succeed, which no real cluster can do.
// The check is on the image, not on anything in the seed, because the
// coredns pods are created by the decoy's own kube-controller-manager and
// never pass through the seed at all.
func TestContainerLacksShell(t *testing.T) {
	pod := func(container, image string) corev1.Pod {
		return corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: container, Image: image}}}}
	}

	shellLess := []string{
		"registry.k8s.io/etcd:3.5.16-0",
		"registry.k8s.io/kube-apiserver:v1.35.0",
		"registry.k8s.io/kube-controller-manager:v1.35.0",
		"registry.k8s.io/kube-scheduler:v1.35.0",
		"registry.k8s.io/coredns/coredns:v1.11.3",
	}
	for _, img := range shellLess {
		p := pod("c", img)
		if !containerLacksShell(p, "c") {
			t.Fatalf("%s is distroless upstream; an exec into it must fail the way the real runtime fails it", img)
		}
		// An unnamed container means the pod's first, as handleStream defaults it.
		if !containerLacksShell(p, "") {
			t.Fatalf("%s not detected when the container is left unnamed", img)
		}
	}

	// Images that really do carry a shell must keep the real exec session --
	// kube-proxy's upstream image is Debian-based, and a user's own fakePods
	// are ordinary application images.
	withShell := []string{
		"registry.k8s.io/kube-proxy:v1.35.0",
		"kennethreitz/httpbin:latest",
		"nginx:1.27",
	}
	for _, img := range withShell {
		if containerLacksShell(pod("c", img), "c") {
			t.Fatalf("%s has a real shell; refusing the exec would itself be the anomaly", img)
		}
	}

	// The targeted container is what matters, not merely some container.
	multi := corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "nginx:1.27"},
		{Name: "sidecar", Image: "registry.k8s.io/pause:3.10"},
	}}}
	if containerLacksShell(multi, "app") {
		t.Fatal("the shell-bearing container was judged by another container's image")
	}
	if !containerLacksShell(multi, "sidecar") {
		t.Fatal("the distroless sidecar was not detected")
	}
}
