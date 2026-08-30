package kubeletshim

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"honeypod.io/honeypod/internal/seed"
)

// forbiddenIdentityStrings are the project-identifying substrings that must
// never reach anything an attacker inside a decoy can read -- a response body,
// an environment variable, a path. Shared by this package's leak guards so a
// new word only has to be added once. internal/controller keeps its own copy
// for the manifest-shaped surfaces it checks; the two are deliberately
// separate packages, not one list imported across a package boundary that
// exists for other reasons.
var forbiddenIdentityStrings = []string{"honeypod", "decoy", "honeypot", "fake"}

// TestHandlePortForward_NoIdentityLeak guards the port-forward "not
// implemented" response: it used to say "this decoy does not implement
// port-forward", naming this as a decoy in its own message text. It
// answers with the same error a real kubelet gives for a missing socat
// helper now; this checks no project-identifying word ever comes back.
func TestHandlePortForward_NoIdentityLeak(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/portForward/billing/checkout-api", nil)
	handlePortForward(rec, req)

	body := strings.ToLower(rec.Body.String())
	for _, bad := range forbiddenIdentityStrings {
		if strings.Contains(body, bad) {
			t.Fatalf("port-forward response contains the identifying substring %q: %s", bad, rec.Body.String())
		}
	}
}

// TestWriteServiceAccountFiles_MatchesRealAutomountLayout covers the on-disk
// shape a real automounted ServiceAccount has: the leaf names are symlinks
// into a ..data dir, not plain files, so `ls -la` inside an exec session is
// indistinguishable from a real mount. A second call (a container restart,
// or the init container having already written it) is a safe no-op that
// leaves the layout in place.
func TestWriteServiceAccountFiles_MatchesRealAutomountLayout(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{ServiceAccountDir: dir, ServiceAccountToken: "the-token", Namespace: "billing", CABundlePath: ""}

	if err := writeServiceAccountFiles(cfg); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// ..data must be a symlink, and each leaf a symlink into it.
	dataInfo, err := os.Lstat(filepath.Join(dir, "..data"))
	if err != nil || dataInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("..data must be a symlink like a real mount, got %v (%v)", dataInfo, err)
	}
	for _, leaf := range []string{"token", "namespace"} {
		info, err := os.Lstat(filepath.Join(dir, leaf))
		if err != nil {
			t.Fatalf("lstat %s: %v", leaf, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s must be a symlink into ..data, not a plain file", leaf)
		}
	}

	// Contents resolve correctly through the symlink chain.
	got, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil || string(got) != "the-token" {
		t.Fatalf("token should resolve to the content through ..data, got %q (%v)", got, err)
	}

	// A second call is a no-op (layout already present) and must not error.
	if err := writeServiceAccountFiles(cfg); err != nil {
		t.Fatalf("second call must be a safe no-op, got: %v", err)
	}
}

// TestReloadSeed_PicksUpChangesAndSurvivesBadFiles covers the mechanism
// that lets a pod join a decoy without restarting it: the operator rewrites
// seed.json in the mounted ConfigMap, and the shim re-reads it on every
// heartbeat rather than only at startup.
func TestReloadSeed_PicksUpChangesAndSurvivesBadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.json")

	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("writing seed: %v", err)
		}
	}
	write(`{"fakeNodes":[{"name":"node-1"}],"fakePods":[{"name":"first","namespace":"web","containers":[]}]}`)

	first, err := seed.Load(path)
	if err != nil {
		t.Fatalf("loading seed: %v", err)
	}
	sh := &Shim{cfg: Config{Seed: first, SeedPath: path}}

	if got := sh.currentSeed().FakePods[0].Name; got != "first" {
		t.Fatalf("expected the initial seed, got %q", got)
	}

	// The operator adds a joined pod.
	write(`{"fakeNodes":[{"name":"node-1"}],"fakePods":[{"name":"first","namespace":"web","containers":[]},{"name":"late-joiner","namespace":"web","containers":[]}]}`)
	sh.reloadSeed()
	if n := len(sh.currentSeed().FakePods); n != 2 {
		t.Fatalf("expected the reload to pick up the joined pod, got %d pods", n)
	}

	// A truncated or half-written file must not wipe what is already
	// serving: kubelet replaces the ConfigMap volume underneath us.
	write(`{"fakePods":[{"name":`)
	sh.reloadSeed()
	if n := len(sh.currentSeed().FakePods); n != 2 {
		t.Fatalf("an unparseable seed must leave the previous one in place, got %d pods", n)
	}
}

// TestPodStatus_NoDescribeLevelTells covers the fields kubectl describe
// exposes: an empty HostIP renders as "Node: <name>/" and empty
// ContainerID/ImageID mark a pod as never actually run. All must be
// populated so a fake pod survives a describe.
func TestPodStatus_NoDescribeLevelTells(t *testing.T) {
	started := true
	statuses := []corev1.ContainerStatus{{
		Name: "app", Image: "nginx:1", Ready: true, Started: &started,
		ContainerID: fakeContainerID("nginx-abc", "app"),
		ImageID:     fakeImageID("nginx:1"),
	}}
	st := podStatus(metav1.Now(), "nginx-abc", "worker-1", "10.0.5.6", statuses, false)

	if st.HostIP != "10.0.5.6" {
		t.Fatalf("HostIP must be the node address, got %q", st.HostIP)
	}
	if st.PodIP == "" || len(st.PodIPs) == 0 || st.PodIPs[0].IP != st.PodIP {
		t.Fatalf("PodIP/PodIPs must be set and consistent, got %q / %+v", st.PodIP, st.PodIPs)
	}
	// A host-networked pod must report podIP == hostIP (the node's address).
	hn := podStatus(metav1.Now(), "etcd-worker-1", "worker-1", "10.0.5.6", statuses, true)
	if hn.PodIP != "10.0.5.6" {
		t.Fatalf("host-network pod must report podIP == hostIP, got %q", hn.PodIP)
	}

	cs := st.ContainerStatuses[0]
	if !strings.HasPrefix(cs.ContainerID, "containerd://") || len(cs.ContainerID) < 20 {
		t.Fatalf("ContainerID must look like a real containerd id, got %q", cs.ContainerID)
	}
	if !strings.Contains(cs.ImageID, "@sha256:") {
		t.Fatalf("ImageID must look real, got %q", cs.ImageID)
	}
	// Deterministic across re-seeds (a real container id is stable until restart).
	if fakeContainerID("nginx-abc", "app") != cs.ContainerID {
		t.Fatal("fakeContainerID must be deterministic")
	}
}

// TestPodStartTime_AnchoredToCreation proves the reported start/uptime is the
// pod's own immutable creationTimestamp, not a fresh "now" each heartbeat --
// so a decoy that has been up an hour shows pods that have been up an hour,
// not "0s ago" perpetually.
func TestPodStartTime_AnchoredToCreation(t *testing.T) {
	created := metav1.NewTime(time.Now().Add(-3 * time.Hour).Truncate(time.Second))
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", CreationTimestamp: created}}
	if got := podStartTime(p); !got.Equal(&created) {
		t.Fatalf("podStartTime must equal creationTimestamp, got %v want %v", got, created)
	}

	// podStatus and the container statuses must carry that same anchored time,
	// not now.
	statuses := runningContainerStatuses("p", []corev1.Container{{Name: "app", Image: "nginx:1"}}, podStartTime(p))
	st := podStatus(podStartTime(p), "p", "n", "10.0.0.9", statuses, false)
	if st.StartTime == nil || !st.StartTime.Equal(&created) {
		t.Fatalf("pod StartTime must be the creation time, got %v", st.StartTime)
	}
	if len(st.Conditions) == 0 || !st.Conditions[0].LastTransitionTime.Equal(&created) {
		t.Fatalf("Ready condition transition must be the creation time, got %+v", st.Conditions)
	}
	if st.ContainerStatuses[0].State.Running == nil || !st.ContainerStatuses[0].State.Running.StartedAt.Equal(&created) {
		t.Fatalf("container StartedAt must be the creation time, got %+v", st.ContainerStatuses[0].State)
	}
}

// TestStableRestartCount proves restart counts are deterministic per
// pod/container (stable across heartbeats), not all-zero, and stay low.
func TestStableRestartCount(t *testing.T) {
	a := stableRestartCount("web-1", "app")
	if a != stableRestartCount("web-1", "app") {
		t.Fatal("restart count must be stable for the same pod/container")
	}
	sawNonZero := false
	for i := 0; i < 50; i++ {
		n := stableRestartCount(fmt.Sprintf("pod-%d", i), "c")
		if n < 0 || n > 2 {
			t.Fatalf("restart count out of expected range: %d", n)
		}
		if n > 0 {
			sawNonZero = true
		}
	}
	if !sawNonZero {
		t.Fatal("expected some containers to report a nonzero restart count across a sample")
	}
}

// TestStripNotReadyTaints proves the shim clears the not-ready/unreachable
// NoSchedule taints (so the real scheduler will place attacker/coredns pods)
// while leaving any other taint intact.
func TestStripNotReadyTaints(t *testing.T) {
	in := []corev1.Taint{
		{Key: "node.kubernetes.io/not-ready", Effect: corev1.TaintEffectNoSchedule},
		{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule},
		{Key: "node.kubernetes.io/unreachable", Effect: corev1.TaintEffectNoExecute},
	}
	out := stripNotReadyTaints(in)
	if len(out) != 1 || out[0].Key != "dedicated" {
		t.Fatalf("expected only the non-lifecycle taint to remain, got %+v", out)
	}
	if len(stripNotReadyTaints(nil)) != 0 {
		t.Fatal("nil taints must stay empty")
	}
}

// TestFakePodIP_UniquePerPod covers a fingerprint that took one command to
// spot: the pod IP used to be derived from the node name alone, so every
// pod scheduled on a node reported the *same* address and `kubectl get pods
// -A -o wide` listed several pods sharing one IP. A real cluster cannot
// produce that. Pods on one node must land in that node's /24 and differ
// from each other; the same pod must keep its address across heartbeats.
func TestFakePodIP_UniquePerPod(t *testing.T) {
	const node = "decoy-node-1"
	names := []string{"coredns-65bcb899d8-5sbms", "coredns-65bcb899d8-gpdp4", "httpbin", "checkout-api"}

	seen := map[string]string{}
	for _, n := range names {
		ip := fakePodIP(node, n)
		if prev, dup := seen[ip]; dup {
			t.Fatalf("pods %q and %q both report %s -- two pods sharing an IP is not something a real cluster does", prev, n, ip)
		}
		seen[ip] = n
		if ip != fakePodIP(node, n) {
			t.Fatalf("pod %q got an unstable IP; a pod's address changing under a watching attacker is its own tell", n)
		}
	}

	// Pods on different nodes belong to different per-node /24s, the way a
	// real cluster hands each node its own pod CIDR.
	a := fakePodIP("node-a", "same-name")
	b := fakePodIP("node-b", "same-name")
	if a == b {
		t.Fatalf("the same pod name on two nodes got the same IP (%s)", a)
	}
}

// TestFakeNodeIdentity_Populated covers the machine-identity fields every
// real kubelet fills in from the host. Left at their zero values they render
// as machineID: "" / systemUUID: "" / bootID: "" under `kubectl get node -o
// yaml`, which no real node shows.
func TestFakeNodeIdentity_Populated(t *testing.T) {
	const node = "decoy-node-1"

	machine := fakeMachineID(node)
	if len(machine) != 32 {
		t.Fatalf("machineID should be 32 hex characters like a real /etc/machine-id, got %q", machine)
	}
	if strings.Contains(machine, "-") {
		t.Fatalf("a real machineID carries no dashes, got %q", machine)
	}
	for _, u := range []string{fakeSystemUUID(node), fakeBootID(node)} {
		if len(u) != 36 || strings.Count(u, "-") != 4 {
			t.Fatalf("expected a dashed UUID, got %q", u)
		}
	}
	if fakeSystemUUID(node) == fakeBootID(node) {
		t.Fatal("systemUUID and bootID should not be the same value")
	}
	// Stable across heartbeats: a machine's identity does not change.
	if fakeMachineID(node) != machine {
		t.Fatal("machineID is not stable for a given node")
	}
	if fakeMachineID("other-node") == machine {
		t.Fatal("two different nodes report the same machineID")
	}
}
