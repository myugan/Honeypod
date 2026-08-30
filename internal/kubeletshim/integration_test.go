package kubeletshim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/certs"
	"honeypod.io/honeypod/internal/seed"
)

// This file proves kubelet-shim's seeding and kubelet-endpoint logic against
// real, locally-running kine and kube-apiserver subprocesses -- not a
// mocked client-go client, and not envtest (which stands in for the
// *outer* apiserver the operator itself talks to; this proves the *inner*
// control plane a Decoy deploys as a pod). This mirrors exactly the
// manual verification this feature was built against: kine and
// kube-apiserver started as real OS processes, a real client-go client
// (via kubeletshim.New) driving them, and -- for TestKubeletShimExecAndLogs_RealAPIServerProxy
// -- a real kubectl binary completing the full round trip through the
// real apiserver's own kubelet-client proxy to kubelet-shim's HTTPS
// server, exactly the path a real Decoy's inner control plane takes in
// production.
//
// Both binaries are expected at $HOME/go/bin/{kine,kube-apiserver} (where
// this environment keeps them for local reference, per the project's own
// setup) as well as PATH; the test is skipped, not failed, if either is
// missing so `go test ./...` stays runnable in an environment without them.

func findBinary(t *testing.T, name string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, "go", "bin", name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	t.Skipf("%s not found on PATH or ~/go/bin; skipping real-subprocess integration test", name)
	return ""
}

// waitForKubeletTLS waits until the kubelet-shim HTTPS server's TLS
// handshake actually succeeds against the given CA -- waitForPort alone
// only proves the TCP listener is open, which can briefly precede the TLS
// config being fully installed.
func waitForKubeletTLS(t *testing.T, port int, caFile string) {
	t.Helper()
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := mustCertPool(t, caPEM)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{RootCAs: pool})
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for kubelet-shim TLS server on port %d", port)
}

func mustCertPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CA cert")
	}
	return pool
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to accept connections", addr)
}

// innerTestCluster starts real kine + kube-apiserver subprocesses backing
// one throwaway inner control plane, returns a rest.Config authenticated
// with a fixed decoy token, and registers cleanup.
type innerTestCluster struct {
	dir        string
	restConfig *rest.Config
	token      string
	caFile     string
	tlsCert    string
	tlsKey     string
}

func startInnerTestCluster(t *testing.T) *innerTestCluster {
	t.Helper()
	// These spin up a real kube-apiserver + kine subprocess -- the slowest
	// tests in the repo. `go test -short` skips them for a fast unit-only
	// loop; CI runs the full set without -short.
	if testing.Short() {
		t.Skip("skipping real-apiserver integration test in -short mode")
	}
	kinePath := findBinary(t, "kine")
	apiserverPath := findBinary(t, "kube-apiserver")

	dir := t.TempDir()
	const token = "it-test-token-abc123"

	caCert, caKey, err := certs.GenerateCA("it-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	leafCert, leafKey, err := certs.IssueServerCert(caCert, caKey, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	saPub, saKey, err := certs.GenerateServiceAccountSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caFile := write("ca.crt", caCert)
	tlsCertFile := write("tls.crt", leafCert)
	tlsKeyFile := write("tls.key", leafKey)
	saPubFile := write("sa.pub", saPub)
	saKeyFile := write("sa.key", saKey)
	// system:masters, matching render.go's real decoyGroups: bypasses the
	// RBAC authorizer entirely, same as production, now that this test
	// runs the real kube-apiserver subprocess with --authorization-mode=RBAC.
	tokenAuthFile := write("token-auth.csv", []byte(fmt.Sprintf("%s,honeypod:decoy,decoy,\"system:masters\"\n", token)))

	// Ports chosen to (very likely) avoid colliding with anything else
	// on the machine; the tests below don't run in parallel with each
	// other so a fixed offset per-cluster isn't needed.
	kineAddr := "127.0.0.1:23790"
	apiserverPort := "28443"

	kineCmd := exec.Command(kinePath,
		"--endpoint=sqlite://"+filepath.Join(dir, "kine.db"),
		"--listen-address="+kineAddr,
		"--metrics-bind-address=0",
	)
	kineCmd.Dir = dir
	kineOut := &bytes.Buffer{}
	kineCmd.Stdout, kineCmd.Stderr = kineOut, kineOut
	if err := kineCmd.Start(); err != nil {
		t.Fatalf("starting kine: %v", err)
	}
	t.Cleanup(func() {
		_ = kineCmd.Process.Kill()
		_ = kineCmd.Wait()
	})
	waitForPort(t, kineAddr, 10*time.Second)

	apiserverCmd := exec.Command(apiserverPath,
		"--etcd-servers=http://"+kineAddr,
		"--secure-port="+apiserverPort,
		"--bind-address=127.0.0.1",
		"--tls-cert-file="+tlsCertFile,
		"--tls-private-key-file="+tlsKeyFile,
		"--token-auth-file="+tokenAuthFile,
		"--authorization-mode=RBAC",
		"--disable-admission-plugins=ServiceAccount",
		"--service-cluster-ip-range=10.97.0.0/16",
		"--service-account-issuer=https://kubernetes.default.svc.cluster.local",
		"--service-account-key-file="+saPubFile,
		"--service-account-signing-key-file="+saKeyFile,
		"--kubelet-preferred-address-types=InternalIP",
		"--kubelet-certificate-authority="+caFile,
	)
	apiserverCmd.Dir = dir
	apiserverOut := &bytes.Buffer{}
	apiserverCmd.Stdout, apiserverCmd.Stderr = apiserverOut, apiserverOut
	if err := apiserverCmd.Start(); err != nil {
		t.Fatalf("starting kube-apiserver: %v", err)
	}
	t.Cleanup(func() {
		_ = apiserverCmd.Process.Kill()
		_ = apiserverCmd.Wait()
		if t.Failed() {
			t.Logf("kine output:\n%s", kineOut.String())
			t.Logf("kube-apiserver output:\n%s", apiserverOut.String())
		}
	})
	waitForPort(t, "127.0.0.1:"+apiserverPort, 30*time.Second)

	restConfig := &rest.Config{
		Host:        "https://127.0.0.1:" + apiserverPort,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: caFile,
		},
	}

	// Give the apiserver's readiness a moment past port-open (it accepts
	// TCP connections slightly before /readyz is fully green); a real
	// client-go List with retries handles the rest, but a short sleep
	// here avoids flaking on the very first request.
	deadline := time.Now().Add(20 * time.Second)
	for {
		k, err := New(Config{RestConfig: restConfig, Seed: &seed.Seed{}, NodeInternalIP: "127.0.0.1", KubeletPort: 1, ServiceAccountToken: token})
		if err == nil && k.APIServerReachable(context.Background()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("inner apiserver never became reachable")
		}
		time.Sleep(300 * time.Millisecond)
	}

	return &innerTestCluster{dir: dir, restConfig: restConfig, token: token, caFile: caFile, tlsCert: tlsCertFile, tlsKey: tlsKeyFile}
}

func testSeed() *seed.Seed {
	return &seed.Seed{
		FakeNodes: []v1alpha1.FakeNode{{Name: "decoy-node-1", KubeletVersion: "v1.31.0"}},
		FakePods: []seed.Pod{{FakePod: v1alpha1.FakePod{
			Name: "checkout-api", Namespace: "billing", Replicas: 2,
			Containers: []v1alpha1.FakeContainer{{Name: "app", Image: "checkout-api:1.4.2"}},
			LogLines:   []string{"2026-08-25T00:00:00Z INFO listening on :8080", "2026-08-25T00:00:01Z INFO GET /healthz 200"},
		}}},
		FakeSecrets: []v1alpha1.FakeSecret{{
			Name: "checkout-api-db-credentials", Namespace: "billing",
			Data: map[string]string{"password": "hunter2-decoy"},
		}},
	}
}

// TestKubeletShimSeed_RealAPIServer proves Seed() against a real,
// locally-running kine+kube-apiserver produces real Node/Namespace/Pod/
// Secret objects with the shape kubelet-shim promises: explicit Ready
// condition, InternalIP pinned to NodeInternalIP, Pods Running with the
// log-lines annotation set, and is idempotent (calling it twice doesn't
// duplicate anything -- RunHeartbeat relies on this).
func TestKubeletShimSeed_RealAPIServer(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	k, err := New(Config{RestConfig: cluster.restConfig, Seed: testSeed(), NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("first seed failed: %v", err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("second (idempotent) seed failed: %v", err)
	}

	node, err := k.client.CoreV1().Nodes().Get(ctx, "decoy-node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting seeded node: %v", err)
	}
	foundReady, foundIP := false, false
	for _, c := range node.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			foundReady = true
		}
	}
	for _, a := range node.Status.Addresses {
		if a.Type == "InternalIP" && a.Address == "10.99.0.5" {
			foundIP = true
		}
	}
	if !foundReady {
		t.Fatalf("expected an explicit Ready=True condition, got: %+v", node.Status.Conditions)
	}
	if !foundIP {
		t.Fatalf("expected InternalIP 10.99.0.5 (NodeInternalIP), got: %+v", node.Status.Addresses)
	}
	if node.Status.DaemonEndpoints.KubeletEndpoint.Port != 10250 {
		t.Fatalf("expected daemonEndpoints.kubeletEndpoint.port=10250, got %d", node.Status.DaemonEndpoints.KubeletEndpoint.Port)
	}

	pods, err := k.client.CoreV1().Pods("billing").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 2 {
		t.Fatalf("expected 2 pod replicas, got %d", len(pods.Items))
	}
	for _, p := range pods.Items {
		if p.Status.Phase != "Running" {
			t.Fatalf("expected pod %s Running, got %s", p.Name, p.Status.Phase)
		}
		if p.Spec.NodeName != "decoy-node-1" {
			t.Fatalf("expected pod scheduled on decoy-node-1, got %q", p.Spec.NodeName)
		}
		if lines, ok := k.getLogLines(p.Namespace, p.Name); !ok || len(lines) == 0 {
			t.Fatalf("expected log lines recorded for pod %s, got %v", p.Name, lines)
		}
		if p.Annotations["honeypod.io/log-lines"] != "" {
			t.Fatalf("expected no honeypod.io/log-lines annotation on the served pod %s -- that would leak the honeypot to anyone with the decoy token", p.Name)
		}
	}

	sec, err := k.client.CoreV1().Secrets("billing").Get(ctx, "checkout-api-db-credentials", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting seeded secret: %v", err)
	}
	if string(sec.Data["password"]) != "hunter2-decoy" {
		t.Fatalf("unexpected secret data: %+v", sec.Data)
	}
}

// TestKubeletShimSeed_RealObjects covers the "nested cluster looks alive for
// real" additions: the shim installs the seed's CRDs as genuine
// CustomResourceDefinitions (so `kubectl get crds` and the custom type both
// work), and maintains a real node Lease in kube-node-lease exactly as a
// real kubelet does. Both are created against a real inner apiserver, not a
// fake client.
func TestKubeletShimSeed_RealObjects(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	s := testSeed()
	s.CRDs = []seed.CRD{
		{Group: "cert-manager.io", Kind: "Certificate", Plural: "certificates", ShortNames: []string{"cert"}},
		{Group: "example.com", Kind: "Widget", Plural: "widgets", Scope: "Cluster", Versions: []string{"v1alpha1"}},
	}
	k, err := New(Config{RestConfig: cluster.restConfig, Seed: s, NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	// Idempotent: a re-seed must not error on the already-installed CRD or
	// the existing lease.
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("second (idempotent) seed failed: %v", err)
	}

	// CRDs installed as real objects, named <plural>.<group>, correct scope.
	cert, err := k.crdClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, "certificates.cert-manager.io", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected certificates.cert-manager.io CRD installed: %v", err)
	}
	if cert.Spec.Scope != "Namespaced" || cert.Spec.Names.Kind != "Certificate" {
		t.Fatalf("unexpected Certificate CRD shape: scope=%s kind=%s", cert.Spec.Scope, cert.Spec.Names.Kind)
	}
	widget, err := k.crdClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, "widgets.example.com", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected widgets.example.com CRD installed: %v", err)
	}
	if widget.Spec.Scope != "Cluster" {
		t.Fatalf("expected Widget CRD to be Cluster-scoped, got %s", widget.Spec.Scope)
	}
	if widget.Spec.Versions[0].Name != "v1alpha1" || !widget.Spec.Versions[0].Storage {
		t.Fatalf("expected v1alpha1 storage version, got %+v", widget.Spec.Versions)
	}

	// Node lease created in kube-node-lease, holderIdentity = node name.
	lease, err := k.client.CoordinationV1().Leases("kube-node-lease").Get(ctx, "decoy-node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected a node lease for decoy-node-1: %v", err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "decoy-node-1" {
		t.Fatalf("expected lease holderIdentity=decoy-node-1, got %v", lease.Spec.HolderIdentity)
	}
	if lease.Spec.RenewTime == nil {
		t.Fatal("expected lease renewTime to be set")
	}
	// The lease renewTime must advance on a later heartbeat pass.
	firstRenew := lease.Spec.RenewTime.Time
	time.Sleep(5 * time.Millisecond)
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("third seed (lease renew) failed: %v", err)
	}
	lease2, err := k.client.CoordinationV1().Leases("kube-node-lease").Get(ctx, "decoy-node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !lease2.Spec.RenewTime.Time.After(firstRenew) {
		t.Fatalf("expected lease renewTime to advance on re-seed: first=%v second=%v", firstRenew, lease2.Spec.RenewTime.Time)
	}
}

// TestKubeletShimSeed_StandardObjectsAndAdoption covers the anti-fingerprint
// additions: the shim seeds the standard kube-dns Service (+ EndpointSlice)
// and the kubeadm ConfigMaps, reports node images, and -- standing in for the
// real kubelet -- marks a pod that was scheduled onto a fake node (as a real
// scheduler would bind an attacker's pod) as Running instead of leaving it
// Pending.
func TestKubeletShimSeed_StandardObjectsAndAdoption(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	s := testSeed()
	s.Services = []seed.Service{{
		Name: "kube-dns", Namespace: "kube-system",
		ClusterIP:   "10.96.0.10",
		Selector:    map[string]string{"k8s-app": "kube-dns"},
		Ports:       []seed.ServicePort{{Name: "dns", Port: 53, TargetPort: 53, Protocol: "UDP"}},
		EndpointIPs: []string{"10.244.0.2", "10.244.0.3"},
	}}
	s.ConfigMaps = []seed.ConfigMap{{
		Name: "kubeadm-config", Namespace: "kube-system",
		Data: map[string]string{"ClusterConfiguration": "kind: ClusterConfiguration\n"},
	}}
	k, err := New(Config{RestConfig: cluster.restConfig, Seed: s, NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	// kube-dns Service + its EndpointSlice.
	if _, err := k.client.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected kube-dns Service: %v", err)
	}
	slices, err := k.client.DiscoveryV1().EndpointSlices("kube-system").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=kube-dns"})
	if err != nil || len(slices.Items) == 0 {
		t.Fatalf("expected a kube-dns EndpointSlice, got %d (%v)", len(slices.Items), err)
	}
	// kubeadm-config ConfigMap.
	if _, err := k.client.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected kubeadm-config ConfigMap: %v", err)
	}
	// Node reports images.
	node, err := k.client.CoreV1().Nodes().Get(ctx, "decoy-node-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Status.Images) == 0 {
		t.Error("node must report a non-empty images list")
	}

	// Adoption: create a pod bound to the fake node but left Pending (as a
	// scheduler would leave it before a kubelet runs it), then re-seed and
	// expect the shim to mark it Running.
	attacker := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "attacker-pod", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "decoy-node-1", Containers: []corev1.Container{{Name: "c", Image: "nginx:1"}}},
	}
	if _, err := k.client.CoreV1().Pods("default").Create(ctx, attacker, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating attacker pod: %v", err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("re-seed for adoption failed: %v", err)
	}
	got, err := k.client.CoreV1().Pods("default").Get(ctx, "attacker-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != corev1.PodRunning {
		t.Fatalf("expected the scheduled attacker pod to be adopted as Running, got %q", got.Status.Phase)
	}
	if len(got.Status.ContainerStatuses) == 0 || !got.Status.ContainerStatuses[0].Ready {
		t.Fatalf("adopted pod must have a ready container status, got %+v", got.Status.ContainerStatuses)
	}
}

// TestKubeletShimSeed_PrunesRemovedObjects proves the shim deletes objects it
// previously seeded once they are dropped from the seed (an author removing a
// fakePod, a joined pod leaving), instead of leaving them stranded -- while
// leaving an object created by someone else (an attacker) untouched.
func TestKubeletShimSeed_PrunesRemovedObjects(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	s := &seed.Seed{
		FakeNodes: []v1alpha1.FakeNode{{Name: "decoy-node-1"}},
		FakePods: []seed.Pod{
			{FakePod: v1alpha1.FakePod{Name: "keep-me", Namespace: "billing", Containers: []v1alpha1.FakeContainer{{Name: "app", Image: "a:1"}}}},
			{FakePod: v1alpha1.FakePod{Name: "drop-me", Namespace: "billing", Containers: []v1alpha1.FakeContainer{{Name: "app", Image: "a:1"}}}},
		},
		FakeSecrets: []v1alpha1.FakeSecret{{Name: "drop-secret", Namespace: "billing", Data: map[string]string{"k": "v"}}},
	}
	k, err := New(Config{RestConfig: cluster.restConfig, Seed: s, NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("first seed: %v", err)
	}

	// An object the shim did NOT create (stands in for an attacker's).
	attacker := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "attacker-pod", Namespace: "billing"},
		Spec:       corev1.PodSpec{NodeName: "decoy-node-1", Containers: []corev1.Container{{Name: "c", Image: "x:1"}}},
	}
	if _, err := k.client.CoreV1().Pods("billing").Create(ctx, attacker, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating attacker pod: %v", err)
	}

	// Drop "drop-me" and the secret from the seed, then re-seed.
	k.cfg.Seed = &seed.Seed{
		FakeNodes: []v1alpha1.FakeNode{{Name: "decoy-node-1"}},
		FakePods:  []seed.Pod{{FakePod: v1alpha1.FakePod{Name: "keep-me", Namespace: "billing", Containers: []v1alpha1.FakeContainer{{Name: "app", Image: "a:1"}}}}},
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	// keep-me stays; drop-me and the secret are pruned; the attacker's pod is
	// left alone (never tracked by the shim).
	if _, err := k.client.CoreV1().Pods("billing").Get(ctx, "keep-me", metav1.GetOptions{}); err != nil {
		t.Errorf("keep-me must remain: %v", err)
	}
	if _, err := k.client.CoreV1().Pods("billing").Get(ctx, "drop-me", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("drop-me must be pruned, got err=%v", err)
	}
	if _, err := k.client.CoreV1().Secrets("billing").Get(ctx, "drop-secret", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("drop-secret must be pruned, got err=%v", err)
	}
	if _, err := k.client.CoreV1().Pods("billing").Get(ctx, "attacker-pod", metav1.GetOptions{}); err != nil {
		t.Errorf("attacker's pod must NOT be pruned: %v", err)
	}
}

// TestKubeletShimExecAndLogs_RealAPIServerProxy is the deepest real-stack
// proof in this repo for the new architecture: a real kubectl binary,
// talking to a real kube-apiserver, which genuinely proxies pods/exec,
// pods/log, and pods/attach to kubelet-shim's own HTTPS server (using the
// seeded Node's InternalIP + daemonEndpoints.kubeletEndpoint.Port, exactly
// as a real cluster would locate a real kubelet). `exec` now runs a real
// process (see exec.go); `logs`/`attach` stay fabricated, since there's no
// real running process behind a FakePod's declared image to attach to.
func TestKubeletShimExecAndLogs_RealAPIServerProxy(t *testing.T) {
	cluster := startInnerTestCluster(t)
	kubectlPath := findBinary(t, "kubectl")
	ctx := context.Background()

	const kubeletPort = 29250
	saDir := t.TempDir()
	k, err := New(Config{
		RestConfig:          cluster.restConfig,
		Seed:                testSeed(),
		NodeInternalIP:      "127.0.0.1",
		KubeletPort:         kubeletPort,
		ServiceAccountToken: cluster.token,
		ServiceAccountDir:   saDir,
		Namespace:           "billing",
		CABundlePath:        cluster.caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	srv, err := k.NewServer(cluster.tlsCert, cluster.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Addr = fmt.Sprintf(":%d", kubeletPort)
	go func() { _ = srv.ListenAndServeTLS(cluster.tlsCert, cluster.tlsKey) }()
	t.Cleanup(func() {
		_ = srv.Close()
	})
	waitForPort(t, fmt.Sprintf("127.0.0.1:%d", kubeletPort), 5*time.Second)
	// The kubelet-endpoint server uses TLS with no application-level
	// health check exposed over plain TCP dial alone; give it a moment to
	// finish installing its TLS listener before the apiserver's first
	// proxied request.
	waitForKubeletTLS(t, kubeletPort, cluster.caFile)

	runKubectl := func(args ...string) string {
		t.Helper()
		full := append([]string{
			"--server=" + cluster.restConfig.Host,
			"--token=" + cluster.token,
			"--certificate-authority=" + cluster.caFile,
		}, args...)
		cmd := exec.Command(kubectlPath, full...)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("kubectl %v failed: %v\nstdout: %s\nstderr: %s", args, err, out.String(), stderr.String())
		}
		return out.String()
	}

	podsOut := runKubectl("-n", "billing", "get", "pods", "-o", "name")
	firstPod := strings.TrimSpace(strings.Split(strings.TrimPrefix(strings.Split(podsOut, "\n")[0], "pod/"), "\n")[0])
	if firstPod == "" {
		t.Fatalf("expected at least one pod, got: %s", podsOut)
	}

	logsOut := runKubectl("-n", "billing", "logs", firstPod)
	if !strings.Contains(logsOut, "listening on :8080") {
		t.Fatalf("expected fabricated log lines proxied through the real apiserver, got: %s", logsOut)
	}

	// A real process actually runs now: prove it by checking the exec
	// session's real uid matches this test binary's own real uid, not a
	// canned string.
	idOut := runKubectl("-n", "billing", "exec", firstPod, "--", "id", "-u")
	if strings.TrimSpace(idOut) != strconv.Itoa(os.Getuid()) {
		t.Fatalf("expected the real process's uid to match this test's own uid (%d), got: %q", os.Getuid(), idOut)
	}

	tokenOut := runKubectl("-n", "billing", "exec", firstPod, "--", "cat", filepath.Join(saDir, "token"))
	if strings.TrimSpace(tokenOut) != cluster.token {
		t.Fatalf("expected the exec session's real cat of the serviceaccount token file to echo back the same decoy token, got: %q", tokenOut)
	}

	attachOut := runKubectl("-n", "billing", "attach", firstPod)
	if !strings.Contains(attachOut, "listening on :8080") {
		t.Fatalf("expected attach to serve the same fabricated log content, got: %s", attachOut)
	}
}

// TestKubeletShimSeed_CompletesGracefulDeletion covers what happens after
// an attacker runs `kubectl delete pod` against a decoy. kube-apiserver
// only stamps a deletionTimestamp and then waits for the kubelet that owns
// the pod to confirm its containers are gone; kubelet-shim is the only
// thing playing kubelet here. It used to just Update the terminating
// object on the next heartbeat, so the pod never left the store: the
// attacker's `kubectl delete` hung until its own timeout and the pod sat
// in Terminating forever -- a broken verb, and a tell, since a real
// cluster removes it in seconds. Seed() has to complete the deletion the
// way a real kubelet does, and then re-create the pod on a later pass the
// way a controller-managed pod comes back after being killed.
func TestKubeletShimSeed_CompletesGracefulDeletion(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	k, err := New(Config{RestConfig: cluster.restConfig, Seed: testSeed(), NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("first seed failed: %v", err)
	}

	pods, err := k.client.CoreV1().Pods("billing").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("expected the seeded pods to exist before deleting one")
	}
	victim := pods.Items[0].Name

	// Exactly what `kubectl delete pod` sends: a graceful delete, which
	// leaves the object in the store carrying a deletionTimestamp.
	if err := k.client.CoreV1().Pods("billing").Delete(ctx, victim, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting pod %s: %v", victim, err)
	}
	terminating, err := k.client.CoreV1().Pods("billing").Get(ctx, victim, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected %s to still be present (graceful deletion): %v", victim, err)
	}
	if terminating.DeletionTimestamp == nil {
		t.Fatalf("expected a deletionTimestamp on %s, so this test is actually exercising the terminating path", victim)
	}
	originalUID := terminating.UID

	// The heartbeat's next re-seed is what a real kubelet's own sync loop
	// stands in for here: it has to finish the delete, not refresh it.
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("re-seed over a terminating pod failed: %v", err)
	}

	after, err := k.client.CoreV1().Pods("billing").Get(ctx, victim, metav1.GetOptions{})
	if err == nil && after.DeletionTimestamp != nil && after.UID == originalUID {
		t.Fatalf("pod %s is still the same terminating object after a re-seed -- `kubectl delete` would hang and it would sit in Terminating forever", victim)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("getting %s after re-seed: %v", victim, err)
	}

	// And it comes back, the way a controller-managed pod does once the
	// killed one is really gone -- a decoy that permanently loses a pod to
	// one `kubectl delete` is its own kind of tell.
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("seed after completed deletion failed: %v", err)
	}
	recreated, err := k.client.CoreV1().Pods("billing").Get(ctx, victim, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected pod %s to be re-created after its deletion completed: %v", victim, err)
	}
	if recreated.DeletionTimestamp != nil {
		t.Fatalf("re-created pod %s still carries a deletionTimestamp", victim)
	}
	if recreated.UID == originalUID {
		t.Fatalf("expected a genuinely new pod object, got the original UID %s back", originalUID)
	}
	if recreated.Status.Phase != "Running" {
		t.Fatalf("expected re-created pod %s Running, got %s", victim, recreated.Status.Phase)
	}
}

// TestKubeletShimSeed_CompletesNamespaceDeletion is the namespace half of
// TestKubeletShimSeed_CompletesGracefulDeletion. `kubectl delete namespace`
// only stamps a deletionTimestamp and leaves the "kubernetes" finalizer
// for the namespace controller to clear -- and a Decoy's inner control
// plane runs no kube-controller-manager, so nothing used to clear it. The
// attacker's delete hung and the namespace sat in Terminating forever.
// Seed() has to finish it, purge what was inside, and then let the
// namespace be re-created on a later pass like any other seeded object.
func TestKubeletShimSeed_CompletesNamespaceDeletion(t *testing.T) {
	cluster := startInnerTestCluster(t)
	ctx := context.Background()

	k, err := New(Config{RestConfig: cluster.restConfig, Seed: testSeed(), NodeInternalIP: "10.99.0.5", KubeletPort: 10250, ServiceAccountToken: cluster.token})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Seed(ctx); err != nil {
		t.Fatalf("first seed failed: %v", err)
	}

	// A namespace of the attacker's own, so this doesn't depend on the
	// seed re-creating one of its own namespaces to look like a pass.
	const attackerNS = "loot"
	if _, err := k.client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: attackerNS},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating %s: %v", attackerNS, err)
	}
	if _, err := k.client.CoreV1().Secrets(attackerNS).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "stash", Namespace: attackerNS},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating a secret in %s: %v", attackerNS, err)
	}

	if err := k.client.CoreV1().Namespaces().Delete(ctx, attackerNS, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting %s: %v", attackerNS, err)
	}
	terminating, err := k.client.CoreV1().Namespaces().Get(ctx, attackerNS, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected %s to still be present (finalizer pending): %v", attackerNS, err)
	}
	if terminating.DeletionTimestamp == nil || len(terminating.Spec.Finalizers) == 0 {
		t.Fatalf("expected %s Terminating with a pending finalizer, so this test exercises the real path: %+v", attackerNS, terminating.Spec.Finalizers)
	}

	if err := k.Seed(ctx); err != nil {
		t.Fatalf("re-seed over a terminating namespace failed: %v", err)
	}

	if _, err := k.client.CoreV1().Namespaces().Get(ctx, attackerNS, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected %s to be gone after a re-seed -- `kubectl delete namespace` would hang and it would sit in Terminating forever (err=%v)", attackerNS, err)
	}

	// The namespaces the seed itself owns must survive all of this.
	if _, err := k.client.CoreV1().Namespaces().Get(ctx, "billing", metav1.GetOptions{}); err != nil {
		t.Fatalf("expected the seeded namespace billing to be untouched: %v", err)
	}
}
