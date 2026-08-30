package controller

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/seed"
)

// TestPodJoinAnnotationPredicate proves the Pod-watch predicate only lets
// through Pods that carry (or used to carry) the join annotation, so the
// reconciler is not woken by every unrelated Pod change in the cluster.
func TestPodJoinAnnotationPredicate(t *testing.T) {
	p := podJoinAnnotationPredicate()
	annotated := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{joinAnnotation: "ns/kt"}}}
	plain := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrelated"}}

	if !p.Create(event.CreateEvent{Object: annotated}) {
		t.Error("annotated Pod create should pass the predicate")
	}
	if p.Create(event.CreateEvent{Object: plain}) {
		t.Error("unannotated Pod create must be filtered out")
	}
	if !p.Delete(event.DeleteEvent{Object: annotated}) {
		t.Error("annotated Pod delete should pass the predicate")
	}
	if p.Delete(event.DeleteEvent{Object: plain}) {
		t.Error("unannotated Pod delete must be filtered out")
	}
	// Removal: old had the annotation, new does not -- must still pass so
	// the Decoy drops the pod from its status.
	if !p.Update(event.UpdateEvent{ObjectOld: annotated, ObjectNew: plain}) {
		t.Error("annotation-removal update must pass so the pod is un-joined")
	}
	// Addition: new gains it.
	if !p.Update(event.UpdateEvent{ObjectOld: plain, ObjectNew: annotated}) {
		t.Error("annotation-addition update must pass")
	}
	// Neither side annotated: filtered out.
	if p.Update(event.UpdateEvent{ObjectOld: plain, ObjectNew: plain}) {
		t.Error("update on a Pod that never had the annotation must be filtered out")
	}
}

func crdNames(kt *honeypodv1alpha1.Decoy) map[string]bool {
	out := map[string]bool{}
	for _, c := range renderCRDs(kt) {
		out[c.Plural+"."+c.Group] = true
	}
	return out
}

// TestRenderCRDs_DefaultsWhenSystemComponents proves the believable default
// operator CRDs are seeded by default, so a fresh decoy's `kubectl get crds`
// is not suspiciously empty.
func TestRenderCRDs_DefaultsWhenSystemComponents(t *testing.T) {
	kt := sampleDecoy("billing", "decoy") // SeedSystemComponents unset => default true
	names := crdNames(kt)
	for _, want := range []string{"certificates.cert-manager.io", "servicemonitors.monitoring.coreos.com"} {
		if !names[want] {
			t.Errorf("expected default CRD %q to be seeded, got %v", want, names)
		}
	}
}

// TestRenderCRDs_OptOutDropsDefaults proves seedSystemComponents=false drops
// the auto CRDs, matching the "author controls everything" contract that
// already governs the kube-system pods.
func TestRenderCRDs_OptOutDropsDefaults(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")
	off := false
	kt.Spec.SeedSystemComponents = &off
	if got := renderCRDs(kt); len(got) != 0 {
		t.Fatalf("expected no CRDs with seedSystemComponents=false, got %v", got)
	}
}

// TestRenderCRDs_AuthorAddedAndOverrides proves spec.fakeCRDs are added on
// top of the defaults, and that an author entry with the same plural.group
// as a default overrides it (e.g. to change scope/versions).
func TestRenderCRDs_AuthorAddedAndOverrides(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")
	kt.Spec.FakeCRDs = []honeypodv1alpha1.FakeCRD{
		{Group: "argoproj.io", Kind: "Application", Plural: "applications", ShortNames: []string{"app"}},
		// Collides with a default: override cert-manager Certificate to be
		// cluster-scoped, proving the author entry wins.
		{Group: "cert-manager.io", Kind: "Certificate", Plural: "certificates", Scope: "Cluster"},
	}
	got := renderCRDs(kt)
	seen := map[string]int{}
	var certScope string
	for _, c := range got {
		key := c.Plural + "." + c.Group
		seen[key]++
		if key == "certificates.cert-manager.io" {
			certScope = c.Scope
		}
	}
	if !containsCRD(got, "applications.argoproj.io") {
		t.Errorf("expected author CRD applications.argoproj.io to be added, got %v", got)
	}
	if seen["certificates.cert-manager.io"] != 1 {
		t.Errorf("expected the colliding CRD to appear once (override, not duplicate), got %d", seen["certificates.cert-manager.io"])
	}
	if certScope != "Cluster" {
		t.Errorf("expected the author's Cluster scope to win the collision, got %q", certScope)
	}
}

func containsCRD(crds []seed.CRD, name string) bool {
	for _, c := range crds {
		if c.Plural+"."+c.Group == name {
			return true
		}
	}
	return false
}

// TestControlPlaneComponentsAreReal proves the decoy runs a real KCM and
// scheduler with leader-election + serving, so their Leases and
// componentstatuses are genuine, and that the controllers that would disturb
// the seeded kube-system pods stay disabled.
func TestControlPlaneComponentsAreReal(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")
	dep := buildDeployment(kt, "decoy-decoy", "decoy-config", "sum", "certsum", "10.0.0.5")

	args := map[string][]string{}
	for _, c := range dep.Spec.Template.Spec.Containers {
		args[c.Name] = c.Args
	}
	kcm, ok := args["kube-controller-manager"]
	if !ok {
		t.Fatal("expected a kube-controller-manager container")
	}
	sched, ok := args["kube-scheduler"]
	if !ok {
		t.Fatal("expected a kube-scheduler container")
	}
	kcmJoined := strings.Join(kcm, " ")
	if !strings.Contains(kcmJoined, "--leader-elect=true") {
		t.Errorf("KCM must leader-elect (writes a real kube-controller-manager Lease), args: %v", kcm)
	}
	if !strings.Contains(kcmJoined, "--secure-port=10257") {
		t.Errorf("KCM must serve on 10257 so componentstatuses report Healthy, args: %v", kcm)
	}
	// The node-eviction / pod-GC controllers, and the daemonset controller
	// (which would churn the seeded kube-proxy pods), must stay off.
	for _, off := range []string{"-node-lifecycle-controller", "-pod-garbage-collector-controller", "-daemonset-controller"} {
		if !strings.Contains(kcmJoined, off) {
			t.Errorf("KCM must keep %q disabled to protect the seed, args: %v", off, kcm)
		}
	}
	// The deployment and replicaset controllers must be ENABLED (not in the
	// disable list), so an attacker's Deployment actually spawns pods.
	for _, on := range []string{"-deployment-controller", "-replicaset-controller"} {
		if strings.Contains(kcmJoined, on) {
			t.Errorf("KCM must NOT disable %q -- attacker Deployments must reconcile, args: %v", on, kcm)
		}
	}
	schedJoined := strings.Join(sched, " ")
	if !strings.Contains(schedJoined, "--leader-elect=true") || !strings.Contains(schedJoined, "--secure-port=10259") {
		t.Errorf("scheduler must leader-elect and serve on 10259, args: %v", sched)
	}
}

// TestRenderStandardObjects proves the static kubeadm artifacts (kube-dns
// Service + endpoints, kube-system/kube-public ConfigMaps) are seeded by
// default and dropped under seedSystemComponents=false.
func TestRenderStandardObjects(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")
	svcs, cms := renderStandardObjects(kt)

	var kubeDNS *seed.Service
	for i := range svcs {
		if svcs[i].Name == "kube-dns" {
			kubeDNS = &svcs[i]
		}
	}
	if kubeDNS == nil {
		t.Fatal("expected a kube-dns Service")
	}
	if kubeDNS.ClusterIP != "10.96.0.10" || len(kubeDNS.EndpointIPs) == 0 {
		t.Errorf("kube-dns must have the standard ClusterIP and backing endpoints, got %+v", kubeDNS)
	}
	want := map[string]bool{"kubeadm-config": false, "kubelet-config": false, "coredns": false, "kube-proxy": false, "cluster-info": false}
	for _, c := range cms {
		if _, ok := want[c.Name]; ok {
			want[c.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("expected standard ConfigMap %q to be seeded", name)
		}
	}

	off := false
	kt.Spec.SeedSystemComponents = &off
	if s, c := renderStandardObjects(kt); len(s) != 0 || len(c) != 0 {
		t.Fatalf("seedSystemComponents=false must drop standard objects, got %d svc %d cm", len(s), len(c))
	}
}

// TestControlPlaneStaticPodsAreHostNetwork proves the seeded static
// control-plane pods carry HostNetwork + a CPU request, so they report
// podIP==hostIP and a Burstable QoS like real ones.
func TestControlPlaneStaticPodsAreHostNetwork(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")
	kt.Spec.FakeNodes = []honeypodv1alpha1.FakeNode{{Name: "cp-1"}}
	pods, _ := defaultKubeSystemPods(kt, kt.Spec.FakeNodes)
	checked := 0
	for _, p := range pods {
		if strings.HasPrefix(p.Name, "etcd-") || strings.HasPrefix(p.Name, "kube-apiserver-") || strings.HasPrefix(p.Name, "kube-proxy-") {
			checked++
			if !p.HostNetwork {
				t.Errorf("static control-plane pod %q must be HostNetwork", p.Name)
			}
			if p.CPURequest == "" {
				t.Errorf("static control-plane pod %q must declare a CPU request (Burstable QoS)", p.Name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("expected some static control-plane pods to check")
	}
}

// TestExecProfile_RenderArg proves the kubelet-shim container is told which
// exec profile to serve, defaulting to shell and honoring spec.execProfile.
func TestExecProfile_RenderArg(t *testing.T) {
	shimArgs := func(kt *honeypodv1alpha1.Decoy) string {
		dep := buildDeployment(kt, "d-decoy", "d-config", "s", "cs", "10.0.0.5")
		for _, c := range dep.Spec.Template.Spec.Containers {
			if c.Name == "kubelet-shim" {
				return strings.Join(c.Args, " ")
			}
		}
		return ""
	}

	// Default: shell.
	if got := shimArgs(sampleDecoy("billing", "d")); !strings.Contains(got, "--exec-profile=shell") {
		t.Errorf("default exec profile must be shell, args: %s", got)
	}
	// Explicit distroless.
	kt := sampleDecoy("billing", "d")
	kt.Spec.ExecProfile = "distroless"
	if got := shimArgs(kt); !strings.Contains(got, "--exec-profile=distroless") {
		t.Errorf("expected --exec-profile=distroless, args: %s", got)
	}
}

// TestExecIsolation_SecurityContext proves the shim container is hardened by
// default and only gains CAP_SYS_ADMIN + unconfined seccomp when
// spec.execIsolation is set -- the deliberate, opt-in containment trade-off.
func TestExecIsolation_SecurityContext(t *testing.T) {
	shimSC := func(kt *honeypodv1alpha1.Decoy) *corev1.SecurityContext {
		dep := buildDeployment(kt, "d-decoy", "d-config", "s", "cs", "10.0.0.5")
		for _, c := range dep.Spec.Template.Spec.Containers {
			if c.Name == "kubelet-shim" {
				return c.SecurityContext
			}
		}
		return nil
	}
	hasCap := func(sc *corev1.SecurityContext, cap corev1.Capability) bool {
		if sc == nil || sc.Capabilities == nil {
			return false
		}
		for _, c := range sc.Capabilities.Add {
			if c == cap {
				return true
			}
		}
		return false
	}

	// Default: hardened, no SYS_ADMIN, RuntimeDefault seccomp.
	off := shimSC(sampleDecoy("billing", "d"))
	if hasCap(off, "SYS_ADMIN") {
		t.Error("default shim must not hold CAP_SYS_ADMIN")
	}
	if off.SeccompProfile == nil || off.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("default shim seccomp must be RuntimeDefault, got %+v", off.SeccompProfile)
	}

	// execIsolation on: SYS_ADMIN + Unconfined, still non-root.
	kt := sampleDecoy("billing", "d")
	kt.Spec.ExecIsolation = true
	on := shimSC(kt)
	if !hasCap(on, "SYS_ADMIN") {
		t.Error("execIsolation must add CAP_SYS_ADMIN")
	}
	if on.SeccompProfile == nil || on.SeccompProfile.Type != corev1.SeccompProfileTypeUnconfined {
		t.Errorf("execIsolation seccomp must be Unconfined, got %+v", on.SeccompProfile)
	}
	// The container runs as root so the added CAP_SYS_ADMIN is effective (the
	// exec session itself drops to the app uid in RunExecInit).
	if on.RunAsUser == nil || *on.RunAsUser != 0 {
		t.Errorf("execIsolation container must run as root for effective CAP_SYS_ADMIN, got %v", on.RunAsUser)
	}
}

// TestDecoyDNSConfig_NoHostLeak proves the decoy pod pins a clean in-cluster
// resolv.conf (DNSPolicy None + a standard cluster search list) so an exec
// session's /etc/resolv.conf can't leak the real host node's DNS -- the
// observed "incus" search domain and the real cluster's nameservers.
func TestDecoyDNSConfig_NoHostLeak(t *testing.T) {
	kt := sampleDecoy("billing", "decoy") // first fakePod namespace: billing
	dep := buildDeployment(kt, "decoy-decoy", "decoy-config", "sum", "certsum", "10.0.0.5")
	spec := dep.Spec.Template.Spec

	if spec.DNSPolicy != corev1.DNSNone {
		t.Fatalf("decoy pod must use DNSPolicy None to override the host resolv.conf, got %q", spec.DNSPolicy)
	}
	if spec.DNSConfig == nil {
		t.Fatal("decoy pod must set an explicit DNSConfig")
	}
	if len(spec.DNSConfig.Nameservers) != 1 || spec.DNSConfig.Nameservers[0] != "10.96.0.10" {
		t.Errorf("expected the cluster DNS ClusterIP as the sole nameserver, got %v", spec.DNSConfig.Nameservers)
	}
	joined := strings.Join(spec.DNSConfig.Searches, " ")
	if !strings.Contains(joined, "svc.cluster.local") || !strings.Contains(joined, "billing.svc.cluster.local") {
		t.Errorf("search list must be the standard in-cluster one rooted at the served namespace, got %v", spec.DNSConfig.Searches)
	}
	// Nothing host-specific may appear.
	for _, s := range spec.DNSConfig.Searches {
		if strings.Contains(s, "incus") {
			t.Errorf("search list leaks a host domain: %q", s)
		}
	}
}

// TestRenderKCMKubeconfig_LoopbackInsecure proves the KCM kubeconfig points
// at the inner apiserver over loopback with the given token and skips TLS
// verify (same-pod, no MITM surface), and never embeds a CA the ConfigMap
// would otherwise have to carry.
func TestRenderKCMKubeconfig_LoopbackInsecure(t *testing.T) {
	out, err := renderKCMKubeconfig("kcm-token-xyz")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"server: https://127.0.0.1:8443", "insecure-skip-tls-verify: true", "token: kcm-token-xyz"} {
		if !strings.Contains(s, want) {
			t.Errorf("KCM kubeconfig missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "certificate-authority") {
		t.Errorf("KCM kubeconfig should not embed a CA (loopback insecure), got:\n%s", s)
	}
}

// TestBuildDeployment_ExecContainerDoesNotMountPrivateKeys covers the exec
// sandbox hardening (Gap 2): the kubelet-shim container, which is the one
// `kubectl exec` runs an attacker shell in, must mount a shim-scoped Secret
// that carries only ca.crt, the two tokens, and the serving keypair. The CA
// private key, the ServiceAccount signing key, and the kube-controller-manager
// token that the full "-decoy" Secret also holds must never be reachable from
// an exec session.
func TestBuildDeployment_ExecContainerDoesNotMountPrivateKeys(t *testing.T) {
	kt := sampleDecoy("billing", "checkout-api-decoy")
	dep := buildDeployment(kt, "checkout-api-decoy-decoy", "checkout-api-decoy-config", "sum", "certsum", "10.0.0.5")

	var shim *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kubelet-shim" {
			shim = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if shim == nil {
		t.Fatal("no kubelet-shim container in the decoy pod")
	}
	mounts := map[string]bool{}
	for _, vm := range shim.VolumeMounts {
		mounts[vm.Name] = true
	}
	if mounts["decoy-secret"] {
		t.Fatal("kubelet-shim mounts the full decoy-secret; an exec session could read the CA private key")
	}
	if !mounts["decoy-shim-secret"] {
		t.Fatal("kubelet-shim does not mount the shim-scoped secret")
	}

	var shimVol *corev1.Volume
	for i := range dep.Spec.Template.Spec.Volumes {
		if dep.Spec.Template.Spec.Volumes[i].Name == "decoy-shim-secret" {
			shimVol = &dep.Spec.Template.Spec.Volumes[i]
		}
	}
	if shimVol == nil || shimVol.Secret == nil {
		t.Fatal("decoy-shim-secret volume is missing or not a Secret projection")
	}
	allowed := map[string]bool{"ca.crt": true, "token": true, "shim.token": true, "tls.crt": true, "tls.key": true}
	if len(shimVol.Secret.Items) == 0 {
		t.Fatal("decoy-shim-secret must project an explicit key subset, not the whole Secret")
	}
	for _, it := range shimVol.Secret.Items {
		if !allowed[it.Key] {
			t.Fatalf("decoy-shim-secret exposes %q to the exec container; only the shim's own keys belong there", it.Key)
		}
	}
}

// TestRenderAuditPolicy covers spec.auditLevel: unset yields the default
// RequestResponse policy, and each level renders a one-rule policy at that
// level.
func TestRenderAuditPolicy(t *testing.T) {
	if got := string(renderAuditPolicy(sampleDecoy("ns", "d"))); !strings.Contains(got, "level: RequestResponse") {
		t.Fatalf("default auditLevel should log RequestResponse, got: %s", got)
	}
	for _, level := range []string{"None", "Metadata", "Request", "RequestResponse"} {
		kt := sampleDecoy("ns", "d")
		kt.Spec.AuditLevel = level
		got := string(renderAuditPolicy(kt))
		if !strings.Contains(got, "level: "+level) {
			t.Fatalf("auditLevel %q should render 'level: %s', got: %s", level, level, got)
		}
	}
}
