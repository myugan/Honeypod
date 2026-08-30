package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/notifier"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	testCtx   = context.Background()
)

func TestMain(m *testing.M) {
	// `go test -short` skips starting envtest (a real kube-apiserver +
	// etcd), leaving only the pure-unit tests in this package for a fast
	// local loop. Envtest-backed tests self-skip via requireEnvtest when
	// k8sClient is nil. CI runs the full set without -short.
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		fmt.Println("envtest start failed:", err)
		os.Exit(1)
	}

	scheme := clientgoscheme.Scheme
	if err := honeypodv1alpha1.AddToScheme(scheme); err != nil {
		fmt.Println("scheme setup failed:", err)
		os.Exit(1)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Println("client setup failed:", err)
		os.Exit(1)
	}

	code := m.Run()
	_ = testEnv.Stop()
	os.Exit(code)
}

// requireEnvtest skips a test when the envtest apiserver was not started
// (i.e. under `go test -short`), so envtest-backed tests don't panic on a
// nil client in the fast unit-only run.
func requireEnvtest(t *testing.T) {
	t.Helper()
	if k8sClient == nil {
		t.Skip("skipping envtest-backed test in -short mode")
	}
}

func newReconciler() *DecoyReconciler {
	return &DecoyReconciler{Client: k8sClient, Scheme: clientgoscheme.Scheme}
}

func uniqueNamespace(t *testing.T) string {
	t.Helper()
	requireEnvtest(t)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "kt-test-"}}
	if err := k8sClient.Create(testCtx, ns); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(testCtx, ns) })
	return ns.Name
}

func sampleDecoy(ns, name string) *honeypodv1alpha1.Decoy {
	return &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: honeypodv1alpha1.DecoySpec{
			KubeletShimImage: "honeypod/kubelet-shim:latest",
			Port:             6443,
			FakeNodes:        []honeypodv1alpha1.FakeNode{{Name: "decoy-node-1"}},
			FakePods: []honeypodv1alpha1.FakePod{{
				Name: "checkout-api", Namespace: "billing", Replicas: 2,
				Containers: []honeypodv1alpha1.FakeContainer{{Name: "app", Image: "checkout-api:1.4.2"}},
			}},
			FakeSecrets: []honeypodv1alpha1.FakeSecret{{
				Name: "checkout-api-db-credentials", Namespace: "billing",
				Data: map[string]string{"password": "decoy"},
			}},
		},
	}
}

// TestReconcile_CreatesAllChildResources drives the reconciler directly
// against a real (envtest) kube-apiserver -- not a fake client -- and
// verifies a single Decoy CR produces every resource the fake decoy
// environment needs, correctly owned for garbage collection.
func TestReconcile_CreatesAllChildResources(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep); err != nil {
		t.Fatalf("expected Deployment to be created: %v", err)
	}
	if len(dep.Spec.Template.Spec.Containers) != 5 {
		t.Fatalf("expected 5 containers (kine + kube-apiserver + kube-controller-manager + kube-scheduler + kubelet-shim), got %d", len(dep.Spec.Template.Spec.Containers))
	}
	// The decoy runs a real kube-controller-manager so its RBAC/SA/token/
	// endpoint/event housekeeping is genuinely present, not fabricated.
	var kcm *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kube-controller-manager" {
			kcm = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if kcm == nil {
		t.Fatal("expected a kube-controller-manager container in the decoy pod")
	}
	if len(kcm.Command) == 0 || kcm.Command[0] != "/usr/local/bin/kube-controller-manager" {
		t.Fatalf("expected KCM Command to bypass go-runner via /usr/local/bin/kube-controller-manager, got %v", kcm.Command)
	}
	// The node/eviction/pod-GC controllers must be off, or the real KCM
	// would evict the fake nodes and delete the seeded pods.
	joinedArgs := strings.Join(kcm.Args, " ")
	for _, off := range []string{"-node-lifecycle-controller", "-pod-garbage-collector-controller", "-taint-eviction-controller"} {
		if !strings.Contains(joinedArgs, off) {
			t.Fatalf("expected KCM to disable %q so it can't evict fake nodes/pods, args: %v", off, kcm.Args)
		}
	}
	// One init container: sa-setup writes the decoy ServiceAccount in the
	// real automount layout as root before the pod runs. No redirect init
	// container, since none of kine/kube-apiserver/kubelet-shim do
	// in-cluster API discovery.
	inits := dep.Spec.Template.Spec.InitContainers
	if len(inits) != 1 || inits[0].Name != "sa-setup" {
		t.Fatalf("expected one sa-setup init container, got %d: %+v", len(inits), inits)
	}
	if inits[0].SecurityContext == nil || inits[0].SecurityContext.RunAsUser == nil || *inits[0].SecurityContext.RunAsUser != 0 {
		t.Fatal("sa-setup must run as root so the ServiceAccount files are root-owned like a real mount")
	}
	if len(dep.OwnerReferences) != 1 || dep.OwnerReferences[0].Kind != "Decoy" {
		t.Fatalf("expected Deployment to be owned by the Decoy, got %+v", dep.OwnerReferences)
	}

	// The real upstream kube-apiserver image's own ENTRYPOINT is
	// /go-runner (a logging wrapper) which does not understand
	// kube-apiserver's own flags -- Command must point directly at the
	// real binary or the container crash-loops with "flag provided but
	// not defined: -etcd-servers" (confirmed live on zeno). Assert it by
	// name rather than index so container reordering doesn't silently
	// defeat this check.
	foundAPIServerCommand := false
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "kube-apiserver" {
			if len(c.Command) == 0 || c.Command[0] != "/usr/local/bin/kube-apiserver" {
				t.Fatalf("expected kube-apiserver container Command to bypass go-runner via /usr/local/bin/kube-apiserver, got %v", c.Command)
			}
			// The real binary carries a Linux file capability baked into
			// the image layer; dropping ALL from the bounding capability
			// set makes the kernel refuse to exec it at all ("operation
			// not permitted", confirmed live on zeno) -- unlike every
			// other container here, this one must NOT drop all
			// capabilities.
			if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Drop {
					if cap == "ALL" {
						t.Fatalf("kube-apiserver container must not drop all capabilities (breaks exec of the real binary), got Capabilities.Drop=%v", c.SecurityContext.Capabilities.Drop)
					}
				}
			}
			foundAPIServerCommand = true
		}
	}
	if !foundAPIServerCommand {
		t.Fatal("expected a kube-apiserver container in the Deployment")
	}

	// Every image under the honeypod/* namespace is custom-built with no
	// real registry to pull from -- imagePullPolicy must be IfNotPresent
	// or a :latest tag defaults to Always and kubelet tries (and fails)
	// to pull it even when it was already imported directly into
	// containerd. This exact class of bug has bitten live on zeno before
	// (fake-apiserver, originally) -- assert it for every container, not
	// just the ones caught by hand so far.
	for _, c := range append(append([]corev1.Container{}, dep.Spec.Template.Spec.InitContainers...), dep.Spec.Template.Spec.Containers...) {
		if strings.HasPrefix(c.Image, "honeypod/") && c.ImagePullPolicy != corev1.PullIfNotPresent {
			t.Fatalf("container %q uses custom image %q but imagePullPolicy is %q, want IfNotPresent", c.Name, c.Image, c.ImagePullPolicy)
		}
	}

	var svc corev1.Service
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &svc); err != nil {
		t.Fatalf("expected Service to be created: %v", err)
	}
	if svc.Spec.Ports[0].Port != 6443 {
		t.Fatalf("expected service port 6443, got %d", svc.Spec.Ports[0].Port)
	}

	var np networkingv1.NetworkPolicy
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-egress"}, &np); err != nil {
		t.Fatalf("expected NetworkPolicy to be created: %v", err)
	}
	if len(np.Spec.PolicyTypes) != 1 || np.Spec.PolicyTypes[0] != networkingv1.PolicyTypeEgress {
		t.Fatalf("expected egress-only NetworkPolicy, got %+v", np.Spec.PolicyTypes)
	}

	var configCM corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-config"}, &configCM); err != nil {
		t.Fatalf("expected config ConfigMap to be created: %v", err)
	}
	if !strings.Contains(configCM.Data[seedFileName], "checkout-api") {
		t.Fatalf("expected config configmap's seed.json to contain the fake workload, got: %s", configCM.Data[seedFileName])
	}
	var sec corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec); err != nil {
		t.Fatalf("expected decoy Secret to be created: %v", err)
	}
	for _, key := range []string{"token", "ca.crt", "tls.crt", "tls.key", "sa.pub", "sa.key", "kubeconfig"} {
		if len(sec.Data[key]) == 0 {
			t.Fatalf("expected decoy secret key %q to be populated", key)
		}
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	if got.Status.Phase != honeypodv1alpha1.DecoyPhasePending {
		t.Fatalf("expected phase Pending before the Deployment is ready, got %s", got.Status.Phase)
	}
	if got.Status.CredentialsSecret != kt.Name+"-decoy" {
		t.Fatalf("expected status.credentialsSecret to be set, got %q", got.Status.CredentialsSecret)
	}
}

// TestReconcile_InnerControlPlaneWiring verifies the new nested-control-plane
// rendering end to end at the manifest level: the Service (created before
// the Deployment specifically so its ClusterIP can be baked into
// kubelet-shim's args) gets a real ClusterIP from the real envtest
// apiserver, that ClusterIP reaches the kubelet-shim container's
// --node-internal-ip flag, the ConfigMap carries every file the inner
// control plane's containers read (token-auth.csv, audit-policy.yaml,
// audit-webhook-kubeconfig.yaml alongside seed.json), the
// audit-webhook-kubeconfig's server URL attributes to this Decoy by
// namespace/name, and the NetworkPolicy's egress allows the operator's own
// audit-webhook namespace in addition to DNS.
func TestReconcile_InnerControlPlaneWiring(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var svc corev1.Service
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &svc); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		t.Fatalf("expected the real apiserver to allocate a ClusterIP, got %q", svc.Spec.ClusterIP)
	}
	foundKubeletPort := false
	for _, p := range svc.Spec.Ports {
		if p.Name == "kubelet" && p.Port == kubeletPort {
			foundKubeletPort = true
		}
	}
	if !foundKubeletPort {
		t.Fatalf("expected a %q port %d on the Service, got %+v", "kubelet", kubeletPort, svc.Spec.Ports)
	}

	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep); err != nil {
		t.Fatal(err)
	}
	var kubeletShimArgs []string
	for _, c := range dep.Spec.Template.Spec.Containers {
		if c.Name == "kubelet-shim" {
			kubeletShimArgs = c.Args
		}
	}
	if kubeletShimArgs == nil {
		t.Fatal("expected a kubelet-shim container")
	}
	wantArg := "--node-internal-ip=" + svc.Spec.ClusterIP
	found := false
	for _, a := range kubeletShimArgs {
		if a == wantArg {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected kubelet-shim args to contain %q (the Service's real ClusterIP), got %v", wantArg, kubeletShimArgs)
	}

	// The real inner kube-apiserver's kubelet-client proxy dials
	// kubelet-shim directly at the Service's ClusterIP (by IP, not by DNS
	// name) for exec/attach/logs -- its TLS cert must carry that
	// IP as a SAN or every such call fails TLS verification with "not
	// valid for <ClusterIP>" (confirmed live on zeno). The cert is only
	// ever issued once (identity must stay stable), so this has to be
	// right from the very first reconcile, not patched in later.
	var sec corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(sec.Data["tls.crt"])
	if block == nil {
		t.Fatal("expected tls.crt to be valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing tls.crt: %v", err)
	}
	wantIP := net.ParseIP(svc.Spec.ClusterIP)
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(wantIP) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("expected kubelet-shim's TLS cert to cover the Service ClusterIP %s as a SAN, got IPAddresses=%v", svc.Spec.ClusterIP, cert.IPAddresses)
	}

	var configCM corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-config"}, &configCM); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{seedFileName, tokenAuthFileName, auditPolicyFileName, auditWebhookKubeconfigFileName} {
		if configCM.Data[key] == "" {
			t.Fatalf("expected ConfigMap key %q to be populated", key)
		}
	}
	if !strings.Contains(configCM.Data[tokenAuthFileName], decoyUsername) {
		t.Fatalf("expected token-auth.csv to carry the decoy identity, got: %s", configCM.Data[tokenAuthFileName])
	}
	wantAuditPath := fmt.Sprintf("/audit/%s/%s", ns, kt.Name)
	if !strings.Contains(configCM.Data[auditWebhookKubeconfigFileName], wantAuditPath) {
		t.Fatalf("expected audit-webhook-kubeconfig.yaml server URL to attribute to %q, got: %s", wantAuditPath, configCM.Data[auditWebhookKubeconfigFileName])
	}

	var np networkingv1.NetworkPolicy
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-egress"}, &np); err != nil {
		t.Fatal(err)
	}
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("expected 2 egress rules (DNS + audit-webhook), got %d: %+v", len(np.Spec.Egress), np.Spec.Egress)
	}
	foundManagerEgress := false
	for _, rule := range np.Spec.Egress {
		for _, to := range rule.To {
			if to.NamespaceSelector != nil && to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == managerNamespace {
				foundManagerEgress = true
			}
		}
	}
	if !foundManagerEgress {
		t.Fatalf("expected an egress rule allowing the manager namespace %q, got: %+v", managerNamespace, np.Spec.Egress)
	}
}

// TestReconcile_CustomSANsAppearOnCert covers spec.sans: an operator can
// add extra DNS names (e.g. "kubernetes.default.svc") to the decoy's cert
// so it resembles a real cluster's apiserver, on top of the ones required
// for the decoy to actually work.
func TestReconcile_CustomSANsAppearOnCert(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	kt.Spec.SANs = []string{"kubernetes.default.svc", "kubernetes.default.svc.cluster.local"}
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var sec corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(sec.Data["tls.crt"])
	if block == nil {
		t.Fatal("expected tls.crt to be valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing tls.crt: %v", err)
	}
	for _, want := range kt.Spec.SANs {
		found := false
		for _, got := range cert.DNSNames {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected custom SAN %q on the decoy's cert, got DNSNames=%v", want, cert.DNSNames)
		}
	}
	if cert.Issuer.CommonName != "kubernetes" {
		t.Fatalf("expected CA issuer CommonName %q to not reveal this is a Decoy, got %q", "kubernetes", cert.Issuer.CommonName)
	}
}

// TestReconcile_BecomesReadyWhenDeploymentIsReady simulates the Deployment
// controller (envtest doesn't run one) marking replicas ready, then verifies
// the Decoy's status transitions to Ready.
func TestReconcile_BecomesReadyWhenDeploymentIsReady(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep); err != nil {
		t.Fatalf("getting deployment: %v", err)
	}
	dep.Status.ReadyReplicas = 1
	dep.Status.Replicas = 1
	if err := k8sClient.Status().Update(testCtx, &dep); err != nil {
		t.Fatalf("simulating deployment readiness: %v", err)
	}

	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	if got.Status.Phase != honeypodv1alpha1.DecoyPhaseReady {
		t.Fatalf("expected phase Ready, got %s", got.Status.Phase)
	}
	if got.Status.Endpoint == "" {
		t.Fatal("expected status.endpoint to be set")
	}
}

// TestReconcile_SeedChangeTriggersRollout verifies editing the CR's fake
// data (fakeSecrets/fakePods/etc.) actually changes what the running
// pod serves -- not just the seed ConfigMap. The fake-apiserver process
// loads its seed once at startup, so without a pod-template checksum
// annotation forcing a rollout, a spec update would silently be inert
// (caught live on zeno: `kubectl` kept serving the old secret after a CR
// patch until this fix).
// TestReconcile_SeedChangeReachesTheDecoyWithoutARollout asserts the seed
// path stays live-reloadable. Changing spec.fakeSecrets rewrites seed.json,
// which must reach the ConfigMap the shim reads without touching the pod
// template: kubelet-shim re-reads that file every heartbeat.
//
// This used to assert the opposite. Rolling the pod on a seed change wiped
// kine's emptyDir, so anything an attacker had created inside the honeypot
// disappeared mid-session, which is a far worse tell than a stale seed.
func TestReconcile_SeedChangeReachesTheDecoyWithoutARollout(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "httpbin-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1 failed: %v", err)
	}

	var dep1 appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep1); err != nil {
		t.Fatal(err)
	}
	checksum1 := dep1.Spec.Template.Annotations["honeypod.io/config-checksum"]
	if checksum1 == "" {
		t.Fatal("expected a config-checksum annotation on the pod template")
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.FakeSecrets[0].Data["password"] = "rotated"
	if err := k8sClient.Update(testCtx, &got); err != nil {
		t.Fatalf("updating spec: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 2 failed: %v", err)
	}

	var dep2 appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep2); err != nil {
		t.Fatal(err)
	}
	if got := dep2.Spec.Template.Annotations["honeypod.io/config-checksum"]; got != checksum1 {
		t.Fatalf("a seed-only change must not roll the decoy, checksum moved %s -> %s", checksum1, got)
	}

	// The new seed still has to be on its way to the shim.
	var cm corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-config"}, &cm); err != nil {
		t.Fatalf("getting config configmap: %v", err)
	}
	if !strings.Contains(cm.Data[seedFileName], "rotated") {
		t.Fatalf("expected the rotated secret in the seed, got: %s", cm.Data[seedFileName])
	}
}

// TestReconcile_IsIdempotentAndStable verifies re-reconciling doesn't churn
// the decoy's identity (token/cert) -- a stability requirement noted from
// prior honeypot work in this environment: rotating identity on every
// reconcile silently breaks any client holding the old kubeconfig.
func TestReconcile_IsIdempotentAndStable(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}

	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1 failed: %v", err)
	}
	var sec1 corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec1); err != nil {
		t.Fatal(err)
	}
	token1 := string(sec1.Data["token"])

	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("reconcile %d failed: %v", i+2, err)
		}
	}

	var sec2 corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec2); err != nil {
		t.Fatal(err)
	}
	if string(sec2.Data["token"]) != token1 {
		t.Fatal("decoy token changed across reconciles; identity must be stable")
	}
}

// TestReconcile_PortChangeRefreshesKubeconfig verifies that changing
// spec.Port updates the server address embedded in the decoy Secret's
// rendered "kubeconfig" key, while leaving the stable identity
// (token/ca.crt/tls.*) untouched. reconcileKubeconfig used to skip
// re-rendering entirely once a "kubeconfig" key existed, so a port change
// would leave every already-issued kubeconfig silently pointing at the old,
// no-longer-listening port forever.
func TestReconcile_PortChangeRefreshesKubeconfig(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1 failed: %v", err)
	}

	var sec1 corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec1); err != nil {
		t.Fatal(err)
	}
	token1 := string(sec1.Data["token"])
	kubeconfig1 := string(sec1.Data["kubeconfig"])
	if !strings.Contains(kubeconfig1, ":6443") {
		t.Fatalf("expected initial kubeconfig to point at port 6443, got:\n%s", kubeconfig1)
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Port = 9443
	if err := k8sClient.Update(testCtx, &got); err != nil {
		t.Fatalf("updating spec: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 2 failed: %v", err)
	}

	var sec2 corev1.Secret
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-decoy"}, &sec2); err != nil {
		t.Fatal(err)
	}
	kubeconfig2 := string(sec2.Data["kubeconfig"])
	if !strings.Contains(kubeconfig2, ":9443") {
		t.Fatalf("expected kubeconfig to be refreshed to port 9443 after spec.Port change, got:\n%s", kubeconfig2)
	}
	if strings.Contains(kubeconfig2, ":6443") {
		t.Fatalf("expected the old port 6443 to no longer appear in the refreshed kubeconfig, got:\n%s", kubeconfig2)
	}
	if string(sec2.Data["token"]) != token1 {
		t.Fatal("decoy token changed on a port-only spec update; identity must stay stable")
	}
}

// TestReconcile_JoinsAnnotatedPod verifies a real Pod -- in a different
// namespace than the Decoy CR, deliberately, to prove the annotation is
// fully-qualified -- annotated honeypod.io/join: "<kt-namespace>/<kt-name>"
// gets mirrored (metadata only) into the seed ConfigMap and recorded in
// status.joinedPods, without disturbing the Decoy's own spec.fakePods.
func TestReconcile_JoinsAnnotatedPod(t *testing.T) {
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)
	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	realPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "real-payments-worker",
			Namespace: podNS,
			Annotations: map[string]string{
				"honeypod.io/join": ktNS + "/" + kt.Name,
			},
			Labels: map[string]string{"app": "payments-worker", "tier": "backend"},
		},
		Spec: corev1.PodSpec{
			NodeName: "real-node-7",
			Containers: []corev1.Container{
				{Name: "worker", Image: "internal-registry.example/payments-worker:9.2.1"},
			},
		},
	}
	if err := k8sClient.Create(testCtx, realPod); err != nil {
		t.Fatalf("creating real pod: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var configCM corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ktNS, Name: kt.Name + "-config"}, &configCM); err != nil {
		t.Fatalf("getting config configmap: %v", err)
	}
	seedData := configCM.Data[seedFileName]
	for _, want := range []string{"real-payments-worker", podNS, "internal-registry.example/payments-worker:9.2.1", "checkout-api"} {
		if !strings.Contains(seedData, want) {
			t.Fatalf("expected seed to contain %q, got: %s", want, seedData)
		}
	}
	// The real node the pod runs on must not follow it into the honeypot:
	// see TestMirrorJoinedPod_DoesNotLeakRealNodeName.
	if strings.Contains(seedData, "real-node-7") {
		t.Fatalf("the real node name leaked into the seed: %s", seedData)
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	if len(got.Status.JoinedPods) != 1 {
		t.Fatalf("expected 1 joined pod in status, got %d: %+v", len(got.Status.JoinedPods), got.Status.JoinedPods)
	}
	if got.Status.JoinedPods[0].Name != "real-payments-worker" || got.Status.JoinedPods[0].Namespace != podNS {
		t.Fatalf("unexpected joined pod in status: %+v", got.Status.JoinedPods[0])
	}
	// The CR's own hand-authored fakePods must be untouched.
	if len(got.Spec.FakePods) != 1 || got.Spec.FakePods[0].Name != "checkout-api" {
		t.Fatalf("expected spec.fakePods to be unmodified, got: %+v", got.Spec.FakePods)
	}
}

// TestReconcile_IgnoresDanglingJoinAnnotation verifies a Pod whose
// honeypod.io/join annotation names a Decoy that doesn't exist doesn't
// fail reconciliation of an unrelated, real Decoy.
func TestReconcile_IgnoresDanglingJoinAnnotation(t *testing.T) {
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)
	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	danglingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "orphaned-joiner",
			Namespace: podNS,
			Annotations: map[string]string{
				"honeypod.io/join": ktNS + "/does-not-exist",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0.0"}},
		},
	}
	if err := k8sClient.Create(testCtx, danglingPod); err != nil {
		t.Fatalf("creating dangling pod: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile of the real Decoy failed: %v", err)
	}

	// The dangling pod targets a different (nonexistent) Decoy, so it must
	// not show up in this one's seed or status.
	var configCM corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ktNS, Name: kt.Name + "-config"}, &configCM); err != nil {
		t.Fatalf("getting config configmap: %v", err)
	}
	if strings.Contains(configCM.Data[seedFileName], "orphaned-joiner") {
		t.Fatalf("dangling join leaked into unrelated Decoy's seed: %s", configCM.Data[seedFileName])
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	if len(got.Status.JoinedPods) != 0 {
		t.Fatalf("expected no joined pods, got: %+v", got.Status.JoinedPods)
	}

	// Reconciling the request the dangling annotation itself maps to must
	// also not error -- Reconcile's existing NotFound handling covers it.
	danglingReq := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: "does-not-exist"}}
	if _, err := r.Reconcile(testCtx, danglingReq); err != nil {
		t.Fatalf("reconciling a nonexistent Decoy target should be a no-op, got error: %v", err)
	}
}

// TestMapJoinedPodToDecoy unit-tests the Pod-watch-to-reconcile-request
// mapping function directly: a valid annotation maps to exactly one request
// for the referenced (possibly cross-namespace) Decoy; a missing,
// malformed, or empty-segment annotation maps to nothing, so an unrelated
// Pod (or one with a garbage annotation) never triggers a reconcile.
func TestMapJoinedPodToDecoy(t *testing.T) {
	requireEnvtest(t)
	cases := []struct {
		name   string
		pod    *corev1.Pod
		expect []types.NamespacedName
	}{
		{
			name: "valid cross-namespace annotation",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "p", Namespace: "workloads",
				Annotations: map[string]string{"honeypod.io/join": "decoys/checkout-api-decoy"},
			}},
			expect: []types.NamespacedName{{Namespace: "decoys", Name: "checkout-api-decoy"}},
		},
		{
			name:   "no annotation",
			pod:    &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "workloads"}},
			expect: nil,
		},
		{
			name: "empty annotation value",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "p", Namespace: "workloads",
				Annotations: map[string]string{"honeypod.io/join": ""},
			}},
			expect: nil,
		},
		{
			name: "malformed annotation (no slash)",
			pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "p", Namespace: "workloads",
				Annotations: map[string]string{"honeypod.io/join": "checkout-api-decoy"},
			}},
			expect: nil,
		},
	}

	r := newReconciler()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs := r.mapJoinedPodToDecoy(testCtx, tc.pod)
			got := make([]types.NamespacedName, 0, len(reqs))
			for _, req := range reqs {
				got = append(got, req.NamespacedName)
			}
			if len(got) != len(tc.expect) {
				t.Fatalf("expected %v, got %v", tc.expect, got)
			}
			for i := range got {
				if got[i] != tc.expect[i] {
					t.Fatalf("expected %v, got %v", tc.expect, got)
				}
			}
		})
	}
}

// TestResolveJoinAnnotation covers the "true" shorthand directly: it
// resolves only when exactly one Decoy exists in the Pod's own
// namespace, and an explicit "<namespace>/<name>" value still works
// unchanged.
func TestResolveJoinAnnotation(t *testing.T) {
	t.Run("explicit value still resolves, independent of any Decoy existing", func(t *testing.T) {
		ns, name, ok := resolveJoinAnnotation(testCtx, k8sClient, "workloads", "decoys/checkout-api-decoy")
		if !ok || ns != "decoys" || name != "checkout-api-decoy" {
			t.Fatalf("expected (decoys, checkout-api-decoy, true), got (%s, %s, %v)", ns, name, ok)
		}
	})

	t.Run("true resolves to the one Decoy in the pod's namespace", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt := sampleDecoy(ns, "only-decoy")
		if err := k8sClient.Create(testCtx, kt); err != nil {
			t.Fatalf("creating Decoy: %v", err)
		}
		gotNS, gotName, ok := resolveJoinAnnotation(testCtx, k8sClient, ns, joinAnnotationImplicit)
		if !ok || gotNS != ns || gotName != "only-decoy" {
			t.Fatalf("expected (%s, only-decoy, true), got (%s, %s, %v)", ns, gotNS, gotName, ok)
		}
	})

	t.Run("true does not resolve with zero Decoys in the namespace", func(t *testing.T) {
		ns := uniqueNamespace(t)
		if _, _, ok := resolveJoinAnnotation(testCtx, k8sClient, ns, joinAnnotationImplicit); ok {
			t.Fatal("expected true to not resolve with no Decoy in the namespace")
		}
	})

	t.Run("true does not resolve with multiple Decoys in the namespace", func(t *testing.T) {
		ns := uniqueNamespace(t)
		for _, name := range []string{"decoy-a", "decoy-b"} {
			if err := k8sClient.Create(testCtx, sampleDecoy(ns, name)); err != nil {
				t.Fatalf("creating Decoy %q: %v", name, err)
			}
		}
		if _, _, ok := resolveJoinAnnotation(testCtx, k8sClient, ns, joinAnnotationImplicit); ok {
			t.Fatal("expected true to not resolve when the namespace has more than one Decoy")
		}
	})
}

// TestListJoinedPods_ImplicitTrueAnnotation proves the "true" shorthand
// end to end through the reconciler: a same-namespace Pod using "true"
// gets joined exactly like one using the explicit annotation form.
func TestListJoinedPods_ImplicitTrueAnnotation(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "implicit-joiner", Namespace: ns,
		Annotations: map[string]string{joinAnnotation: joinAnnotationImplicit},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "example/worker:1.0"}}}}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}

	r := newReconciler()
	joined, err := r.listJoinedPods(testCtx, kt)
	if err != nil {
		t.Fatalf("listJoinedPods: %v", err)
	}
	if len(joined) != 1 || joined[0].Name != "implicit-joiner" {
		t.Fatalf("expected exactly the implicit-joiner pod to be joined, got: %+v", joined)
	}
}

// TestReconcile_DeleteRemovesDecoy covers the delete leg of the CRD
// lifecycle: envtest has no garbage-collector controller, so cascading
// deletion of owned resources is proven on the real zeno cluster (e2e); here
// we prove the owner references that make that cascade possible are correct
// and that the Decoy object itself deletes cleanly.
func TestReconcile_DeleteRemovesDecoy(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep); err != nil {
		t.Fatal(err)
	}
	var honeypodUID = kt.UID
	if err := k8sClient.Get(testCtx, req.NamespacedName, kt); err != nil {
		t.Fatal(err)
	}
	if dep.OwnerReferences[0].UID != kt.UID {
		t.Fatalf("owner UID mismatch: dep owner=%s kt=%s", dep.OwnerReferences[0].UID, honeypodUID)
	}

	if err := k8sClient.Delete(testCtx, kt); err != nil {
		t.Fatalf("deleting Decoy: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile after delete failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var got honeypodv1alpha1.Decoy
		err := k8sClient.Get(testCtx, req.NamespacedName, &got)
		if err != nil {
			return // deleted
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Decoy was not deleted within timeout")
}

// TestReconcile_DeleteCleansUpMirroredSecretsInOtherNamespaces covers
// mirroredSecretsFinalizer: a cross-namespace mirrored credentials Secret
// can't carry an OwnerReference back to its Decoy, so it must be cleaned
// up explicitly on delete.
func TestReconcile_DeleteCleansUpMirroredSecretsInOtherNamespaces(t *testing.T) {
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)
	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "cross-ns-joiner", Namespace: podNS,
		Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "example/worker:1.0"}}}}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	mirrorKey := types.NamespacedName{Namespace: podNS, Name: mirroredSecretName(kt.Name)}
	if err := k8sClient.Get(testCtx, mirrorKey, &corev1.Secret{}); err != nil {
		t.Fatalf("expected mirrored secret to exist after join: %v", err)
	}

	if err := k8sClient.Delete(testCtx, kt); err != nil {
		t.Fatalf("deleting Decoy: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 3 (finalizer cleanup) failed: %v", err)
	}

	if err := k8sClient.Get(testCtx, mirrorKey, &corev1.Secret{}); err == nil {
		t.Fatal("expected the mirrored secret to be deleted once its owning Decoy is deleted")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for mirror deletion: %v", err)
	}

	if err := k8sClient.Get(testCtx, req.NamespacedName, &honeypodv1alpha1.Decoy{}); err == nil {
		t.Fatal("expected the Decoy to be gone once its finalizer was removed")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for Decoy deletion: %v", err)
	}
}

// TestReconcile_NotifiesAlertOnPodJoin proves the full wire-up end to
// end: a real reconcile diffing joined pods against a real Alert+Provider
// (generic-webhook) actually results in an HTTP POST, not just that the
// pieces compile together.
func TestReconcile_NotifiesAlertOnPodJoin(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: ns},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "generic-webhook", Address: srv.URL},
	}
	if err := k8sClient.Create(testCtx, provider); err != nil {
		t.Fatalf("creating Provider: %v", err)
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alerts", Namespace: ns},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "generic-webhook"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: kt.Name}},
		},
	}
	if err := k8sClient.Create(testCtx, alert); err != nil {
		t.Fatalf("creating Alert: %v", err)
	}

	r := &DecoyReconciler{Client: k8sClient, Scheme: clientgoscheme.Scheme, Notifier: notifier.New(k8sClient)}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1 failed: %v", err)
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "worker", Namespace: uniqueNamespace(t),
		Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}

	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 2 failed: %v", err)
	}

	if gotBody == nil {
		t.Fatal("expected the generic-webhook Provider to receive a PodJoin notification")
	}
	var msg struct {
		EventType string `json:"eventType"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(gotBody, &msg); err != nil {
		t.Fatalf("decoding notification body: %v", err)
	}
	if msg.EventType != "PodJoin" || !strings.Contains(msg.Message, "joined") {
		t.Fatalf("unexpected notification: %+v", msg)
	}
}

// reconciledDecoyWithService creates and reconciles a Decoy, returning
// it (refreshed from the API, so Status is populated) and its Service's
// ClusterIP -- the shared setup every Gap-1 admission-webhook test below
// needs, since PodJoinMutator.MutatePod requires a real, reconciled
// Decoy + Service to have anything to inject.
func reconciledDecoyWithService(t *testing.T, ns, name string) (*honeypodv1alpha1.Decoy, string) {
	t.Helper()
	kt := sampleDecoy(ns, name)
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	var svc corev1.Service
	if err := k8sClient.Get(testCtx, req.NamespacedName, &svc); err != nil {
		t.Fatalf("getting service: %v", err)
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		t.Fatalf("expected a real allocated ClusterIP, got %q", svc.Spec.ClusterIP)
	}
	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	return &got, svc.Spec.ClusterIP
}

// findVolumeMount returns the VolumeMount named name on the given
// container, if any.
func findVolumeMount(c corev1.Container, name string) (corev1.VolumeMount, bool) {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return m, true
		}
	}
	return corev1.VolumeMount{}, false
}

// TestPodJoinMutator_MutatePod covers the join webhook's core
// decision logic (internal/controller/join_webhook.go) directly -- no HTTP,
// no AdmissionReview encoding, just PodJoinMutator.MutatePod against a
// real envtest apiserver holding a real, reconciled Decoy + Service.
func TestPodJoinMutator_MutatePod(t *testing.T) {
	t.Run("no annotation is a no-op", func(t *testing.T) {
		ns := uniqueNamespace(t)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: ns},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated != nil {
			t.Fatalf("expected no mutation for an unannotated pod, got: %+v", mutated)
		}
	})

	t.Run("dangling annotation is a no-op, not an error", func(t *testing.T) {
		ns := uniqueNamespace(t)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "dangling", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/does-not-exist"},
		}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated != nil {
			t.Fatalf("expected no mutation for a dangling annotation, got: %+v", mutated)
		}
	})

	t.Run("Decoy exists but not yet reconciled (no Service) is a no-op", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt := sampleDecoy(ns, "unreconciled-decoy")
		if err := k8sClient.Create(testCtx, kt); err != nil {
			t.Fatalf("creating Decoy: %v", err)
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "early-joiner", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated != nil {
			t.Fatalf("expected no mutation before the Decoy's Service exists, got: %+v", mutated)
		}
	})

	t.Run("same-namespace pod mounts the primary -decoy secret directly", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt, clusterIP := reconciledDecoyWithService(t, ns, "checkout-api-decoy")

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "same-ns-joiner", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "existing-init", Image: "example/init:1.0"}},
			Containers:     []corev1.Container{{Name: "app", Image: "example/app:1.0"}},
		}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}

		if len(mutated.Spec.InitContainers) != 1 || mutated.Spec.InitContainers[0].Name != "existing-init" {
			t.Fatalf("expected no new init container -- this mutator uses the env-var redirect, not redirect-init -- got: %+v", mutated.Spec.InitContainers)
		}

		mount, ok := findVolumeMount(mutated.Spec.Containers[0], "kube-api-access-decoy")
		if !ok || mount.MountPath != serviceAccountTokenMountPath {
			t.Fatalf("expected the app container to mount the decoy token at %s, got: %+v", serviceAccountTokenMountPath, mutated.Spec.Containers[0].VolumeMounts)
		}
		if _, ok := findVolumeMount(mutated.Spec.InitContainers[0], "kube-api-access-decoy"); !ok {
			t.Fatal("expected the pod's pre-existing init container to also get the decoy token mount")
		}

		var vol *corev1.Volume
		for i := range mutated.Spec.Volumes {
			if mutated.Spec.Volumes[i].Name == "kube-api-access-decoy" {
				vol = &mutated.Spec.Volumes[i]
			}
		}
		if vol == nil || vol.Projected == nil || vol.Projected.Sources[0].Secret == nil {
			t.Fatal("expected a projected decoy token volume")
		}
		if got := vol.Projected.Sources[0].Secret.Name; got != kt.Name+"-decoy" {
			t.Fatalf("expected a same-namespace pod to reference the primary -decoy secret, got %q", got)
		}

		// The redirect itself: an explicit KUBERNETES_SERVICE_HOST/PORT env
		// var wins over kubelet's own service-link injection on a name
		// collision, so client-go's rest.InClusterConfig() -- and anything
		// following that convention -- talks to the decoy with no packet
		// interception needed at all.
		envMap := map[string]string{}
		for _, e := range mutated.Spec.Containers[0].Env {
			envMap[e.Name] = e.Value
		}
		if envMap["KUBERNETES_SERVICE_HOST"] != clusterIP {
			t.Fatalf("expected KUBERNETES_SERVICE_HOST=%s, got env=%+v", clusterIP, mutated.Spec.Containers[0].Env)
		}
		if envMap["KUBERNETES_SERVICE_PORT"] != fmt.Sprintf("%d", servicePort(kt)) {
			t.Fatalf("expected KUBERNETES_SERVICE_PORT=%d, got env=%+v", servicePort(kt), mutated.Spec.Containers[0].Env)
		}
	})

	// TestPodJoinMutator_SuppressesServiceLinksAndFullyOverridesKubernetesEnv
	// covers a leak found on a live cluster: kubelet injects one env-var
	// family per Service in a Pod's own namespace (legacy "service links"),
	// and this Decoy's own Service matches whenever the Decoy and the
	// Pod it joins share a namespace. Without this, a joined pod carried a
	// second, unexplained *_SERVICE_HOST/*_PORT_<n>_TCP family naming the
	// honeypot's ClusterIP and its kubelet-shim port 10250 directly.
	//
	// Separately, only KUBERNETES_SERVICE_HOST/PORT were overridden, so the
	// rest of the standard "kubernetes" service-link family
	// (KUBERNETES_PORT_<n>_TCP_ADDR and friends) still named the real
	// cluster right next to the overridden pair -- an inconsistency an
	// attacker reading full env would notice immediately.
	t.Run("suppresses service-links and fully overrides the kubernetes env family", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt, clusterIP := reconciledDecoyWithService(t, ns, "same-ns-decoy")

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "leak-check", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}

		if mutated.Spec.EnableServiceLinks == nil || *mutated.Spec.EnableServiceLinks {
			t.Fatal("expected EnableServiceLinks=false, or kubelet injects a second env-var family named after this Decoy's own Service")
		}

		// The var NAMES take their port number from the real cluster's own
		// "kubernetes" Service (envtest doesn't run the apiserver's
		// bootstrap reconciler that creates it, so this exercises the
		// documented fallback: realKubernetesServicePortDefault, 443).
		// Only the VALUES point at the decoy.
		port := fmt.Sprintf("%d", servicePort(kt))
		const realPort = "443"
		want := map[string]string{
			"KUBERNETES_SERVICE_HOST":                    clusterIP,
			"KUBERNETES_SERVICE_PORT":                    port,
			"KUBERNETES_SERVICE_PORT_HTTPS":              port,
			"KUBERNETES_PORT":                            "tcp://" + clusterIP + ":" + port,
			"KUBERNETES_PORT_" + realPort + "_TCP":       "tcp://" + clusterIP + ":" + port,
			"KUBERNETES_PORT_" + realPort + "_TCP_PROTO": "tcp",
			"KUBERNETES_PORT_" + realPort + "_TCP_PORT":  port,
			"KUBERNETES_PORT_" + realPort + "_TCP_ADDR":  clusterIP,
		}
		envMap := map[string]string{}
		for _, e := range mutated.Spec.Containers[0].Env {
			envMap[e.Name] = e.Value
		}
		for name, wantVal := range want {
			if got := envMap[name]; got != wantVal {
				t.Fatalf("%s: got %q, want %q -- a partial override leaves the real cluster's address alongside the decoy's, env=%+v",
					name, got, wantVal, mutated.Spec.Containers[0].Env)
			}
		}
	})

	// TestPodJoinMutator_DiscoversRealKubernetesServicePort covers
	// realKubernetesServicePort's live-lookup path, not just its fallback:
	// a cluster whose own "kubernetes" Service uses a non-default port
	// must have the override's var names follow it, or kubelet's own
	// family under the real port survives untouched beside ours.
	t.Run("names the override vars after a discovered, non-default kubernetes Service port", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt, clusterIP := reconciledDecoyWithService(t, ns, "custom-port-decoy")

		// envtest's own apiserver eventually creates a real "kubernetes"
		// Service in "default" on its own internal timer (the same
		// bootstrap reconciler a real cluster's apiserver runs), so
		// whether it already exists by the time this subtest runs is a
		// race, not something this test can assume either way. Handle
		// both: update it in place if it's there, create it if it isn't.
		var realSvc corev1.Service
		err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, &realSvc)
		switch {
		case apierrors.IsNotFound(err):
			realSvc = corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
				Spec: corev1.ServiceSpec{
					Ports:     []corev1.ServicePort{{Name: "https", Port: 8443, TargetPort: intstr.FromInt(6443)}},
					ClusterIP: corev1.ClusterIPNone,
				},
			}
			if err := k8sClient.Create(testCtx, &realSvc); err != nil {
				t.Fatalf("creating a stand-in kubernetes Service: %v", err)
			}
			t.Cleanup(func() { _ = k8sClient.Delete(testCtx, &realSvc) })
		case err == nil:
			original := realSvc.Spec.Ports
			realSvc.Spec.Ports = []corev1.ServicePort{{Name: "https", Port: 8443, TargetPort: intstr.FromInt(6443)}}
			if err := k8sClient.Update(testCtx, &realSvc); err != nil {
				t.Fatalf("pointing the real kubernetes Service at port 8443: %v", err)
			}
			t.Cleanup(func() {
				var cur corev1.Service
				if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, &cur); err == nil {
					cur.Spec.Ports = original
					_ = k8sClient.Update(testCtx, &cur)
				}
			})
		default:
			t.Fatalf("getting the kubernetes Service: %v", err)
		}

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "custom-port-joiner", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}

		envMap := map[string]string{}
		for _, e := range mutated.Spec.Containers[0].Env {
			envMap[e.Name] = e.Value
		}
		wantName := "KUBERNETES_PORT_8443_TCP_ADDR"
		if got, ok := envMap[wantName]; !ok || got != clusterIP {
			t.Fatalf("expected %s=%s (following the discovered port 8443), got env=%+v", wantName, clusterIP, mutated.Spec.Containers[0].Env)
		}
		if _, ok := envMap["KUBERNETES_PORT_443_TCP_ADDR"]; ok {
			t.Fatalf("a stray KUBERNETES_PORT_443_TCP_ADDR means the override used the fallback port instead of the discovered 8443, env=%+v", mutated.Spec.Containers[0].Env)
		}
	})

	// Standard, documented admission-controller-chain behavior (not
	// exercised against a live cluster in this change -- see README's
	// "what's proven at which level" for this feature): a pod admitted
	// through the real admission chain already carries the built-in
	// ServiceAccount controller's own "kube-api-access-<random>"
	// volume/mount by the time a mutating webhook sees it (that controller
	// runs before webhook admission) -- without stripping it, the Pod ends
	// up with two ServiceAccount-token mounts at effectively the same path
	// (differing only by a trailing slash), an undefined double-mount that
	// could leave the *real* token winning over the decoy at exactly the
	// path an attacker checks first. This test simulates that admission-
	// controller output directly (MutatePod is called on a Pod that already
	// has it, the same shape the real chain hands the webhook) rather than
	// needing a live apiserver's ServiceAccount admission to reproduce it.
	t.Run("strips the real auto-mounted ServiceAccount token before adding the decoy", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt, _ := reconciledDecoyWithService(t, ns, "checkout-api-decoy")

		realVol := corev1.Volume{Name: "kube-api-access-abcde", VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{},
		}}
		realMount := corev1.VolumeMount{Name: "kube-api-access-abcde", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "already-admitted", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{
			Volumes:    []corev1.Volume{realVol},
			Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0", VolumeMounts: []corev1.VolumeMount{realMount}}},
		}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}

		for _, v := range mutated.Spec.Volumes {
			if v.Name == "kube-api-access-abcde" {
				t.Fatalf("expected the real auto-mounted volume to be stripped, still present: %+v", mutated.Spec.Volumes)
			}
		}
		for _, vm := range mutated.Spec.Containers[0].VolumeMounts {
			if vm.Name == "kube-api-access-abcde" {
				t.Fatalf("expected the real auto-mounted VolumeMount to be stripped, still present: %+v", mutated.Spec.Containers[0].VolumeMounts)
			}
		}
		if len(mutated.Spec.Containers[0].VolumeMounts) != 1 || mutated.Spec.Containers[0].VolumeMounts[0].Name != "kube-api-access-decoy" {
			t.Fatalf("expected exactly one ServiceAccount-token-shaped mount left (the decoy), got: %+v", mutated.Spec.Containers[0].VolumeMounts)
		}
		if mutated.Spec.AutomountServiceAccountToken == nil || *mutated.Spec.AutomountServiceAccountToken {
			t.Fatal("expected AutomountServiceAccountToken to be explicitly set to false")
		}
	})

	// Confirmed live on zeno: a cluster running Kyverno with a mutate
	// policy that reasserts automountServiceAccountToken can leave a pod
	// with two mounts at the ServiceAccount path, one of them not named
	// "kube-api-access-*" so the name-based strip alone misses it. This
	// simulates that shape directly.
	t.Run("strips a same-path mount even under a non-standard volume name", func(t *testing.T) {
		ns := uniqueNamespace(t)
		kt, _ := reconciledDecoyWithService(t, ns, "checkout-api-decoy")

		strayVol := corev1.Volume{Name: "some-other-token", VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{},
		}}
		strayMount := corev1.VolumeMount{Name: "some-other-token", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount/", ReadOnly: true}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "duplicate-mount-shape", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		}, Spec: corev1.PodSpec{
			Volumes:    []corev1.Volume{strayVol},
			Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0", VolumeMounts: []corev1.VolumeMount{strayMount}}},
		}}
		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}

		if len(mutated.Spec.Containers[0].VolumeMounts) != 1 || mutated.Spec.Containers[0].VolumeMounts[0].Name != "kube-api-access-decoy" {
			t.Fatalf("expected exactly one mount at the ServiceAccount path (the decoy), got: %+v", mutated.Spec.Containers[0].VolumeMounts)
		}
		for _, v := range mutated.Spec.Volumes {
			if v.Name == "some-other-token" {
				t.Fatalf("expected the stray same-path volume to be stripped, still present: %+v", mutated.Spec.Volumes)
			}
		}
	})

	t.Run("cross-namespace pod references the mirrored credentials secret", func(t *testing.T) {
		ktNS := uniqueNamespace(t)
		podNS := uniqueNamespace(t)
		kt := sampleDecoy(ktNS, "checkout-api-decoy")
		if err := k8sClient.Create(testCtx, kt); err != nil {
			t.Fatalf("creating Decoy: %v", err)
		}

		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "cross-ns-joiner", Namespace: podNS,
			Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
		}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "example/worker:1.0"}}}}
		if err := k8sClient.Create(testCtx, pod); err != nil {
			t.Fatalf("creating pod: %v", err)
		}

		// Reconciling the Decoy now (pod already exists and is
		// discovered via listJoinedPods) both stands up the Service the
		// mutator needs and mirrors the credentials secret into podNS --
		// see reconcileMirroredSecrets.
		r := newReconciler()
		req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		var mirror corev1.Secret
		if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: podNS, Name: mirroredSecretName(kt.Name)}, &mirror); err != nil {
			t.Fatalf("expected a mirrored credentials secret in %s: %v", podNS, err)
		}
		var primary corev1.Secret
		if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ktNS, Name: kt.Name + "-decoy"}, &primary); err != nil {
			t.Fatalf("getting primary decoy secret: %v", err)
		}
		if string(mirror.Data["token"]) != string(primary.Data["token"]) || string(mirror.Data["ca.crt"]) != string(primary.Data["ca.crt"]) {
			t.Fatal("mirrored secret's token/ca.crt must match the primary decoy secret")
		}
		if _, ok := mirror.Data["tls.key"]; ok {
			t.Fatal("mirrored secret must not carry the primary secret's TLS private key")
		}
		if _, ok := mirror.Data["sa.key"]; ok {
			t.Fatal("mirrored secret must not carry the primary secret's service-account signing key")
		}

		m := &PodJoinMutator{Client: k8sClient}
		mutated, err := m.MutatePod(testCtx, pod)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mutated == nil {
			t.Fatal("expected a mutation")
		}
		var vol *corev1.Volume
		for i := range mutated.Spec.Volumes {
			if mutated.Spec.Volumes[i].Name == "kube-api-access-decoy" {
				vol = &mutated.Spec.Volumes[i]
			}
		}
		if vol == nil || vol.Projected == nil || vol.Projected.Sources[0].Secret == nil {
			t.Fatal("expected a projected decoy token volume")
		}
		if got := vol.Projected.Sources[0].Secret.Name; got != mirroredSecretName(kt.Name) {
			t.Fatalf("expected a cross-namespace pod to reference the mirrored secret %q, got %q", mirroredSecretName(kt.Name), got)
		}
	})
}

// TestReconcileMirroredSecrets_CleansUpStaleMirrors covers the half
// of buildMirroredSecret's design that TestPodJoinMutator_MutatePod
// above doesn't: OwnerReferences can't garbage-collect a cross-namespace
// Secret, so reconcileMirroredSecrets has to delete a mirror
// explicitly once its namespace no longer has any joined pod for this
// Decoy.
func TestReconcileMirroredSecrets_CleansUpStaleMirrors(t *testing.T) {
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)
	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "temp-joiner", Namespace: podNS,
		Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Image: "example/worker:1.0"}}}}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating pod: %v", err)
	}

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1 failed: %v", err)
	}
	mirrorKey := types.NamespacedName{Namespace: podNS, Name: mirroredSecretName(kt.Name)}
	if err := k8sClient.Get(testCtx, mirrorKey, &corev1.Secret{}); err != nil {
		t.Fatalf("expected mirrored secret to exist after join: %v", err)
	}

	if err := k8sClient.Delete(testCtx, pod); err != nil {
		t.Fatalf("deleting joined pod: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 2 failed: %v", err)
	}
	if err := k8sClient.Get(testCtx, mirrorKey, &corev1.Secret{}); err == nil {
		t.Fatal("expected the mirrored secret to be deleted once its namespace has no more joined pods")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected error checking for mirror deletion: %v", err)
	}
}

// TestPodMutationHandler_ServeHTTP exercises the real HTTP handler
// (NewPodMutationHandler) end to end at the AdmissionReview layer: a
// synthetic *admissionv1.AdmissionReview request is constructed by hand
// (as a real webhook caller -- the apiserver -- would build one) and POSTed
// to the actual handler code via httptest, proving the JSON encode/decode
// and JSON-patch construction, not just PodJoinMutator.MutatePod in
// isolation.
func TestPodMutationHandler_ServeHTTP(t *testing.T) {
	ns := uniqueNamespace(t)
	kt, _ := reconciledDecoyWithService(t, ns, "checkout-api-decoy")

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "http-joiner", Namespace: ns,
			Annotations: map[string]string{joinAnnotation: ns + "/" + kt.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}},
	}
	podRaw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshaling pod: %v", err)
	}

	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:    "test-uid-1",
			Object: runtime.RawExtension{Raw: podRaw},
		},
	}
	reqBody, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshaling review: %v", err)
	}

	handler := NewPodMutationHandler(&PodJoinMutator{Client: k8sClient})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("posting admission review: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var out admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatalf("expected an allowed response, got: %+v", out.Response)
	}
	if out.Response.UID != "test-uid-1" {
		t.Fatalf("expected the request UID echoed back, got %q", out.Response.UID)
	}
	if out.Response.PatchType == nil || *out.Response.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("expected a JSONPatch patch type, got: %+v", out.Response.PatchType)
	}
	var patchOps []map[string]any
	if err := json.Unmarshal(out.Response.Patch, &patchOps); err != nil {
		t.Fatalf("decoding patch: %v", err)
	}
	if len(patchOps) == 0 {
		t.Fatal("expected a non-empty JSON patch")
	}
	patchJSON := string(out.Response.Patch)
	if !strings.Contains(patchJSON, "KUBERNETES_SERVICE_HOST") {
		t.Fatalf("expected the patch to inject the KUBERNETES_SERVICE_HOST override, got: %s", patchJSON)
	}
	if !strings.Contains(patchJSON, "kube-api-access-decoy") {
		t.Fatalf("expected the patch to inject the decoy token volume, got: %s", patchJSON)
	}
}

// TestPatchMutatingWebhookCABundle proves the real CA-bundle-patching logic
// (webhookcert.go) against a real envtest apiserver object: a
// MutatingWebhookConfiguration with a placeholder empty caBundle, exactly
// as shipped in config/manager/webhook.yaml, ending up with the given CA
// PEM bytes in every webhook entry after PatchMutatingWebhookCABundle runs.
// TestWebhookCABundle_PatchesOnFirstReconcile covers the initial fill-in
// against a real apiserver: config/manager/webhook.yaml ships with an empty
// clientConfig.caBundle placeholder, and WebhookCABundleReconciler is the
// only thing that ever sets it, on its first pass over the object it
// watches. Empty means the apiserver cannot verify the join webhook's
// serving cert, and with failurePolicy: Ignore every join silently no-ops.
func TestWebhookCABundle_PatchesOnFirstReconcile(t *testing.T) {
	requireEnvtest(t)
	name := "test-honeypod-pod-join"
	ignore := admissionregistrationv1.Ignore
	none := admissionregistrationv1.SideEffectClassNone
	webhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name:                    "podjoin.honeypod.io",
			AdmissionReviewVersions: []string{"v1"},
			SideEffects:             &none,
			FailurePolicy:           &ignore,
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL: strPtr("https://example.invalid/mutate-pods"),
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
				},
			}},
		}},
	}
	if err := k8sClient.Create(testCtx, webhookConfig); err != nil {
		t.Fatalf("creating MutatingWebhookConfiguration: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(testCtx, webhookConfig) })

	caPEM := []byte("-----BEGIN CERTIFICATE-----\nfake-ca-for-test\n-----END CERTIFICATE-----\n")
	r := &WebhookCABundleReconciler{Client: k8sClient, ConfigName: name, CABundle: caPEM}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var got admissionregistrationv1.MutatingWebhookConfiguration
	if err := k8sClient.Get(testCtx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Webhooks) != 1 || string(got.Webhooks[0].ClientConfig.CABundle) != string(caPEM) {
		t.Fatalf("expected caBundle to be patched to the given CA PEM, got: %s", got.Webhooks[0].ClientConfig.CABundle)
	}

	// Already correct: a second pass must not write again, or every
	// reconcile would wake the next one off its own watch event.
	rvBefore := got.ResourceVersion
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if err := k8sClient.Get(testCtx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.ResourceVersion != rvBefore {
		t.Fatalf("expected an already-correct caBundle to be left untouched, but the object was rewritten (%s -> %s)", rvBefore, got.ResourceVersion)
	}
}

// TestEnsureWebhookServingCert_PersistsAcrossCalls covers the fix for a
// real bug found live on zeno: regenerating the webhook's cert on every
// manager restart meant the real apiserver's admission-webhook trust cache
// (which doesn't refresh instantly) rejected the new cert for a while after
// every restart, and failurePolicy: Ignore silently skipped pod joins
// the whole time. Calling this twice, like two manager starts would, must
// return the exact same cert both times.
func TestEnsureWebhookServingCert_PersistsAcrossCalls(t *testing.T) {
	ns := uniqueNamespace(t)
	dnsNames := []string{"localhost", "127.0.0.1"}

	cert1, ca1, err := EnsureWebhookServingCert(testCtx, k8sClient, ns, "webhook-tls", dnsNames)
	if err != nil {
		t.Fatalf("first EnsureWebhookServingCert: %v", err)
	}
	cert2, ca2, err := EnsureWebhookServingCert(testCtx, k8sClient, ns, "webhook-tls", dnsNames)
	if err != nil {
		t.Fatalf("second EnsureWebhookServingCert: %v", err)
	}

	if len(cert1.Certificate) == 0 || len(cert2.Certificate) == 0 {
		t.Fatal("expected both calls to return a non-empty certificate")
	}
	if string(cert1.Certificate[0]) != string(cert2.Certificate[0]) {
		t.Fatal("expected the second call to reuse the first call's cert, got a different one")
	}
	if string(ca1) != string(ca2) {
		t.Fatal("expected the second call to reuse the first call's CA, got a different one")
	}
}

func strPtr(s string) *string { return &s }

// drainEvents returns every event currently buffered on a FakeRecorder,
// without blocking. Recorder.Event writes synchronously, so events emitted
// during a Reconcile are already present by the time it returns.
func drainEvents(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func anyContains(events []string, substr string) bool {
	for _, e := range events {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// TestReconcile_EmitsEvents covers Finding 2's fix: the reconciler records
// Kubernetes Events on the Decoy for the Ready transition and for a pod
// joining, on the transition edge only.
func TestReconcile_EmitsEvents(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	rec := record.NewFakeRecorder(32)
	r := newReconciler()
	r.Recorder = rec
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}

	// First reconcile: still Pending (no ready replica), so no Ready event.
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}
	if anyContains(drainEvents(rec), "Ready") {
		t.Fatal("did not expect a Ready event while the Decoy is Pending")
	}

	// Simulate the Deployment becoming ready, then reconcile: Ready event.
	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &dep); err != nil {
		t.Fatalf("getting deployment: %v", err)
	}
	dep.Status.ReadyReplicas = 1
	dep.Status.Replicas = 1
	if err := k8sClient.Status().Update(testCtx, &dep); err != nil {
		t.Fatalf("simulating deployment readiness: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}
	if !anyContains(drainEvents(rec), "Ready") {
		t.Fatal("expected a Ready event once the Decoy became Ready")
	}

	// Annotate a real pod to join, then reconcile: PodJoined event.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "joiner",
			Namespace:   ns,
			Annotations: map[string]string{"honeypod.io/join": ns + "/" + kt.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "img:1"}}},
	}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating joiner pod: %v", err)
	}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile 3: %v", err)
	}
	if !anyContains(drainEvents(rec), "PodJoined") {
		t.Fatal("expected a PodJoined event after annotating a pod")
	}
}

// TestDecoyValidation_ExecIsolationRequiresRuntimeClass covers Gap 1: the CRD
// rejects spec.execIsolation without spec.runtimeClassName, so the added
// privilege (root, CAP_SYS_ADMIN, unconfined seccomp) is always bounded by a
// sandboxed runtime rather than the host kernel.
func TestDecoyValidation_ExecIsolationRequiresRuntimeClass(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)

	bad := sampleDecoy(ns, "iso-no-runtime")
	bad.Spec.ExecIsolation = true
	if err := k8sClient.Create(testCtx, bad); err == nil {
		t.Fatal("expected execIsolation without runtimeClassName to be rejected by the CRD")
	}

	rc := "gvisor"
	ok := sampleDecoy(ns, "iso-with-runtime")
	ok.Spec.ExecIsolation = true
	ok.Spec.RuntimeClassName = &rc
	if err := k8sClient.Create(testCtx, ok); err != nil {
		t.Fatalf("execIsolation with runtimeClassName should be allowed: %v", err)
	}
}

// TestReconcile_NetworkPolicyNameAndLegacyPrune covers the ambiguity fix: the
// NetworkPolicy is named "<name>-egress" (not the bare decoy name shared by
// the Deployment and Service), and a pre-rename NetworkPolicy this Decoy owns
// is pruned on reconcile while an unrelated one keeping the old name is left
// alone.
func TestReconcile_NetworkPolicyNameAndLegacyPrune(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	// A legacy NetworkPolicy at the bare decoy name, owned by the Decoy, as a
	// pre-rename decoy would have.
	owned := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: kt.Name, Namespace: ns},
		Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}},
	}
	if err := controllerutil.SetControllerReference(kt, owned, k8sClient.Scheme()); err != nil {
		t.Fatalf("owner ref: %v", err)
	}
	if err := k8sClient.Create(testCtx, owned); err != nil {
		t.Fatalf("creating legacy NP: %v", err)
	}

	r := newReconciler()
	if _, err := r.Reconcile(testCtx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The new NetworkPolicy carries the -egress suffix.
	var np networkingv1.NetworkPolicy
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-egress"}, &np); err != nil {
		t.Fatalf("expected NetworkPolicy %q: %v", kt.Name+"-egress", err)
	}
	// The owned legacy one is pruned.
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name}, &networkingv1.NetworkPolicy{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected the owned legacy NetworkPolicy to be pruned, got err=%v", err)
	}
}
