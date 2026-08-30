package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/certs"
	"honeypod.io/honeypod/internal/seed"
)

// TestDecoySpec_ResourcesDefaultsOnCreate covers the real apiserver
// actually applying spec.resources' CRD default (added so this deploys
// cleanly in a namespace with a ResourceQuota and no LimitRange, which
// otherwise rejects any pod that doesn't declare limits at all -- confirmed
// live on zeno). A Decoy created with resources left unset should come
// back with the default filled in, not an empty ResourceRequirements.
//
// Built as unstructured YAML-shaped data, not the typed Decoy Go
// struct: Go's encoding/json "omitempty" has no effect on a plain (non-
// pointer) struct field, so a typed client.Create() always sends
// "resources":{} explicitly and never actually exercises the default --
// only a request that omits the key entirely does, the same as every real
// `kubectl apply -f` deployment of this project actually sends.
func TestDecoySpec_ResourcesDefaultsOnCreate(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "honeypod.io/v1alpha1",
		"kind":       "Decoy",
		"metadata":   map[string]interface{}{"name": "no-resources-set", "namespace": ns},
		"spec": map[string]interface{}{
			"kubeletShimImage": "honeypod/kubelet-shim:latest",
			"fakeNodes":        []interface{}{map[string]interface{}{"name": "decoy-node-1"}},
		},
	}}
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, client.ObjectKeyFromObject(kt), &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}

	wantLimits := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("256Mi")}
	wantRequests := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")}
	for name, want := range wantLimits {
		if got := got.Spec.Resources.Limits[name]; got.Cmp(want) != 0 {
			t.Fatalf("expected default limits[%s]=%s, got %s", name, want.String(), got.String())
		}
	}
	for name, want := range wantRequests {
		if got := got.Spec.Resources.Requests[name]; got.Cmp(want) != 0 {
			t.Fatalf("expected default requests[%s]=%s, got %s", name, want.String(), got.String())
		}
	}
}

// forbiddenIdentityStrings are the project-identifying substrings that must
// never appear in anything a real exec session inside a decoy could read
// (a real `ls`/`cat` on any mounted path). Lowercase, since real paths are
// lowercase by convention.
var forbiddenIdentityStrings = []string{"honeypod", "decoy", "honeypot", "fake"}

// TestBuildDeployment_NoIdentityLeakInMountPaths is a static guard against
// the whole class of bug fixed earlier: kubelet-shim's own container used
// to mount its config/secrets at /etc/honeypod-secret and /etc/honeypod/,
// a real `ls /etc` in a real exec session would show directories literally
// named after this project. This checks every container's VolumeMounts
// directly, so any future change that reintroduces a project-named mount
// path fails here instead of needing another manual live sweep to catch.
func TestBuildDeployment_NoIdentityLeakInMountPaths(t *testing.T) {
	kt := sampleDecoy("billing", "checkout-api-decoy")
	dep := buildDeployment(kt, "checkout-api-decoy-decoy", "checkout-api-decoy-config", "somechecksum", "certsum", "10.0.0.5")

	check := func(containerName, mountPath string) {
		t.Helper()
		lower := strings.ToLower(mountPath)
		for _, bad := range forbiddenIdentityStrings {
			if strings.Contains(lower, bad) {
				t.Fatalf("container %q mounts at %q, which contains the identifying substring %q -- a real exec session could see this", containerName, mountPath, bad)
			}
		}
	}
	for _, c := range dep.Spec.Template.Spec.Containers {
		for _, vm := range c.VolumeMounts {
			check(c.Name, vm.MountPath)
		}
	}
	for _, c := range dep.Spec.Template.Spec.InitContainers {
		for _, vm := range c.VolumeMounts {
			check(c.Name, vm.MountPath)
		}
	}
}

// TestReconcile_ReportsFailureInStatus covers the observability gap found
// during end-to-end verification: a reconcile error used to leave status
// completely empty, so `kubectl get decoys` showed a blank phase and
// nothing explained the problem outside the controller's own log. A
// failure must land on the object itself: phase Failed, plus a
// Ready=False condition carrying the error text.
func TestReconcile_ReportsFailureInStatus(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "will-fail")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	// Block reconcile on a resource it must write: an immutable ConfigMap
	// already sitting on the name it needs. Realistic (someone pre-created
	// a conflicting object) and deterministic, since immutable ConfigMaps
	// reject every update.
	immutable := true
	blocker := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: kt.Name + "-config", Namespace: ns},
		Immutable:  &immutable,
		Data:       map[string]string{"seed.json": "blocked"},
	}
	if err := k8sClient.Create(testCtx, blocker); err != nil {
		t.Fatalf("creating blocking ConfigMap: %v", err)
	}

	r := newReconciler()
	if _, err := r.Reconcile(testCtx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(kt)}); err == nil {
		t.Fatal("expected reconcile to fail against the immutable ConfigMap")
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, client.ObjectKeyFromObject(kt), &got); err != nil {
		t.Fatalf("getting Decoy: %v", err)
	}
	if got.Status.Phase != honeypodv1alpha1.DecoyPhaseFailed {
		t.Fatalf("expected phase %q after a failed reconcile, got %q", honeypodv1alpha1.DecoyPhaseFailed, got.Status.Phase)
	}
	cond := apimeta.FindStatusCondition(got.Status.Conditions, "Ready")
	if cond == nil {
		t.Fatal("expected a Ready condition after a failed reconcile")
	}
	if cond.Status != metav1.ConditionFalse {
		t.Fatalf("expected Ready=False after a failed reconcile, got %q", cond.Status)
	}
	if !strings.Contains(cond.Message, "configmap") && !strings.Contains(cond.Message, "ConfigMap") {
		t.Fatalf("expected the condition message to carry the real error, got %q", cond.Message)
	}
}

// TestServedNamespace covers the leak found during end-to-end
// verification: an exec session's .../serviceaccount/namespace file used
// to report the Decoy CR's own outer-cluster namespace (typically named
// after this project), contradicting the namespace of the fake pod the
// attacker thought they were in. It must report a namespace visible
// inside the decoy instead.
func TestServedNamespace(t *testing.T) {
	t.Run("uses the first fake pod's namespace", func(t *testing.T) {
		kt := sampleDecoy("honeypod-decoy", "checkout-api-decoy")
		if got := servedNamespace(kt); got != "billing" {
			t.Fatalf("expected the fake pod's namespace \"billing\", got %q", got)
		}
	})

	t.Run("falls back to a fake secret's namespace", func(t *testing.T) {
		kt := sampleDecoy("honeypod-decoy", "checkout-api-decoy")
		kt.Spec.FakePods = nil
		if got := servedNamespace(kt); got != "billing" {
			t.Fatalf("expected the fake secret's namespace \"billing\", got %q", got)
		}
	})

	t.Run("falls back to default when nothing is seeded", func(t *testing.T) {
		kt := sampleDecoy("honeypod-decoy", "checkout-api-decoy")
		kt.Spec.FakePods = nil
		kt.Spec.FakeSecrets = nil
		if got := servedNamespace(kt); got != "default" {
			t.Fatalf("expected fallback \"default\", got %q", got)
		}
	})

	t.Run("never reports the Decoy's own namespace", func(t *testing.T) {
		kt := sampleDecoy("honeypod-decoy", "checkout-api-decoy")
		if got := servedNamespace(kt); got == kt.Namespace {
			t.Fatalf("servedNamespace leaked the operator-side namespace %q", got)
		}
	})
}

// TestRenderTokenAuthFile_SeparateShimIdentity covers the alert-fatigue
// bug found during end-to-end verification: kubelet-shim authenticated
// with the decoy token, so its own seeding (creating fake pods,
// namespaces, secrets) was attributed to kubernetes-admin, exactly what a
// real attacker looks like, and every decoy restart fired a burst of
// Alerts. The shim needs its own system: identity so the notability
// heuristic can drop its traffic without hiding an attacker's.
func TestRenderTokenAuthFile_SeparateShimIdentity(t *testing.T) {
	kt := sampleDecoy("honeypod-decoy", "checkout-api-decoy")
	got := string(renderTokenAuthFile(kt, "decoy-token-value", "shim-token-value", "kcm-token-value"))

	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three identities in the token-auth file, got %d: %q", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "decoy-token-value,kubernetes-admin,") {
		t.Fatalf("expected the decoy line first, got %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "shim-token-value,system:node:") {
		t.Fatalf("expected the shim line to use a system:node identity, got %q", lines[1])
	}
	// The decoy's own kube-controller-manager, under a system: identity so
	// its housekeeping traffic is filtered from attacker alerts.
	if !strings.HasPrefix(lines[2], "kcm-token-value,system:kube-controller-manager,") {
		t.Fatalf("expected the kcm line to use a system:kube-controller-manager identity, got %q", lines[2])
	}
	if lines[0] == lines[1] || lines[1] == lines[2] || lines[0] == lines[2] {
		t.Fatal("decoy, shim, and kcm must not share an identity")
	}
	// The whole point: notifier's heuristic filters on a system: username.
	if !strings.Contains(lines[1], ",system:node:"+kt.Spec.FakeNodes[0].Name+",") {
		t.Fatalf("expected the shim identity to name the seeded node, got %q", lines[1])
	}
}

// TestKubernetesVersion_ApiserverAndNodesStayConsistent covers the
// realism bug found during verification: the apiserver image and the
// version fake nodes report were independent, so pinning an older
// apiserver left the nodes claiming a newer version. Kubernetes' own skew
// policy makes a node newer than its control plane impossible, so that
// combination gives the decoy away outright.
func TestKubernetesVersion_ApiserverAndNodesStayConsistent(t *testing.T) {
	t.Run("one version drives both", func(t *testing.T) {
		kt := sampleDecoy("billing", "decoy")
		kt.Spec.KubernetesVersion = "v1.29.0"
		kt.Spec.KubeAPIServerImage = ""
		kt.Spec.FakeNodes = []honeypodv1alpha1.FakeNode{{Name: "node-a"}}

		if got := kubeAPIServerImage(kt); got != "registry.k8s.io/kube-apiserver:v1.29.0" {
			t.Fatalf("expected the apiserver image to follow kubernetesVersion, got %q", got)
		}

		raw, err := renderSeedJSON(kt, nil)
		if err != nil {
			t.Fatalf("rendering seed: %v", err)
		}
		var s seed.Seed
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("unmarshalling seed: %v", err)
		}
		if len(s.FakeNodes) != 1 || s.FakeNodes[0].KubeletVersion != "v1.29.0" {
			t.Fatalf("expected the seeded node to report v1.29.0, got %+v", s.FakeNodes)
		}
	})

	t.Run("an explicit node version still wins, so a node can lag", func(t *testing.T) {
		kt := sampleDecoy("billing", "decoy")
		kt.Spec.KubernetesVersion = "v1.31.0"
		kt.Spec.FakeNodes = []honeypodv1alpha1.FakeNode{{Name: "old", KubeletVersion: "v1.30.4"}}

		raw, err := renderSeedJSON(kt, nil)
		if err != nil {
			t.Fatalf("rendering seed: %v", err)
		}
		var s seed.Seed
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("unmarshalling seed: %v", err)
		}
		if s.FakeNodes[0].KubeletVersion != "v1.30.4" {
			t.Fatalf("expected the per-node override to survive, got %q", s.FakeNodes[0].KubeletVersion)
		}
	})

	t.Run("an explicit image overrides, version still drives nodes", func(t *testing.T) {
		kt := sampleDecoy("billing", "decoy")
		kt.Spec.KubernetesVersion = "v1.31.0"
		kt.Spec.KubeAPIServerImage = "registry.internal/kube-apiserver:v1.31.0"
		if got := kubeAPIServerImage(kt); got != "registry.internal/kube-apiserver:v1.31.0" {
			t.Fatalf("expected the explicit image to win, got %q", got)
		}
	})
}

// TestReconcile_TerminatingJoinedNamespaceDoesNotBlockDecoy covers an
// availability bug found during stability testing: deleting a namespace
// that still held an joined pod made every reconcile fail on "namespace
// is being terminated" while creating that namespace's mirrored
// credentials Secret. The decoy stayed Pending for the whole teardown,
// and a namespace wedged by a finalizer would have held it there
// indefinitely. An joined pod in a dying namespace is going away
// anyway, so that namespace is skipped instead.
func TestReconcile_TerminatingJoinedNamespaceDoesNotBlockDecoy(t *testing.T) {
	t.Run("a terminating-namespace error is recognised", func(t *testing.T) {
		err := apierrors.NewForbidden(
			schema.GroupResource{Resource: "secrets"}, "creds",
			errors.New("unable to create new content in namespace payments because it is being terminated"),
		)
		if !isNamespaceTerminating(err) {
			t.Fatalf("expected a terminating-namespace error to be recognised: %v", err)
		}
	})

	t.Run("other forbidden errors still fail the reconcile", func(t *testing.T) {
		err := apierrors.NewForbidden(
			schema.GroupResource{Resource: "secrets"}, "creds",
			errors.New("user cannot create secrets"),
		)
		if isNamespaceTerminating(err) {
			t.Fatal("an unrelated forbidden error must not be treated as a terminating namespace")
		}
	})

	t.Run("unrelated errors are not swallowed", func(t *testing.T) {
		if isNamespaceTerminating(errors.New("connection refused")) {
			t.Fatal("a plain error must not be treated as a terminating namespace")
		}
	})
}

// TestDecoySpec_RejectsDuplicateSeedEntries covers a bug found during
// stability testing: two fakePods sharing a name and namespace produced
// the same generated pod name, so the shim's own seeding pass conflicted
// with itself, crash-looped, and left the Decoy stuck in Pending with
// nothing in status explaining why. Duplicates are rejected up front now,
// so the user gets a clear message instead of a silent crash loop.
func TestDecoySpec_RejectsDuplicateSeedEntries(t *testing.T) {
	ns := uniqueNamespace(t)

	mk := func(name string, spec map[string]interface{}) *unstructured.Unstructured {
		spec["kubeletShimImage"] = "honeypod/kubelet-shim:latest"
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "honeypod.io/v1alpha1",
			"kind":       "Decoy",
			"metadata":   map[string]interface{}{"name": name, "namespace": ns},
			"spec":       spec,
		}}
	}
	pod := func(name, namespace string) map[string]interface{} {
		return map[string]interface{}{
			"name": name, "namespace": namespace,
			"containers": []interface{}{map[string]interface{}{"name": "c", "image": "x:1"}},
		}
	}

	t.Run("duplicate fakePods are rejected", func(t *testing.T) {
		err := k8sClient.Create(testCtx, mk("dup-pods", map[string]interface{}{
			"fakePods": []interface{}{pod("api", "prod"), pod("api", "prod")},
		}))
		if err == nil {
			t.Fatal("expected duplicate fakePods to be rejected")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			t.Fatalf("expected a clear duplicate-value message, got %v", err)
		}
	})

	t.Run("the same name in a different namespace is fine", func(t *testing.T) {
		if err := k8sClient.Create(testCtx, mk("ok-pods", map[string]interface{}{
			"fakePods": []interface{}{pod("api", "prod"), pod("api", "staging")},
		})); err != nil {
			t.Fatalf("same name in different namespaces must be allowed: %v", err)
		}
	})

	t.Run("duplicate fakeNodes are rejected", func(t *testing.T) {
		err := k8sClient.Create(testCtx, mk("dup-nodes", map[string]interface{}{
			"fakeNodes": []interface{}{
				map[string]interface{}{"name": "n1"},
				map[string]interface{}{"name": "n1"},
			},
		}))
		if err == nil {
			t.Fatal("expected duplicate fakeNodes to be rejected")
		}
	})

	t.Run("duplicate fakeSecrets are rejected", func(t *testing.T) {
		sec := func(n, ns string) map[string]interface{} {
			return map[string]interface{}{"name": n, "namespace": ns, "data": map[string]interface{}{"k": "v"}}
		}
		err := k8sClient.Create(testCtx, mk("dup-secrets", map[string]interface{}{
			"fakeSecrets": []interface{}{sec("creds", "prod"), sec("creds", "prod")},
		}))
		if err == nil {
			t.Fatal("expected duplicate fakeSecrets to be rejected")
		}
	})
}

// TestDecoySpec_RejectsDanglingNodeName covers unclear behaviour found
// during stability testing: a fakePod naming a node that isn't in
// fakeNodes still appeared Running, but `kubectl exec` on it failed with a
// misleading "pods <node> not found", and a pod on a node absent from
// `get nodes` is an impossible cluster state an attacker would notice.
func TestDecoySpec_RejectsDanglingNodeName(t *testing.T) {
	ns := uniqueNamespace(t)
	mk := func(name, nodeName string, nodes []interface{}) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "honeypod.io/v1alpha1",
			"kind":       "Decoy",
			"metadata":   map[string]interface{}{"name": name, "namespace": ns},
			"spec": map[string]interface{}{
				"fakeNodes": nodes,
				"fakePods": []interface{}{map[string]interface{}{
					"name": "app", "namespace": "prod", "nodeName": nodeName,
					"containers": []interface{}{map[string]interface{}{"name": "c", "image": "x:1"}},
				}},
			},
		}}
	}
	realNode := []interface{}{map[string]interface{}{"name": "node-a"}}

	t.Run("a dangling nodeName is rejected", func(t *testing.T) {
		err := k8sClient.Create(testCtx, mk("dangling", "ghost-node", realNode))
		if err == nil {
			t.Fatal("expected a fakePod on an unknown node to be rejected")
		}
		if !strings.Contains(err.Error(), "fakeNodes") {
			t.Fatalf("expected the message to point at fakeNodes, got %v", err)
		}
	})

	t.Run("a nodeName that exists is accepted", func(t *testing.T) {
		if err := k8sClient.Create(testCtx, mk("resolves", "node-a", realNode)); err != nil {
			t.Fatalf("a valid nodeName must be accepted: %v", err)
		}
	})

	t.Run("an empty nodeName is accepted and defaults", func(t *testing.T) {
		if err := k8sClient.Create(testCtx, mk("defaulted", "", realNode)); err != nil {
			t.Fatalf("an empty nodeName must be accepted: %v", err)
		}
	})
}

// TestReconcile_ReissuesServingCertWhenClusterIPChanges covers a bug found
// during continuous verification: the decoy Secret was returned unchanged
// whenever it already existed, so if the Service was recreated with a
// different ClusterIP the serving cert's SANs went stale. The apiserver
// dials kubelet-shim by IP for exec/attach/logs, so every one of those
// failed TLS verification while the Decoy still reported Ready:
//
//	x509: certificate is valid for 10.110.39.119, not 10.105.207.164
//
// The cert is reissued for the new address, and the decoy token, which an
// attacker may already hold, is deliberately left alone.
func TestReconcile_ReissuesServingCertWhenClusterIPChanges(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "cert-rotate")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}

	r := newReconciler()
	first, err := r.reconcileSecret(testCtx, kt, kt.Name+"-decoy", "10.0.0.10")
	if err != nil {
		t.Fatalf("first reconcileSecret: %v", err)
	}
	originalToken := string(first.Data["token"])
	if !certCoversIP(first.Data["tls.crt"], "10.0.0.10") {
		t.Fatal("expected the freshly issued cert to cover the ClusterIP")
	}

	// Same Secret, different Service address: what a Service recreation does.
	second, err := r.reconcileSecret(testCtx, kt, kt.Name+"-decoy", "10.0.0.99")
	if err != nil {
		t.Fatalf("second reconcileSecret: %v", err)
	}
	if !certCoversIP(second.Data["tls.crt"], "10.0.0.99") {
		t.Fatal("expected the cert to be reissued for the new ClusterIP")
	}
	if got := string(second.Data["token"]); got != originalToken {
		t.Fatal("the decoy token must survive a cert reissue, an attacker may already hold it")
	}

	// Stable once it matches: no needless churn on every reconcile.
	third, err := r.reconcileSecret(testCtx, kt, kt.Name+"-decoy", "10.0.0.99")
	if err != nil {
		t.Fatalf("third reconcileSecret: %v", err)
	}
	if string(third.Data["tls.crt"]) != string(second.Data["tls.crt"]) {
		t.Fatal("expected no reissue when the cert already covers the ClusterIP")
	}
}

// TestCertCoversIP covers the check that decides whether a reissue is
// needed, including the malformed inputs that must fail safe.
func TestCertCoversIP(t *testing.T) {
	caCert, caKey, err := certs.GenerateCA("kubernetes")
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}
	leaf, _, err := certs.IssueServerCert(caCert, caKey, []string{"svc.example", "127.0.0.1", "10.1.2.3"})
	if err != nil {
		t.Fatalf("issuing cert: %v", err)
	}

	if !certCoversIP(leaf, "10.1.2.3") {
		t.Fatal("expected a listed IP to be covered")
	}
	if certCoversIP(leaf, "10.9.9.9") {
		t.Fatal("expected an unlisted IP not to be covered")
	}
	for name, in := range map[string][]byte{"empty": nil, "garbage": []byte("not a cert")} {
		if certCoversIP(in, "10.1.2.3") {
			t.Fatalf("%s input must not count as covering an IP", name)
		}
	}
	if certCoversIP(leaf, "") {
		t.Fatal("an empty IP must not count as covered")
	}
}

// TestBuildDeployment_CertChecksumRollsThePod covers the second half of
// the stale-cert bug: reissuing the cert in the Secret is not enough,
// because kubelet-shim loads its serving keypair once at startup. Without
// a pod template change the Secret held a correct cert while the running
// pod kept serving the stale one, so exec stayed broken.
func TestBuildDeployment_CertChecksumRollsThePod(t *testing.T) {
	kt := sampleDecoy("billing", "decoy")

	before := buildDeployment(kt, "decoy-decoy", "decoy-config", "cfg", "cert-aaa", "10.0.0.5")
	after := buildDeployment(kt, "decoy-decoy", "decoy-config", "cfg", "cert-bbb", "10.0.0.5")

	got := before.Spec.Template.Annotations["honeypod.io/cert-checksum"]
	if got != "cert-aaa" {
		t.Fatalf("expected the cert checksum on the pod template, got %q", got)
	}
	if after.Spec.Template.Annotations["honeypod.io/cert-checksum"] == got {
		t.Fatal("a reissued cert must change the pod template so the pod restarts")
	}

	same := buildDeployment(kt, "decoy-decoy", "decoy-config", "cfg", "cert-aaa", "10.0.0.5")
	if same.Spec.Template.Annotations["honeypod.io/cert-checksum"] != got {
		t.Fatal("an unchanged cert must not churn the pod template")
	}
}

// TestReconcile_FinalizerOnlyWhileNeeded covers an operational hazard
// found during continuous verification: the mirrored-secrets finalizer was
// added to every Decoy unconditionally, so uninstalling the operator
// while any Decoy still existed left that object, and its namespace,
// stuck Terminating forever with nothing left running to clear it. The
// finalizer only cleans up Secrets mirrored into other namespaces, so it
// is carried only while such a Secret actually exists.
func TestReconcile_FinalizerOnlyWhileNeeded(t *testing.T) {
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)
	kt, _ := reconciledDecoyWithService(t, ktNS, "finalizer-scope")
	r := newReconciler()
	key := client.ObjectKeyFromObject(kt)

	reconcileNow := func() {
		t.Helper()
		if _, err := r.Reconcile(testCtx, reconcile.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	hasFinalizer := func() bool {
		t.Helper()
		var got honeypodv1alpha1.Decoy
		if err := k8sClient.Get(testCtx, key, &got); err != nil {
			t.Fatalf("getting Decoy: %v", err)
		}
		return controllerutil.ContainsFinalizer(&got, mirroredSecretsFinalizer)
	}

	reconcileNow()
	if hasFinalizer() {
		t.Fatal("a Decoy with no cross-namespace join must not carry the finalizer")
	}

	// A pod joined from another namespace needs a mirrored Secret there,
	// which only the finalizer can clean up.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "far-worker", Namespace: podNS,
			Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1.0"}}},
	}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating joined pod: %v", err)
	}
	reconcileNow()
	if !hasFinalizer() {
		t.Fatal("a cross-namespace join must add the finalizer")
	}

	// Once that pod is gone the mirror is cleaned up, so the finalizer
	// must be released rather than pinning the object forever.
	if err := k8sClient.Delete(testCtx, pod); err != nil {
		t.Fatalf("deleting joined pod: %v", err)
	}
	reconcileNow()
	if hasFinalizer() {
		t.Fatal("the finalizer must be removed once no cross-namespace join remains")
	}
}

// TestMirrorJoinedPod_DoesNotLeakRealNodeName covers a bug found on a live
// cluster: a joined pod was mirrored with the real node it runs on, which
// broke exec and leaked the real cluster's node naming.
//
// The real node has no Node object inside the honeypot, so the inner
// apiserver had nothing to proxy exec to and returned a confusing
// "pods <real-node-name> not found". It is also an obvious tell, since the
// pod claims a node that `kubectl get nodes` does not list. Mirrored pods
// must carry no node, letting kubelet-shim place them on a fake one.
func TestMirrorJoinedPod_DoesNotLeakRealNodeName(t *testing.T) {
	realNode := "zeno-md-0-vqr74-gmnsp-kf99v"
	mirrored := mirrorJoinedPod(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-worker", Namespace: "payments"},
		Spec: corev1.PodSpec{
			NodeName:   realNode,
			Containers: []corev1.Container{{Name: "app", Image: "app:1.0"}},
		},
	})

	if mirrored.NodeName != "" {
		t.Fatalf("a mirrored pod must not carry a node name, got %q", mirrored.NodeName)
	}

	// The seed the shim actually consumes must not mention it either.
	kt := &honeypodv1alpha1.Decoy{
		Spec: honeypodv1alpha1.DecoySpec{
			FakeNodes: []honeypodv1alpha1.FakeNode{{Name: "zeno-md-1-h8k3n-q9x2p"}},
		},
	}
	seedJSON, err := renderSeedJSON(kt, []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "payments-worker", Namespace: "payments"},
		Spec: corev1.PodSpec{
			NodeName:   realNode,
			Containers: []corev1.Container{{Name: "app", Image: "app:1.0"}},
		},
	}})
	if err != nil {
		t.Fatalf("rendering seed: %v", err)
	}
	if strings.Contains(string(seedJSON), realNode) {
		t.Fatalf("the real node name leaked into the seed: %s", seedJSON)
	}
}

// TestBuildDeployment_ShimPresentsAsKubelet covers a leak found by reading
// the decoy through its raw API instead of kubectl: kube-apiserver derives
// managedFields[].manager from the User-Agent, so every seeded Node, Pod,
// and Secret carried "manager: kubelet-shim", a name that exists nowhere in
// a real cluster. kubectl hides managedFields by default, but a compromised
// pod calling the API directly sees them.
//
// The shim is told which version to claim so it can present a real kubelet's
// User-Agent, which makes the manager read as plain "kubelet".
func TestBuildDeployment_ShimPresentsAsKubelet(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "ns"},
		Spec:       honeypodv1alpha1.DecoySpec{KubernetesVersion: "v1.34.2"},
	}
	dep := buildDeployment(kt, "sec", "cm", "sum", "certsum", "10.0.0.1")

	var shim *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kubelet-shim" {
			shim = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if shim == nil {
		t.Fatal("no kubelet-shim container in the rendered pod")
	}

	want := "--kubernetes-version=v1.34.2"
	if !slices.Contains(shim.Args, want) {
		t.Fatalf("kubelet-shim must be told the version to claim (%s), got args: %v", want, shim.Args)
	}
}

// TestJoinedPodStatus_DistinguishesMirroredFromRedirected covers the
// difference between the two halves of the honeypod.io/join annotation.
//
// Mirroring works the moment the annotation appears, with no restart: the
// pod shows up inside the honeypot. Redirecting its traffic only happens at
// CREATE, because a running pod's env and volumes are immutable. Reporting
// both the same way claimed a workload was trapped when it was only listed.
func TestJoinedPodStatus_DistinguishesMirroredFromRedirected(t *testing.T) {
	redirected := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "went-through-admission", Namespace: "web"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: decoyVolumeName}},
		},
	}
	mirroredOnly := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "annotated-while-running", Namespace: "web"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: "kube-api-access-x7fkq"}},
		},
	}

	if !podIsRedirected(redirected) {
		t.Fatal("a pod carrying the decoy volume went through the webhook and is redirected")
	}
	if podIsRedirected(mirroredOnly) {
		t.Fatal("a pod with only the real ServiceAccount volume still talks to the real cluster")
	}
}

// TestConfigChecksum_SeedChangeDoesNotRollThePod covers the fix for a
// honeypot-wide tell: joining or unjoining a pod changed seed.json, which
// changed the rollout checksum, which restarted the decoy. kine's SQLite
// lives in an emptyDir, so that restart discarded everything an attacker
// had created inside the honeypot, mid-session.
//
// kubelet-shim re-reads seed.json on every heartbeat, so a seed change must
// not roll the pod. The other files are read once by kube-apiserver at
// startup and must still roll it.
func TestConfigChecksum_SeedChangeDoesNotRollThePod(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "sum")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()

	before, err := r.reconcileConfigMap(testCtx, kt, kt.Name+"-config", nil, "tok", "shimtok", "kcmtok")
	if err != nil {
		t.Fatalf("first reconcileConfigMap: %v", err)
	}

	// A joined pod only ever changes seed.json.
	joined := []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "late-joiner", Namespace: ns},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:1"}}},
	}}
	afterSeed, err := r.reconcileConfigMap(testCtx, kt, kt.Name+"-config", joined, "tok", "shimtok", "kcmtok")
	if err != nil {
		t.Fatalf("reconcileConfigMap with a joined pod: %v", err)
	}
	if afterSeed != before {
		t.Fatalf("a seed-only change must not roll the decoy pod, checksum moved %s -> %s", before, afterSeed)
	}

	// The seed really did change, otherwise the assertion above is empty.
	var cm corev1.ConfigMap
	if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: kt.Name + "-config"}, &cm); err != nil {
		t.Fatalf("getting configmap: %v", err)
	}
	if !strings.Contains(cm.Data[seedFileName], "late-joiner") {
		t.Fatalf("expected the joined pod in the seed, got: %s", cm.Data[seedFileName])
	}

	// A token change must still roll it.
	afterToken, err := r.reconcileConfigMap(testCtx, kt, kt.Name+"-config", joined, "different-token", "shimtok", "kcmtok")
	if err != nil {
		t.Fatalf("reconcileConfigMap with a new token: %v", err)
	}
	if afterToken == afterSeed {
		t.Fatal("a token-auth change must roll the pod, kube-apiserver only reads that file at startup")
	}
}

// TestBuildDeployment_SeedIsLiveReloadable pins the mount shape that makes
// a live seed reload possible at all.
//
// A SubPath mount is resolved once when the container starts and is never
// refreshed when the ConfigMap changes, so the shim would re-read the same
// bytes forever and a joined pod would never appear without a restart. Only
// a plain directory mount is kept up to date by kubelet.
//
// It must also project seed.json alone: this is the container `kubectl exec`
// runs a real shell in, and the same ConfigMap holds token-auth.csv.
func TestBuildDeployment_SeedIsLiveReloadable(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "ns"}}
	dep := buildDeployment(kt, "sec", "cm", "sum", "certsum", "10.0.0.1")

	var shim *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kubelet-shim" {
			shim = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if shim == nil {
		t.Fatal("no kubelet-shim container")
	}

	mount, ok := findVolumeMount(*shim, "seed")
	if !ok {
		t.Fatal("kubelet-shim needs a seed mount to re-read")
	}
	if mount.SubPath != "" {
		t.Fatalf("the seed mount must not use SubPath, ConfigMap updates never reach one; got SubPath=%q", mount.SubPath)
	}
	if !slices.Contains(shim.Args, "--seed="+seedDirPath+"/"+seedFileName) {
		t.Fatalf("kubelet-shim must read the seed from the live mount, got args: %v", shim.Args)
	}

	var seedVol *corev1.Volume
	for i := range dep.Spec.Template.Spec.Volumes {
		if dep.Spec.Template.Spec.Volumes[i].Name == "seed" {
			seedVol = &dep.Spec.Template.Spec.Volumes[i]
		}
	}
	if seedVol == nil || seedVol.ConfigMap == nil {
		t.Fatal("the seed volume must come from the config ConfigMap")
	}
	if len(seedVol.ConfigMap.Items) != 1 || seedVol.ConfigMap.Items[0].Key != seedFileName {
		t.Fatalf("the seed volume must project only %s, or an exec session can read token-auth.csv; got %+v",
			seedFileName, seedVol.ConfigMap.Items)
	}
}

// TestApplyDeployment_SurvivesConcurrentUpdates covers a bug seen live: two
// reconciles landed on the same Deployment close enough together that the
// second one's Get-then-Update lost the race, and controller-runtime logged
// it as a Reconciler error with a full stack trace -- for what is actually
// an ordinary, self-healing resourceVersion conflict, not a real failure.
//
// Run enough concurrent applyDeployment calls against a real (envtest)
// apiserver and at least one is certain to lose that race under the old
// plain Get-then-Update. retry.RetryOnConflict must absorb it: every call
// here has to return nil.
func TestApplyDeployment_SurvivesConcurrentUpdates(t *testing.T) {
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "concurrent-test")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()

	dep := buildDeployment(kt, "sec", "cm", "sum", "certsum", "10.0.0.1")
	if err := r.applyDeployment(testCtx, dep); err != nil {
		t.Fatalf("initial applyDeployment: %v", err)
	}

	const workers = 3
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := buildDeployment(kt, "sec", "cm", fmt.Sprintf("sum-%d", i), "certsum", "10.0.0.1")
			errs <- r.applyDeployment(testCtx, d)
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("applyDeployment under concurrent writers must retry through a conflict, got: %v", err)
		}
	}
}

// TestRenderSeedJSON_SeedsDefaultKubeSystemPods covers the always-on
// synthesis of the standard kube-system pods every real cluster has, so
// `kubectl get pods -A` never shows a suspiciously bare cluster with only
// whatever an author declared in spec.fakePods.
func TestRenderSeedJSON_SeedsDefaultKubeSystemPods(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{
		Spec: honeypodv1alpha1.DecoySpec{
			KubernetesVersion: "v1.34.2",
			FakeNodes: []honeypodv1alpha1.FakeNode{
				{Name: "cp-node"},
				{Name: "worker-node"},
			},
			FakePods: []honeypodv1alpha1.FakePod{{
				Name: "checkout-api", Namespace: "billing",
				Containers: []honeypodv1alpha1.FakeContainer{{Name: "app", Image: "checkout:1.0"}},
			}},
		},
	}
	seedJSON, err := renderSeedJSON(kt, nil)
	if err != nil {
		t.Fatalf("rendering seed: %v", err)
	}

	var s struct {
		FakePods    []honeypodv1alpha1.FakePod `json:"fakePods"`
		Controllers []seed.Controller          `json:"controllers"`
	}
	if err := json.Unmarshal(seedJSON, &s); err != nil {
		t.Fatalf("parsing seed: %v", err)
	}

	if s.FakePods[0].Namespace != "billing" {
		t.Fatalf("the author's own fakePods entry must stay first (servedNamespace depends on it), got %+v", s.FakePods[0])
	}

	byName := map[string]honeypodv1alpha1.FakePod{}
	for _, p := range s.FakePods {
		byName[p.Name] = p
	}

	for _, want := range []struct{ name, node string }{
		{"etcd-cp-node", "cp-node"},
		{"kube-apiserver-cp-node", "cp-node"},
		{"kube-controller-manager-cp-node", "cp-node"},
		{"kube-scheduler-cp-node", "cp-node"},
		{"kube-proxy-cp-node", "cp-node"},
		{"kube-proxy-worker-node", "worker-node"},
	} {
		p, ok := byName[want.name]
		if !ok {
			t.Fatalf("expected a default pod named %q, got: %+v", want.name, s.FakePods)
		}
		if p.Namespace != "kube-system" {
			t.Fatalf("%s: expected namespace kube-system, got %q", want.name, p.Namespace)
		}
		if p.NodeName != want.node {
			t.Fatalf("%s: expected nodeName %q, got %q", want.name, want.node, p.NodeName)
		}
		if p.Replicas > 1 {
			t.Fatalf("%s: a real static pod/DaemonSet pod is a singleton per node, got Replicas=%d", want.name, p.Replicas)
		}
	}

	// coredns is now seeded only as a Deployment object; the real deployment/
	// replicaset controllers build its ReplicaSet and pods (see
	// defaultKubeSystemPods), so there is deliberately no seeded coredns pod.
	if _, ok := byName["coredns"]; ok {
		t.Fatal("coredns must not be seeded as a pod -- the real controllers create its pods")
	}
	var corednsDeploy *seed.Controller
	for i := range s.Controllers {
		if s.Controllers[i].Kind == "Deployment" && s.Controllers[i].Name == "coredns" {
			corednsDeploy = &s.Controllers[i]
		}
	}
	if corednsDeploy == nil || corednsDeploy.Namespace != "kube-system" || corednsDeploy.Replicas != 2 {
		t.Fatalf("expected a coredns/kube-system Deployment controller with Replicas=2, got %+v", corednsDeploy)
	}

	apiserverImage := byName["kube-apiserver-cp-node"].Containers[0].Image
	if apiserverImage != "registry.k8s.io/kube-apiserver:v1.34.2" {
		t.Fatalf("kube-apiserver's image must follow spec.kubernetesVersion, got %q", apiserverImage)
	}

	// Only one control-plane node should get the singleton control-plane
	// components -- a real second node running its own etcd/apiserver
	// would be a second, independent control plane, not a worker.
	if _, ok := byName["etcd-worker-node"]; ok {
		t.Fatal("only the first fakeNode should get etcd/apiserver/controller-manager/scheduler")
	}
}

// TestRenderSeedJSON_NoFakeNodesSeedsNoKubeSystemPods covers the one
// escape hatch: a Decoy with no fakeNodes at all has nowhere for these
// synthesized pods to claim they're scheduled, so none are added.
func TestRenderSeedJSON_NoFakeNodesSeedsNoKubeSystemPods(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{}
	seedJSON, err := renderSeedJSON(kt, nil)
	if err != nil {
		t.Fatalf("rendering seed: %v", err)
	}
	if strings.Contains(string(seedJSON), "kube-system") {
		t.Fatalf("a Decoy with no fakeNodes must seed no kube-system pods, got: %s", seedJSON)
	}
}

// TestRenderSeedJSON_SeedSystemComponentsFalseOptsOut covers the opt-out:
// SeedSystemComponents=false means no auto kube-system pods, so an author
// can shape kube-system themselves via fakePods (a specific CNI, a managed
// cluster that hides its control plane, etc.).
func TestRenderSeedJSON_SeedSystemComponentsFalseOptsOut(t *testing.T) {
	off := false
	kt := &honeypodv1alpha1.Decoy{
		Spec: honeypodv1alpha1.DecoySpec{
			SeedSystemComponents: &off,
			FakeNodes:            []honeypodv1alpha1.FakeNode{{Name: "cp-node"}},
			FakePods: []honeypodv1alpha1.FakePod{{
				Name: "cilium", Namespace: "kube-system",
				Containers: []honeypodv1alpha1.FakeContainer{{Name: "cilium-agent", Image: "quay.io/cilium/cilium:v1.16.3"}},
			}},
		},
	}
	seedJSON, err := renderSeedJSON(kt, nil)
	if err != nil {
		t.Fatalf("rendering seed: %v", err)
	}
	for _, mustNotAppear := range []string{"etcd-cp-node", "kube-apiserver-cp-node", "kube-scheduler-cp-node", "kube-proxy-cp-node"} {
		if strings.Contains(string(seedJSON), mustNotAppear) {
			t.Fatalf("SeedSystemComponents=false must add no default pods, found %q: %s", mustNotAppear, seedJSON)
		}
	}
	// The author's own kube-system pod must still be there.
	if !strings.Contains(string(seedJSON), "cilium") {
		t.Fatalf("the author's own fakePods must survive, got: %s", seedJSON)
	}
}

// TestRenderSeedJSON_SeedSystemComponentsNilDefaultsOn confirms the field
// left unset keeps the pods, so existing Decoys are unaffected.
func TestRenderSeedJSON_SeedSystemComponentsNilDefaultsOn(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{
		Spec: honeypodv1alpha1.DecoySpec{
			FakeNodes: []honeypodv1alpha1.FakeNode{{Name: "cp-node"}},
		},
	}
	seedJSON, err := renderSeedJSON(kt, nil)
	if err != nil {
		t.Fatalf("rendering seed: %v", err)
	}
	if !strings.Contains(string(seedJSON), "kube-apiserver-cp-node") {
		t.Fatalf("with the field unset the default pods must still seed, got: %s", seedJSON)
	}
}

// TestBuildDeployment_HostnameDoesNotLeakDecoy covers a /etc/hostname leak:
// the exec-sandbox container's static hostname was the decoy pod's own name,
// "<honeypod>-<hash>", literally containing the Decoy name, so `cat
// /etc/hostname` gave the decoy away. The pod hostname is now a believable
// fakePod-derived name with no trace of the Decoy.
func TestBuildDeployment_HostnameDoesNotLeakDecoy(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: "httpbin-decoy", Namespace: "honeypod-decoy"},
		Spec: honeypodv1alpha1.DecoySpec{
			FakePods: []honeypodv1alpha1.FakePod{{
				Name: "httpbin", Namespace: "web",
				Containers: []honeypodv1alpha1.FakeContainer{{Name: "app", Image: "httpbin:1"}},
			}},
		},
	}
	dep := buildDeployment(kt, "sec", "cm", "sum", "certsum", "10.0.0.1")
	got := dep.Spec.Template.Spec.Hostname
	if got != "httpbin" {
		t.Fatalf("expected the pod hostname to be the fakePod name %q, got %q", "httpbin", got)
	}
	if strings.Contains(got, "decoy") || strings.Contains(got, kt.Name) {
		t.Fatalf("the pod hostname must not contain the Decoy name, got %q", got)
	}
}

func TestSanitizeDNSLabel(t *testing.T) {
	cases := map[string]string{
		"httpbin":               "httpbin",
		"Payments_API":          "payments-api",
		"--weird..name--":       "weird-name",
		"":                      "worker",
		"UPPER":                 "upper",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	}
	for in, want := range cases {
		if got := sanitizeDNSLabel(in); got != want {
			t.Fatalf("sanitizeDNSLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildDeployment_ApiserverWritesAuditLogToVolume covers the file audit
// backend: the decoy's own kube-apiserver writes an audit.log to a mounted
// volume, exactly like a real kubeadm cluster, in addition to the webhook.
func TestBuildDeployment_ApiserverWritesAuditLogToVolume(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "ns"}}
	dep := buildDeployment(kt, "sec", "cm", "sum", "certsum", "10.0.0.1")

	var api *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kube-apiserver" {
			api = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if api == nil {
		t.Fatal("no kube-apiserver container")
	}
	if !slices.Contains(api.Args, "--audit-log-path=/var/log/kubernetes/audit.log") {
		t.Fatalf("kube-apiserver must write an audit.log file, got args: %v", api.Args)
	}
	mount, ok := findVolumeMount(*api, "audit-logs")
	if !ok || mount.MountPath != "/var/log/kubernetes" {
		t.Fatalf("kube-apiserver must mount the audit-logs volume at /var/log/kubernetes, got: %+v", api.VolumeMounts)
	}
	// The webhook backend must still be there -- this is dual, not a swap.
	if !slices.Contains(api.Args, "--audit-webhook-mode=blocking") {
		t.Fatal("the webhook audit backend must remain alongside the file backend")
	}
}

// TestBuildDeployment_PersistenceUsesPVC covers spec.persistence: kine and
// the audit log move onto one PVC (each under a subPath), and the Deployment
// uses the Recreate strategy so the single-writer RWO claim is never
// double-mounted during a rollout. Unset, both stay emptyDir.
func TestBuildDeployment_PersistenceUsesPVC(t *testing.T) {
	// Ephemeral by default.
	plain := buildDeployment(&honeypodv1alpha1.Decoy{ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "ns"}}, "s", "c", "sum", "cs", "10.0.0.1")
	if hasVolume(plain, "data") {
		t.Fatal("without persistence there must be no PVC-backed data volume")
	}
	if !hasVolume(plain, "kine-data") || !hasVolume(plain, "audit-logs") {
		t.Fatal("without persistence, kine-data and audit-logs must be emptyDir volumes")
	}

	// Persistent: one PVC, subPaths, Recreate.
	kt := &honeypodv1alpha1.Decoy{
		ObjectMeta: metav1.ObjectMeta{Name: "kt", Namespace: "ns"},
		Spec:       honeypodv1alpha1.DecoySpec{Persistence: &honeypodv1alpha1.PersistenceSpec{}},
	}
	dep := buildDeployment(kt, "s", "c", "sum", "cs", "10.0.0.1")
	if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Fatalf("a PVC-backed decoy needs the Recreate strategy, got %q", dep.Spec.Strategy.Type)
	}
	var dataVol *corev1.Volume
	for i := range dep.Spec.Template.Spec.Volumes {
		if dep.Spec.Template.Spec.Volumes[i].Name == "data" {
			dataVol = &dep.Spec.Template.Spec.Volumes[i]
		}
	}
	if dataVol == nil || dataVol.PersistentVolumeClaim == nil || dataVol.PersistentVolumeClaim.ClaimName != "kt-data" {
		t.Fatalf("expected a data volume backed by PVC kt-data, got %+v", dataVol)
	}
	// kine and apiserver mount the same PVC under distinct subPaths.
	subPaths := map[string]string{}
	for _, c := range dep.Spec.Template.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == "data" {
				subPaths[c.Name] = m.SubPath
			}
		}
	}
	if subPaths["kine"] != "kine" || subPaths["kube-apiserver"] != "audit" {
		t.Fatalf("expected kine->kine and kube-apiserver->audit subPaths, got %+v", subPaths)
	}
}

func hasVolume(dep *appsv1.Deployment, name string) bool {
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == name {
			return true
		}
	}
	return false
}

// TestDefaultKubeSystemPods_HaveControllerChain covers the ownerRef/controller
// work: seeded kube-system pods must carry real owner references (no
// "Controlled By: <none>"), and the owning objects must be listed so they
// resolve. Static control-plane pods are mirror pods owned by their Node;
// coredns is owned by a ReplicaSet (owned by a Deployment); kube-proxy by a
// DaemonSet.
func TestDefaultKubeSystemPods_HaveControllerChain(t *testing.T) {
	kt := &honeypodv1alpha1.Decoy{
		Spec: honeypodv1alpha1.DecoySpec{FakeNodes: []honeypodv1alpha1.FakeNode{{Name: "cp"}}},
	}
	nodes := kt.Spec.FakeNodes
	pods, controllers := defaultKubeSystemPods(kt, nodes)

	byName := map[string]seedPodRef{}
	for _, p := range pods {
		byName[p.Name] = seedPodRef{owners: p.OwnerRefs, annos: p.Annotations}
	}

	// Static control-plane pod: mirror pod owned by the Node, with config markers.
	etcd, ok := byName["etcd-cp"]
	if !ok || len(etcd.owners) != 1 || etcd.owners[0].Kind != "Node" || etcd.owners[0].Name != "cp" {
		t.Fatalf("etcd must be a mirror pod owned by its Node, got %+v", etcd)
	}
	if etcd.annos["kubernetes.io/config.source"] != "file" || etcd.annos["kubernetes.io/config.mirror"] == "" {
		t.Fatalf("etcd must carry the static-pod config markers, got %+v", etcd.annos)
	}

	// coredns is now seeded only as a Deployment object; the real deployment/
	// replicaset controllers build its ReplicaSet and pods, so no coredns pod
	// (nor a hand-made ReplicaSet) is seeded here.
	if _, ok := byName["coredns"]; ok {
		t.Fatal("coredns must not be seeded as a pod -- the real controllers create it")
	}
	// kube-proxy owned by a DaemonSet (its controller stays disabled, so it
	// is still seeded directly).
	kp := byName["kube-proxy-cp"]
	if len(kp.owners) != 1 || kp.owners[0].Kind != "DaemonSet" {
		t.Fatalf("kube-proxy must be owned by a DaemonSet, got %+v", kp.owners)
	}

	// The owning objects must be listed: the coredns Deployment and the
	// kube-proxy DaemonSet. No seeded ReplicaSet -- the real controller makes it.
	kinds := map[string]bool{}
	for _, c := range controllers {
		kinds[c.Kind] = true
	}
	for _, want := range []string{"Deployment", "DaemonSet"} {
		if !kinds[want] {
			t.Fatalf("expected a %s controller object to be seeded, got %+v", want, controllers)
		}
	}
	if kinds["ReplicaSet"] {
		t.Fatalf("no ReplicaSet should be seeded now (the real replicaset controller builds coredns's), got %+v", controllers)
	}
}

type seedPodRef struct {
	owners []seed.OwnerRef
	annos  map[string]string
}

// TestBuildDeployment_ServiceLinksDisabled covers a leak that no mount-path
// check could catch, because kubelet injects it rather than the manifest
// declaring it: with service links left on (the Kubernetes default),
// kubelet adds a <SERVICE>_SERVICE_HOST/_PORT variable for every Service in
// the namespace, and the decoy's own Service is named after the Decoy.
// An attacker who runs `env` in an exec session -- which the exec path
// otherwise takes real care to keep clean, see newExecSandbox -- would read
// "CHECKOUT_API_DECOY_SERVICE_HOST" straight back and know exactly what
// they were standing in. The KUBERNETES_* variables a real pod has are
// injected regardless and are unaffected.
func TestBuildDeployment_ServiceLinksDisabled(t *testing.T) {
	kt := sampleDecoy("billing", "checkout-api-decoy")
	dep := buildDeployment(kt, "checkout-api-decoy-decoy", "checkout-api-decoy-config", "somechecksum", "certsum", "10.0.0.5")

	links := dep.Spec.Template.Spec.EnableServiceLinks
	if links == nil {
		t.Fatal("enableServiceLinks is unset, so kubelet defaults it to true and injects a variable named after this Decoy's own Service into every exec session")
	}
	if *links {
		t.Fatal("expected enableServiceLinks=false on the decoy pod")
	}
}

// TestShimBinaryPath_NoIdentityLeak guards where the kubelet-shim binary is
// installed. It used to sit at the filesystem root as /kubelet-shim, and
// the kubelet-shim container is the one a real `kubectl exec` runs a shell
// in -- so `ls /` inside a decoy pod listed the honeypot's own component
// binary next to /etc and /usr. It belongs on a normal PATH directory under
// a name that says nothing, the same reasoning that already makes the
// container's user "app" rather than "kubelet-shim".
func TestShimBinaryPath_NoIdentityLeak(t *testing.T) {
	if strings.Count(shimBinaryPath, "/") < 2 {
		t.Fatalf("expected the shim binary off the filesystem root, got %q", shimBinaryPath)
	}
	for _, bad := range append(forbiddenIdentityStrings, "shim", "kubelet") {
		if strings.Contains(strings.ToLower(shimBinaryPath), bad) {
			t.Fatalf("shim binary path %q contains the identifying substring %q", shimBinaryPath, bad)
		}
	}

	// The manifest and the image have to agree, or the decoy pod
	// CrashLoopBackOffs on a path that isn't there.
	dockerfile, err := os.ReadFile(filepath.Join("..", "..", "docker", "Dockerfile.kubelet-shim"))
	if err != nil {
		t.Fatalf("reading the kubelet-shim Dockerfile: %v", err)
	}
	if !strings.Contains(string(dockerfile), shimBinaryPath) {
		t.Fatalf("docker/Dockerfile.kubelet-shim does not install the binary at %s, which is what render.go tells the pod to run", shimBinaryPath)
	}
}

// TestBuildDeployment_ExecContainerHasNoControlPlanePaths covers the leak
// class that survives a project-name check: /etc/kubernetes/pki and
// /etc/kubernetes/seed contain none of forbiddenIdentityStrings, but the
// kubelet-shim container is the one a real `kubectl exec` runs a shell in,
// and it is pretending to be an ordinary application pod. Every mount
// shows up in /proc/mounts, which an attacker can just read, and an app
// pod with the control plane's own PKI directory mounted into it is not
// something a real cluster produces. Only the kube-apiserver container --
// which no attacker can exec into, and where the path is authentic --
// keeps /etc/kubernetes.
func TestBuildDeployment_ExecContainerHasNoControlPlanePaths(t *testing.T) {
	kt := sampleDecoy("billing", "checkout-api-decoy")
	dep := buildDeployment(kt, "checkout-api-decoy-decoy", "checkout-api-decoy-config", "somechecksum", "certsum", "10.0.0.5")

	var shim *corev1.Container
	for i := range dep.Spec.Template.Spec.Containers {
		if dep.Spec.Template.Spec.Containers[i].Name == "kubelet-shim" {
			shim = &dep.Spec.Template.Spec.Containers[i]
		}
	}
	if shim == nil {
		t.Fatal("no kubelet-shim container in the rendered decoy pod")
	}

	for _, m := range shim.VolumeMounts {
		if strings.HasPrefix(m.MountPath, "/etc/kubernetes") {
			t.Fatalf("kubelet-shim mounts %q -- a control-plane path an exec session reads straight out of /proc/mounts", m.MountPath)
		}
	}
	// The flags have to follow the mount, or the container starts up
	// pointing at files that aren't there.
	for _, a := range shim.Args {
		if strings.Contains(a, "/etc/kubernetes") {
			t.Fatalf("kubelet-shim arg %q still points into a control-plane path", a)
		}
	}
}

// TestKubeletShimImage_BusyboxNotFromDebian guards the busybox the "minimal"
// exec profile serves. Debian bookworm's busybox/busybox-static packages ship
// a 1.35.0 build whose wget applet segfaults: `wget -O- <url>` dies with
// SIGSEGV against a refused port and against a real host alike, while
// `curl` on the same image behaves normally. That matters because under the
// minimal profile busybox *is* the whole userland an attacker sees, and wget
// is one of the first things anyone runs in a container they just landed in.
// A decoy whose wget dumps core is both broken and unmistakable -- no real
// alpine or busybox image behaves that way, so it undoes exactly what the
// minimal profile exists to achieve.
//
// The fix is to take the binary from the official busybox image in a build
// stage. This test fails if anyone reintroduces the Debian package.
func TestKubeletShimImage_BusyboxNotFromDebian(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docker", "Dockerfile.kubelet-shim"))
	if err != nil {
		t.Fatalf("reading the kubelet-shim Dockerfile: %v", err)
	}
	dockerfile := string(b)

	// Join backslash continuations so a multi-line apt-get install reads as
	// one instruction, and drop comments -- the comments here name the
	// Debian package precisely to explain why it is not used.
	var instructions []string
	var cur string
	for _, line := range strings.Split(dockerfile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		cur += strings.TrimSuffix(line, "\\")
		if strings.HasSuffix(line, "\\") {
			continue
		}
		instructions = append(instructions, cur)
		cur = ""
	}

	for _, inst := range instructions {
		if strings.Contains(inst, "apt-get install") && strings.Contains(inst, "busybox") {
			t.Fatalf("the Dockerfile apt-installs busybox from Debian; that build's wget applet segfaults, see this test's comment:\n  %s", strings.TrimSpace(inst))
		}
	}

	if !strings.Contains(dockerfile, "FROM busybox:") {
		t.Fatal("expected a busybox build stage taking the binary from the official image")
	}
	if !strings.Contains(dockerfile, "COPY --from=busybox") {
		t.Fatal("expected the busybox binary to be copied out of that stage")
	}
	// The applets still have to be installed somewhere off the filesystem
	// root -- a top-level busybox dir shows up in `ls /` and no real image
	// has one.
	if !strings.Contains(dockerfile, "--install -s /usr/lib/busybox") {
		t.Fatal("expected the busybox applet symlinks to be installed under /usr/lib/busybox")
	}
}

// TestShimUsername_NeutralFallbackWithoutFakeNodes guards the OPSEC fallback:
// a Decoy with no fakeNodes still needs a shim identity, and that name can
// surface in the decoy's own audit stream, so it must not spell out the tool.
// It also has to stay a valid, node-shaped system:node identity.
func TestShimUsername_NeutralFallbackWithoutFakeNodes(t *testing.T) {
	kt := sampleDecoy("production", "shopwave")
	kt.Spec.FakeNodes = nil

	got := shimUsername(kt)

	if !strings.HasPrefix(got, "system:node:") {
		t.Fatalf("shim identity should be a system:node name, got %q", got)
	}
	if strings.Contains(strings.ToLower(got), "honeypod") {
		t.Fatalf("shim identity must not name the tool, got %q", got)
	}
	if strings.TrimPrefix(got, "system:node:") == "" {
		t.Fatalf("shim identity has an empty node name: %q", got)
	}
}
