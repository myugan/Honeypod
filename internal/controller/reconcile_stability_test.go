package controller

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
)

// childCounts lists every resource kind the reconciler creates for one
// Decoy, selected the same way an operator would: by this operator's own
// labels, in the Decoy's namespace. Counting rather than getting by name
// is what catches a reconciler that creates a second copy of something under
// a name it then stops managing.
func childCounts(t *testing.T, ns, name string) map[string]int {
	t.Helper()
	sel := client.MatchingLabels(selectorLabels(name))
	counts := map[string]int{}

	var deps appsv1.DeploymentList
	if err := k8sClient.List(testCtx, &deps, client.InNamespace(ns), sel); err != nil {
		t.Fatal(err)
	}
	counts["Deployment"] = len(deps.Items)

	var svcs corev1.ServiceList
	if err := k8sClient.List(testCtx, &svcs, client.InNamespace(ns), sel); err != nil {
		t.Fatal(err)
	}
	counts["Service"] = len(svcs.Items)

	var cms corev1.ConfigMapList
	if err := k8sClient.List(testCtx, &cms, client.InNamespace(ns), sel); err != nil {
		t.Fatal(err)
	}
	counts["ConfigMap"] = len(cms.Items)

	var secrets corev1.SecretList
	if err := k8sClient.List(testCtx, &secrets, client.InNamespace(ns), sel); err != nil {
		t.Fatal(err)
	}
	counts["Secret"] = len(secrets.Items)

	var nps networkingv1.NetworkPolicyList
	if err := k8sClient.List(testCtx, &nps, client.InNamespace(ns), sel); err != nil {
		t.Fatal(err)
	}
	counts["NetworkPolicy"] = len(nps.Items)

	return counts
}

// childResourceVersions is the write-amplification probe: a reconciler that
// has converged must stop writing. Any resourceVersion that keeps moving
// across steady-state reconciles is an object being rewritten with content
// it already had -- which, for anything under Owns(), wakes the next
// reconcile off its own watch event and never settles.
func childResourceVersions(t *testing.T, ns, name string) map[string]string {
	t.Helper()
	objs := map[string]client.Object{
		"Deployment/" + name:                &appsv1.Deployment{},
		"Service/" + name:                   &corev1.Service{},
		"ConfigMap/" + name + "-config":     &corev1.ConfigMap{},
		"Secret/" + name + "-decoy":         &corev1.Secret{},
		"NetworkPolicy/" + name + "-egress": &networkingv1.NetworkPolicy{},
	}
	got := map[string]string{}
	for key, obj := range objs {
		var n string
		switch key {
		case "ConfigMap/" + name + "-config":
			n = name + "-config"
		case "Secret/" + name + "-decoy":
			n = name + "-decoy"
		case "NetworkPolicy/" + name + "-egress":
			n = name + "-egress"
		default:
			n = name
		}
		if err := k8sClient.Get(testCtx, types.NamespacedName{Namespace: ns, Name: n}, obj); err != nil {
			t.Fatalf("getting %s: %v", key, err)
		}
		got[key] = obj.GetResourceVersion()
	}
	return got
}

// TestReconcile_NeverDuplicatesChildResourcesAndStopsWriting is the core
// idempotency guarantee: repeated reconciles of an unchanged Decoy must
// leave exactly one of each child resource, and must stop writing to them
// once they match.
func TestReconcile_NeverDuplicatesChildResourcesAndStopsWriting(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}

	// Two passes to settle: the first creates, the second writes back the
	// rendered kubeconfig that depends on what the first pass produced.
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("settling reconcile %d: %v", i+1, err)
		}
	}
	before := childResourceVersions(t, ns, kt.Name)

	for i := 0; i < 4; i++ {
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("steady-state reconcile %d: %v", i+1, err)
		}
	}

	for kind, n := range childCounts(t, ns, kt.Name) {
		if n != 1 {
			t.Errorf("expected exactly one %s after repeated reconciles, got %d", kind, n)
		}
	}
	for key, rv := range childResourceVersions(t, ns, kt.Name) {
		if rv != before[key] {
			t.Errorf("%s was rewritten by a steady-state reconcile (resourceVersion %s -> %s); a converged reconciler must stop writing", key, before[key], rv)
		}
	}
}

// TestReconcile_MirroredSecretIsStableAcrossReconciles extends the same
// guarantee to the cross-namespace credentials mirror, which is the one
// child not held by an OwnerReference and so the one reconciled entirely by
// hand: exactly one mirror per joining namespace, and no rewrite once its
// contents already match.
func TestReconcile_MirroredSecretIsStableAcrossReconciles(t *testing.T) {
	requireEnvtest(t)
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)

	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "joined-app",
			Namespace:   podNS,
			Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:1"}}},
	}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating joined pod: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(testCtx, pod) })

	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	for i := 0; i < 2; i++ {
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("settling reconcile %d: %v", i+1, err)
		}
	}

	mirrorKey := types.NamespacedName{Namespace: podNS, Name: mirroredSecretName(kt.Name)}
	var mirror corev1.Secret
	if err := k8sClient.Get(testCtx, mirrorKey, &mirror); err != nil {
		t.Fatalf("getting the mirrored credentials secret: %v", err)
	}
	rvBefore := mirror.ResourceVersion

	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(testCtx, req); err != nil {
			t.Fatalf("steady-state reconcile %d: %v", i+1, err)
		}
	}

	var mirrors corev1.SecretList
	if err := k8sClient.List(testCtx, &mirrors, client.InNamespace(podNS), client.MatchingLabels{
		mirroredSecretLabelDecoyNamespace: ktNS,
		mirroredSecretLabelDecoyName:      kt.Name,
	}); err != nil {
		t.Fatal(err)
	}
	if len(mirrors.Items) != 1 {
		t.Fatalf("expected exactly one mirrored credentials secret in %s, got %d", podNS, len(mirrors.Items))
	}
	if mirrors.Items[0].ResourceVersion != rvBefore {
		t.Errorf("the mirrored credentials secret was rewritten by a steady-state reconcile (resourceVersion %s -> %s)", rvBefore, mirrors.Items[0].ResourceVersion)
	}

	// The mirror deliberately carries only what a joined pod's decoy
	// ServiceAccount volume needs, never the TLS private key or the
	// service-account signing keypair the primary Secret also holds.
	for _, key := range []string{"tls.key", "sa.key", "ca.key", "shim.token"} {
		if _, ok := mirrors.Items[0].Data[key]; ok {
			t.Errorf("mirrored credentials secret must not carry %q", key)
		}
	}
}

// TestReconcile_RepairsStrippedLabelsAndOwnerReference covers drift on an
// existing child: labels are how this controller finds its own objects and
// how the Service selects the decoy pod, and the controller reference is the
// only thing that garbage-collects the child when the Decoy goes away.
// Losing either silently (a hand edit, a re-apply from a stale manifest)
// must be repaired, not ignored.
func TestReconcile_RepairsStrippedLabelsAndOwnerReference(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	key := types.NamespacedName{Namespace: ns, Name: kt.Name}
	var dep appsv1.Deployment
	if err := k8sClient.Get(testCtx, key, &dep); err != nil {
		t.Fatal(err)
	}
	dep.Labels = map[string]string{"someone-elses": "label"}
	dep.OwnerReferences = nil
	if err := k8sClient.Update(testCtx, &dep); err != nil {
		t.Fatalf("stripping labels and owner reference: %v", err)
	}

	if _, err := r.Reconcile(testCtx, req); err != nil {
		t.Fatalf("repair reconcile: %v", err)
	}

	var repaired appsv1.Deployment
	if err := k8sClient.Get(testCtx, key, &repaired); err != nil {
		t.Fatal(err)
	}
	for k, want := range commonLabels(kt.Name) {
		if repaired.Labels[k] != want {
			t.Errorf("expected label %s=%s to be restored, got %q", k, want, repaired.Labels[k])
		}
	}
	if repaired.Labels["someone-elses"] != "label" {
		t.Error("expected a label this operator does not manage to be left alone")
	}
	if !metav1.IsControlledBy(&repaired, kt) {
		t.Fatalf("expected the controller reference to the Decoy to be restored, got %v", repaired.OwnerReferences)
	}
}

// TestReconcileSecret_NoClusterIPLeavesTheCertAlone covers a reissue loop:
// the serving cert is reissued when it does not cover the Service's
// ClusterIP, but with no ClusterIP at all there is nothing to cover, and a
// cert reissued anyway fails the same check next pass. Every reissue
// rewrites the decoy Secret, which is under Owns(), so the watch event
// re-triggers the reconcile that caused it -- forever.
func TestReconcileSecret_NoClusterIPLeavesTheCertAlone(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	kt := sampleDecoy(ns, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	r := newReconciler()

	first, err := r.reconcileSecret(testCtx, kt, kt.Name+"-decoy", "")
	if err != nil {
		t.Fatalf("first reconcileSecret: %v", err)
	}
	wantCert := string(first.Data["tls.crt"])
	wantRV := first.ResourceVersion

	for i := 0; i < 3; i++ {
		got, err := r.reconcileSecret(testCtx, kt, kt.Name+"-decoy", "")
		if err != nil {
			t.Fatalf("reconcileSecret %d: %v", i+2, err)
		}
		if string(got.Data["tls.crt"]) != wantCert {
			t.Fatal("serving cert was reissued with no ClusterIP to cover; this rewrites the Secret on every reconcile and never converges")
		}
		if got.ResourceVersion != wantRV {
			t.Fatalf("decoy Secret was rewritten with no ClusterIP to cover (resourceVersion %s -> %s)", wantRV, got.ResourceVersion)
		}
	}
}

// createBlocker fails Create for one GroupKind in one namespace, standing in
// for the API server refusing (or the operator dying at) exactly that call.
type createBlocker struct {
	client.Client
	namespace string
	gk        schema.GroupKind
	err       error
}

func (c *createBlocker) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	gvks, _, err := c.Scheme().ObjectKinds(obj)
	if err == nil && len(gvks) > 0 && gvks[0].GroupKind() == c.gk && obj.GetNamespace() == c.namespace {
		return c.err
	}
	return c.Client.Create(ctx, obj, opts...)
}

// TestReconcile_MirroredSecretFinalizerGoesOnBeforeTheMirror pins the
// ordering that keeps a cross-namespace mirror collectable. OwnerReferences
// cannot cross namespaces, so the finalizer is the only thing that deletes a
// mirror when the Decoy is. Adding it after the mirror is created leaves
// a window where a Decoy deleted in between strands credentials in
// another namespace with nothing left to clean them up. Blocking the mirror
// create makes that window observable: the finalizer must already be on the
// object even though no mirror exists yet.
func TestReconcile_MirroredSecretFinalizerGoesOnBeforeTheMirror(t *testing.T) {
	requireEnvtest(t)
	ktNS := uniqueNamespace(t)
	podNS := uniqueNamespace(t)

	kt := sampleDecoy(ktNS, "checkout-api-decoy")
	if err := k8sClient.Create(testCtx, kt); err != nil {
		t.Fatalf("creating Decoy: %v", err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "joined-app",
			Namespace:   podNS,
			Annotations: map[string]string{joinAnnotation: ktNS + "/" + kt.Name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:1"}}},
	}
	if err := k8sClient.Create(testCtx, pod); err != nil {
		t.Fatalf("creating joined pod: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(testCtx, pod) })

	blocked := &createBlocker{
		Client:    k8sClient,
		namespace: podNS,
		gk:        schema.GroupKind{Kind: "Secret"},
		err:       apierrors.NewInternalError(context.DeadlineExceeded),
	}
	r := &DecoyReconciler{Client: blocked, Scheme: k8sClient.Scheme()}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ktNS, Name: kt.Name}}
	if _, err := r.Reconcile(testCtx, req); err == nil {
		t.Fatal("expected the blocked mirror create to fail the reconcile")
	}

	var got honeypodv1alpha1.Decoy
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if !controllerutil.ContainsFinalizer(&got, mirroredSecretsFinalizer) {
		t.Fatal("expected the mirrored-secrets finalizer to be added before the first mirror is created, so a Decoy deleted mid-reconcile still cleans up")
	}

	// And it comes back off once there is nothing left to clean up.
	if err := k8sClient.Delete(testCtx, pod); err != nil {
		t.Fatalf("deleting joined pod: %v", err)
	}
	if _, err := newReconciler().Reconcile(testCtx, req); err != nil {
		t.Fatalf("reconcile after unjoin: %v", err)
	}
	if err := k8sClient.Get(testCtx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if controllerutil.ContainsFinalizer(&got, mirroredSecretsFinalizer) {
		t.Fatal("expected the finalizer to be removed once no joined pod remains outside the Decoy's namespace; a finalizer that outlives its purpose wedges the object")
	}
}

// notFoundOnce makes the first Get of one key look like a miss, reproducing
// the window in which two managers both decide to generate a webhook cert.
type notFoundOnce struct {
	client.Client
	key  types.NamespacedName
	done bool
}

func (c *notFoundOnce) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if !c.done && key == c.key {
		c.done = true
		return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, key.Name)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

// TestEnsureWebhookServingCert_LosingTheCreateRaceUsesTheStoredCert covers
// two managers racing to create the cert Secret. The loser must serve the
// keypair that actually landed, not the one it generated and threw away:
// WebhookCABundleReconciler publishes the stored CA as the caBundle, so a
// mismatched keypair fails every apiserver handshake, and with
// failurePolicy: Ignore every join silently no-ops.
func TestEnsureWebhookServingCert_LosingTheCreateRaceUsesTheStoredCert(t *testing.T) {
	requireEnvtest(t)
	ns := uniqueNamespace(t)
	dnsNames := []string{"localhost", "127.0.0.1"}

	winner, winnerCA, err := EnsureWebhookServingCert(testCtx, k8sClient, ns, "webhook-tls", dnsNames)
	if err != nil {
		t.Fatalf("seeding the stored cert: %v", err)
	}

	racer := &notFoundOnce{Client: k8sClient, key: types.NamespacedName{Namespace: ns, Name: "webhook-tls"}}
	loser, loserCA, err := EnsureWebhookServingCert(testCtx, racer, ns, "webhook-tls", dnsNames)
	if err != nil {
		t.Fatalf("losing EnsureWebhookServingCert: %v", err)
	}
	if !racer.done {
		t.Fatal("test bug: the racing Get was never intercepted")
	}

	if len(loser.Certificate) == 0 || string(loser.Certificate[0]) != string(winner.Certificate[0]) {
		t.Fatal("expected the loser of the create race to return the stored keypair, not the one it generated and failed to store")
	}
	if string(loserCA) != string(winnerCA) {
		t.Fatal("expected the loser of the create race to return the stored CA, which is what gets published as the webhook caBundle")
	}
}
