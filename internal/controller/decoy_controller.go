package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/certs"
	"honeypod.io/honeypod/internal/metrics"
	"honeypod.io/honeypod/internal/notifier"
)

// mirroredSecretsFinalizer cleans up cross-namespace mirrored credentials
// Secrets on Decoy deletion -- OwnerReferences can't cross namespaces.
const mirroredSecretsFinalizer = "honeypod.io/mirrored-secrets"

// deleteMirroredSecrets removes every mirrored credentials Secret belonging
// to kt, across all namespaces.
func (r *DecoyReconciler) deleteMirroredSecrets(ctx context.Context, kt *honeypodv1alpha1.Decoy) error {
	var all corev1.SecretList
	if err := r.List(ctx, &all, client.MatchingLabels{
		mirroredSecretLabelDecoyNamespace: kt.Namespace,
		mirroredSecretLabelDecoyName:      kt.Name,
	}); err != nil {
		return fmt.Errorf("listing mirrored credentials secrets: %w", err)
	}
	for i := range all.Items {
		s := &all.Items[i]
		if err := r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting mirrored credentials secret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	return nil
}

// isNamespaceTerminating reports whether err is the API server refusing a
// create because the target namespace is being deleted. The typed status
// cause is what the namespace lifecycle admission plugin actually sets;
// the message check is a fallback for an older apiserver that only
// returned the prose.
func isNamespaceTerminating(err error) bool {
	if apierrors.HasStatusCause(err, corev1.NamespaceTerminatingCause) {
		return true
	}
	return apierrors.IsForbidden(err) && strings.Contains(err.Error(), "being terminated")
}

// needsMirroredSecrets reports whether this Decoy has at least one joined
// Pod outside its own namespace, which is the only case that produces a
// cross-namespace mirrored credentials Secret.
func needsMirroredSecrets(decoyNamespace string, joined []corev1.Pod) bool {
	for _, p := range joined {
		if p.Namespace != decoyNamespace {
			return true
		}
	}
	return false
}

// setMirroredSecretsFinalizer adds or removes the finalizer, and writes only
// when that actually changes the object. Most Decoys never join across
// namespaces and so never carry it at all, which keeps them deletable even
// if the operator is gone.
//
// The caller must add it *before* creating any mirror and remove it *after*
// deleting the last one: doing either in the other order leaves a window
// where a mirror exists in another namespace with nothing left to clean it
// up, since OwnerReferences can't cross namespaces.
func (r *DecoyReconciler) setMirroredSecretsFinalizer(ctx context.Context, kt *honeypodv1alpha1.Decoy, want bool) error {
	var changed bool
	if want {
		changed = controllerutil.AddFinalizer(kt, mirroredSecretsFinalizer)
	} else {
		changed = controllerutil.RemoveFinalizer(kt, mirroredSecretsFinalizer)
	}
	if !changed {
		return nil
	}
	return r.Update(ctx, kt)
}

// DecoyReconciler reconciles a Decoy object.
type DecoyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ManagerAuditWebhookURL is the base URL (scheme://host:port, no path)
	// of the operator's own audit-webhook receiver (see
	// internal/auditwebhook and cmd/manager/main.go). Every Decoy's
	// inner apiserver is configured to POST its real audit events to
	// "<ManagerAuditWebhookURL>/audit/<namespace>/<name>". Left empty,
	// defaultManagerAuditWebhookURL() is used, matching this project's own
	// config/manager manifests.
	ManagerAuditWebhookURL string

	// Notifier sends PodJoin events to matching Alerts. Left nil (e.g.
	// in tests), join notification is skipped entirely.
	Notifier *notifier.Dispatcher

	// Recorder emits Kubernetes Events on the Decoy (Ready, ReconcileFailed,
	// PodJoined/PodLeft) so `kubectl describe decoy` surfaces what happened.
	// SetupWithManager fills it in; left nil (e.g. in tests that construct
	// the reconciler directly), Event emission is skipped.
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=honeypod.io,resources=decoys,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=honeypod.io,resources=decoys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=honeypod.io,resources=decoys/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;configmaps;secrets;persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=honeypod.io,resources=providers;alerts;auditsinks,verbs=get;list;watch

// Reconcile drives one Decoy to its desired state. Any failure along
// the way is recorded on the Decoy's own status (phase Failed, plus a
// Ready=False condition carrying the error) before being returned, so
// `kubectl get decoys` and `kubectl describe` show what went wrong
// instead of a blank phase that only the controller log explains.
func (r *DecoyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	res, err := r.reconcile(ctx, req)
	if err != nil {
		metrics.ReconcileErrors.WithLabelValues(req.Namespace, req.Name).Inc()
		r.markFailed(ctx, req.NamespacedName, err)
	}
	return res, err
}

// markFailed records a reconcile error on the Decoy's status. Best
// effort: if the object is gone or the status write itself fails, the
// original reconcile error is still what the caller returns.
func (r *DecoyReconciler) markFailed(ctx context.Context, name types.NamespacedName, reconcileErr error) {
	var kt honeypodv1alpha1.Decoy
	// Only the transition into Failed is worth an Event: markFailed runs on
	// every failed reconcile, and a stuck Decoy requeues with backoff, so
	// emitting each time would flood the Events feed.
	entered := false
	// A concurrent write to this same Decoy routinely makes the status
	// update lose kt's resourceVersion. Re-fetching and reapplying inside
	// RetryOnConflict keeps the failure reason from being dropped over an
	// ordinary, self-healing race.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, name, &kt); err != nil {
			return err
		}
		if !kt.DeletionTimestamp.IsZero() {
			return nil
		}
		entered = kt.Status.Phase != honeypodv1alpha1.DecoyPhaseFailed
		kt.Status.Phase = honeypodv1alpha1.DecoyPhaseFailed
		metrics.SetPhase(kt.Namespace, kt.Name, string(honeypodv1alpha1.DecoyPhaseFailed))
		apimeta.SetStatusCondition(&kt.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ReconcileFailed",
			Message:            reconcileErr.Error(),
			ObservedGeneration: kt.Generation,
		})
		return r.Status().Update(ctx, &kt)
	})
	if err == nil && entered && r.Recorder != nil {
		r.Recorder.Event(&kt, corev1.EventTypeWarning, "ReconcileFailed", reconcileErr.Error())
	}
}

func (r *DecoyReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var kt honeypodv1alpha1.Decoy
	if err := r.Get(ctx, req.NamespacedName, &kt); err != nil {
		if apierrors.IsNotFound(err) {
			// The Decoy is gone; drop its metric series so /metrics
			// stops advertising a decoy that no longer exists.
			metrics.DeleteDecoy(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !kt.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&kt, mirroredSecretsFinalizer) {
			return ctrl.Result{}, nil
		}
		if err := r.deleteMirroredSecrets(ctx, &kt); err != nil {
			return ctrl.Result{}, err
		}
		controllerutil.RemoveFinalizer(&kt, mirroredSecretsFinalizer)
		return ctrl.Result{}, r.Update(ctx, &kt)
	}

	secretName := decoySecretName(kt.Name)
	configCMName := kt.Name + "-config"

	// The Service must be reconciled before both the Secret and the
	// Deployment:
	//   - every seeded fake Node's InternalIP is set to this Service's
	//     ClusterIP (stable across pod restarts, unlike the pod's own IP --
	//     see kubeletshim.Config.NodeInternalIP's doc comment), which
	//     kubelet-shim only learns via a --node-internal-ip flag baked into
	//     the Deployment at render time;
	//   - the real inner kube-apiserver's kubelet-client proxy dials that
	//     same ClusterIP directly (by IP, not by DNS name) for
	//     exec/attach/logs, so kubelet-shim's TLS cert must carry it as a
	//     SAN or every such call fails TLS verification (confirmed live on
	//     zeno: "certificate is valid for 127.0.0.1, not <ClusterIP>") --
	//     the cert is only ever issued once (identity must stay stable, see
	//     reconcileSecret), so the ClusterIP has to be known before that
	//     first issuance, not patched in later.
	svc := buildService(&kt)
	if err := controllerutil.SetControllerReference(&kt, svc, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	clusterIP, err := r.applyService(ctx, svc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling service: %w", err)
	}

	secret, err := r.reconcileSecret(ctx, &kt, secretName, clusterIP)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling decoy secret: %w", err)
	}

	previousJoined := kt.Status.JoinedPods
	joined, err := r.listJoinedPods(ctx, &kt)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("listing joined pods: %w", err)
	}
	r.reconcileJoinTransitions(ctx, &kt, previousJoined, joined)

	// The finalizer only exists to clean up mirrored Secrets in other
	// namespaces, which OwnerReferences can't reach. Carry it only while
	// such a Secret actually exists: a finalizer that outlives its purpose
	// wedges the object, and its namespace, if the operator is ever
	// uninstalled before the Decoy is deleted. It has to go on before the
	// first mirror is created, though -- a Decoy deleted in between would
	// otherwise strand that mirror in a namespace nothing cleans up.
	wantMirrors := needsMirroredSecrets(kt.Namespace, joined)
	if wantMirrors {
		if err := r.setMirroredSecretsFinalizer(ctx, &kt, true); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding mirrored-secrets finalizer: %w", err)
		}
	}

	// Every distinct namespace with at least one joined pod needs its own
	// mirrored credentials Secret so PodJoinMutator (join_webhook.go)
	// can mount a same-namespace Secret onto that pod -- see
	// buildMirroredSecret's doc comment for why OwnerReferences can't
	// do this cleanup and why this uses labels instead.
	if err := r.reconcileMirroredSecrets(ctx, &kt, secret, joined); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling joined-pod credentials secrets: %w", err)
	}

	// Symmetrically, the finalizer only comes off once the last mirror is
	// actually gone.
	if !wantMirrors {
		if err := r.setMirroredSecretsFinalizer(ctx, &kt, false); err != nil {
			return ctrl.Result{}, fmt.Errorf("removing mirrored-secrets finalizer: %w", err)
		}
	}

	configChecksum, err := r.reconcileConfigMap(ctx, &kt, configCMName, joined, string(secret.Data["token"]), string(secret.Data["shim.token"]), string(secret.Data["kcm.token"]))
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling config configmap: %w", err)
	}

	// With spec.persistence set, the decoy's storage lives on a PVC that
	// must exist before the Deployment that mounts it. The PVC is never
	// deleted or resized on later reconciles: a claim carries the very
	// state persistence exists to keep, so it is created once and left
	// alone (and garbage-collected with the Decoy via its owner ref).
	if kt.Spec.Persistence != nil {
		if err := r.ensureDataPVC(ctx, &kt); err != nil {
			return ctrl.Result{}, fmt.Errorf("reconciling data PVC: %w", err)
		}
	}

	dep := buildDeployment(&kt, secretName, configCMName, configChecksum, checksum(secret.Data["tls.crt"]), clusterIP)
	if err := controllerutil.SetControllerReference(&kt, dep, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.applyDeployment(ctx, dep); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling deployment: %w", err)
	}

	np := buildNetworkPolicy(&kt)
	if err := controllerutil.SetControllerReference(&kt, np, r.Scheme); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.applyNetworkPolicy(ctx, np); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling network policy: %w", err)
	}
	// Prune the pre-rename NetworkPolicy (once named the bare decoy name) so a
	// decoy created before the "-egress" rename does not keep a stale copy.
	// Scoped to one this Decoy owns, so a user's own NetworkPolicy that merely
	// shares the name is never touched.
	if np.Name != kt.Name {
		var legacyNP networkingv1.NetworkPolicy
		err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: kt.Name}, &legacyNP)
		switch {
		case err == nil && metav1.IsControlledBy(&legacyNP, &kt):
			if err := r.Delete(ctx, &legacyNP); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("pruning legacy network policy: %w", err)
			}
		case err != nil && !apierrors.IsNotFound(err):
			return ctrl.Result{}, fmt.Errorf("checking for legacy network policy: %w", err)
		}
	}

	// The kubeconfig depends on the Service's DNS name and the CA we just
	// ensured exists in the Secret, so render/refresh it after both exist.
	server := fmt.Sprintf("https://%s:%d", serviceDNSName(kt.Name, kt.Namespace), servicePort(&kt))
	if err := r.reconcileKubeconfig(ctx, &kt, secretName, secret, server); err != nil {
		return ctrl.Result{}, fmt.Errorf("reconciling kubeconfig: %w", err)
	}

	return ctrl.Result{}, r.updateStatus(ctx, &kt, secretName, server, joined, log)
}

// listJoinedPods finds every real Pod in the cluster (any namespace) whose
// honeypod.io/join annotation names this Decoy, either explicitly
// ("<namespace>/<name>") or via "true" (same namespace as the Pod, only if
// kt is the one Decoy there). A Pod whose annotation names a Decoy
// that doesn't exist, names a different one, or says "true" in a namespace
// with zero or multiple Decoys simply never matches, so it's silently
// ignored rather than failing anything.
func (r *DecoyReconciler) listJoinedPods(ctx context.Context, kt *honeypodv1alpha1.Decoy) ([]corev1.Pod, error) {
	var podList corev1.PodList
	// Deliberately unscoped: the join annotation cannot be expressed as a
	// field/label selector, so there is nothing to narrow the List by. This
	// reads from the controller's informer cache, not the apiserver, and the
	// controller already watches Pods cluster-wide (see SetupWithManager) so
	// that cache exists regardless. A custom field index would only trim the
	// per-reconcile iteration, not the watch or the cache, so it is not worth
	// the indexer setup and the cached-client requirement it would impose on
	// the tests. Expected decoy counts are small, so the scan is cheap.
	if err := r.List(ctx, &podList); err != nil {
		return nil, err
	}
	target := kt.Namespace + "/" + kt.Name

	// How a "true" (implicit) annotation resolves for THIS kt, computed once.
	// Single-decoy first: if kt is the only Decoy in the cluster, a "true"
	// pod in any namespace joins it; otherwise only a "true" pod in kt's own
	// namespace does, and only if kt is the sole Decoy there. Mirrors
	// resolveJoinAnnotation so the webhook and the reconciler agree.
	var implicitChecked bool
	var soleInCluster, soleInOwnNS bool
	resolveImplicit := func() {
		if implicitChecked {
			return
		}
		implicitChecked = true
		var all honeypodv1alpha1.DecoyList
		if err := r.List(ctx, &all); err != nil {
			return
		}
		if len(all.Items) == 1 {
			soleInCluster = all.Items[0].Namespace == kt.Namespace && all.Items[0].Name == kt.Name
			return
		}
		inNS := 0
		for i := range all.Items {
			if all.Items[i].Namespace == kt.Namespace {
				inNS++
			}
		}
		soleInOwnNS = inNS == 1
	}

	joined := make([]corev1.Pod, 0, len(podList.Items))
	for _, p := range podList.Items {
		val := p.Annotations[joinAnnotation]
		if val == target {
			joined = append(joined, p)
			continue
		}
		if val == joinAnnotationImplicit {
			resolveImplicit()
			if soleInCluster || (soleInOwnNS && p.Namespace == kt.Namespace) {
				joined = append(joined, p)
			}
		}
	}
	sort.Slice(joined, func(i, j int) bool {
		a, b := joined[i], joined[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return joined, nil
}

// reconcileJoinTransitions compares the previously-recorded joined pods
// against the freshly-listed ones and, for every pod that joined or left,
// emits a Kubernetes Event on the Decoy and notifies matching Alerts. Both
// side effects fire only on the transition edge, not on every reconcile, and
// each is skipped when its dependency (Recorder or Notifier) is nil.
func (r *DecoyReconciler) reconcileJoinTransitions(ctx context.Context, kt *honeypodv1alpha1.Decoy, previous []honeypodv1alpha1.JoinedPod, current []corev1.Pod) {
	ref := notifier.DecoyRef{Namespace: kt.Namespace, Name: kt.Name}

	wasJoined := make(map[types.NamespacedName]bool, len(previous))
	for _, p := range previous {
		wasJoined[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = true
	}
	isJoined := make(map[types.NamespacedName]bool, len(current))
	for _, p := range current {
		key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
		isJoined[key] = true
		if !wasJoined[key] {
			if r.Recorder != nil {
				r.Recorder.Eventf(kt, corev1.EventTypeNormal, "PodJoined", "Pod %s joined the decoy", key)
			}
			if r.Notifier != nil {
				r.Notifier.NotifyPodJoin(ctx, ref, key, true)
			}
		}
	}
	for key := range wasJoined {
		if !isJoined[key] {
			if r.Recorder != nil {
				r.Recorder.Eventf(kt, corev1.EventTypeNormal, "PodLeft", "Pod %s left the decoy", key)
			}
			if r.Notifier != nil {
				r.Notifier.NotifyPodJoin(ctx, ref, key, false)
			}
		}
	}
}

// reconcileMirroredSecrets ensures a mirrored credentials Secret
// (buildMirroredSecret -- token + ca.crt only) exists in every
// distinct namespace that currently has at least one Pod joining this
// Decoy, other than the Decoy's own namespace (a same-namespace
// joined pod can mount the primary "<name>-decoy" Secret directly, no
// mirror needed). It also deletes any previously-created mirror in a
// namespace that no longer has any joined pod for this Decoy -- e.g.
// the last joining Pod there was deleted or un-annotated -- since
// OwnerReferences can't do that cleanup for a cross-namespace Secret (see
// buildMirroredSecret's doc comment).
func (r *DecoyReconciler) reconcileMirroredSecrets(ctx context.Context, kt *honeypodv1alpha1.Decoy, secret *corev1.Secret, joined []corev1.Pod) error {
	needed := map[string]bool{}
	for _, p := range joined {
		if p.Namespace == kt.Namespace {
			continue
		}
		needed[p.Namespace] = true
	}

	for ns := range needed {
		desired := buildMirroredSecret(kt, ns, secret.Data["token"], secret.Data["ca.crt"])
		_, err := applyResource(ctx, r.Client, desired, func(live, desired *corev1.Secret) {
			live.Data = desired.Data
		})
		if err != nil {
			// A namespace being torn down can't accept new objects. The
			// joined pod in it is going away too, so its mirrored
			// credentials are moot: skip it rather than failing the whole
			// reconcile, which would otherwise hold the decoy in Pending
			// for as long as that unrelated namespace takes to finish
			// terminating (forever, if a finalizer wedges it).
			if isNamespaceTerminating(err) {
				continue
			}
			return fmt.Errorf("reconciling mirrored credentials secret in %s: %w", ns, err)
		}
	}

	var all corev1.SecretList
	if err := r.List(ctx, &all, client.MatchingLabels{
		mirroredSecretLabelDecoyNamespace: kt.Namespace,
		mirroredSecretLabelDecoyName:      kt.Name,
	}); err != nil {
		return fmt.Errorf("listing mirrored credentials secrets: %w", err)
	}
	for i := range all.Items {
		s := &all.Items[i]
		if needed[s.Namespace] {
			continue
		}
		if err := r.Delete(ctx, s); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting stale mirrored credentials secret %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	return nil
}

// mapJoinedPodToDecoy turns Pod watch events into a reconcile.Request for
// whichever Decoy the Pod's honeypod.io/join annotation names (or
// resolves to, for "true"), so an annotated Pod being created/updated/
// deleted, or the annotation being added/removed, triggers a reconcile of
// the referenced Decoy. It never checks whether that Decoy actually
// exists: Reconcile already handles a not-found target cleanly, and
// controller-runtime maps both the old and new object on an Update event,
// so removing the annotation still reconciles the Decoy it used to
// point at.
func (r *DecoyReconciler) mapJoinedPodToDecoy(ctx context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	ns, name, ok := resolveJoinAnnotation(ctx, r.Client, pod.Namespace, pod.Annotations[joinAnnotation])
	if !ok {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
}

// certCoversIP reports whether a PEM serving cert lists ip among its IP
// SANs. An unparseable or empty cert counts as not covering it, so the
// caller reissues rather than serving something broken.
func certCoversIP(certPEM []byte, ip string) bool {
	if len(certPEM) == 0 || ip == "" {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	for _, got := range crt.IPAddresses {
		if got.Equal(want) {
			return true
		}
	}
	return false
}

// reissueServingCert replaces only the TLS keypair in an existing decoy
// Secret, keeping the CA, the tokens, and the ServiceAccount keys so the
// decoy's identity survives. Signed by the same CA, so a client that
// already trusts this decoy still does.
func (r *DecoyReconciler) reissueServingCert(ctx context.Context, kt *honeypodv1alpha1.Decoy, secret *corev1.Secret, clusterIP string) (*corev1.Secret, error) {
	caCert, caKey := secret.Data["ca.crt"], secret.Data["ca.key"]
	if len(caCert) == 0 || len(caKey) == 0 {
		// Older Secrets kept no CA key, so the CA can't sign again. Start
		// a fresh CA rather than leaving exec broken; the decoy token is
		// still preserved below.
		var err error
		caCert, caKey, err = certs.GenerateCA("kubernetes")
		if err != nil {
			return nil, fmt.Errorf("regenerating CA to reissue serving cert: %w", err)
		}
	}
	dnsNames := append([]string{serviceDNSName(kt.Name, kt.Namespace), kt.Name, "localhost", "127.0.0.1", clusterIP}, kt.Spec.SANs...)
	leafCert, leafKey, err := certs.IssueServerCert(caCert, caKey, dnsNames)
	if err != nil {
		return nil, fmt.Errorf("reissuing serving cert: %w", err)
	}
	secret.Data["ca.crt"] = caCert
	secret.Data["ca.key"] = caKey
	secret.Data["tls.crt"] = leafCert
	secret.Data["tls.key"] = leafKey
	if err := r.Update(ctx, secret); err != nil {
		return nil, fmt.Errorf("saving reissued serving cert: %w", err)
	}
	return secret, nil
}

func (r *DecoyReconciler) reconcileSecret(ctx context.Context, kt *honeypodv1alpha1.Decoy, name, clusterIP string) (*corev1.Secret, error) {
	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: name}, &existing)
	if err == nil {
		// A Secret created before the decoy ran its own
		// kube-controller-manager has no kcm.token. Backfill one in place so
		// an upgrade doesn't leave the new KCM container unauthenticated,
		// without disturbing the decoy/shim identities an attacker may hold.
		if len(existing.Data["kcm.token"]) == 0 {
			kcmToken, err := generateToken()
			if err != nil {
				return nil, err
			}
			if existing.Data == nil {
				existing.Data = map[string][]byte{}
			}
			existing.Data["kcm.token"] = []byte(kcmToken)
			if err := r.Update(ctx, &existing); err != nil {
				return nil, fmt.Errorf("backfilling kcm token: %w", err)
			}
		}
		// Keep the identity an attacker may already hold, but the serving
		// cert has to actually cover the address the apiserver dials. If
		// the Service was recreated with a different ClusterIP, the old
		// SANs no longer match and every exec/attach/logs call fails TLS
		// verification while the decoy still reports Ready, so reissue
		// just the cert and leave the token alone.
		//
		// With no ClusterIP at all (a headless Service, or one the API
		// server has not assigned yet) there is nothing to cover: a cert
		// reissued for it would fail the same check on the next pass and
		// rewrite the Secret forever, and every rewrite wakes the
		// Owns(Secret) watch into another reconcile. Leave the cert alone.
		if clusterIP == "" || certCoversIP(existing.Data["tls.crt"], clusterIP) {
			return &existing, nil
		}
		return r.reissueServingCert(ctx, kt, &existing, clusterIP)
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	// A second, separate credential for kubelet-shim's own client, so its
	// seeding/housekeeping is attributable to a system: identity instead of
	// looking like attacker traffic. See renderTokenAuthFile.
	shimToken, err := generateToken()
	if err != nil {
		return nil, err
	}
	// A third credential for the decoy's own kube-controller-manager, under
	// a system:kube-controller-manager identity so its (substantial) real
	// housekeeping traffic is filtered from attacker alerts the same way the
	// shim's is. See renderTokenAuthFile and buildDeployment's KCM container.
	kcmToken, err := generateToken()
	if err != nil {
		return nil, err
	}
	// CommonName deliberately does not mention honeypod/decoy/kine/fake --
	// this CA's cert is presented over TLS to anyone who connects,
	// including an attacker holding the decoy token, and "kubernetes" is
	// what a real kubeadm-provisioned cluster's own root CA is named.
	caCert, caKey, err := certs.GenerateCA("kubernetes")
	if err != nil {
		return nil, err
	}
	// clusterIP is included as a SAN because the real inner kube-apiserver's
	// kubelet-client proxy dials kubelet-shim directly at this IP (by IP,
	// not by DNS name) for exec/attach/logs -- see the ordering comment in
	// Reconcile for why this must be known at first issuance rather than
	// patched in later.
	dnsNames := append([]string{serviceDNSName(kt.Name, kt.Namespace), kt.Name, "localhost", "127.0.0.1", clusterIP}, kt.Spec.SANs...)
	leafCert, leafKey, err := certs.IssueServerCert(caCert, caKey, dnsNames)
	if err != nil {
		return nil, err
	}
	// Required for the inner kube-apiserver to start at all -- see
	// certs.GenerateServiceAccountSigningKey's doc comment. Not a second
	// credential system: no real ServiceAccount token flow ever runs
	// against this inner cluster (ServiceAccount admission is disabled).
	saPub, saKey, err := certs.GenerateServiceAccountSigningKey()
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: kt.Namespace, Labels: commonLabels(kt.Name)},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"token":      []byte(token),
			"shim.token": []byte(shimToken),
			"kcm.token":  []byte(kcmToken),
			"ca.crt":     caCert,
			"ca.key":     caKey,
			"tls.crt":    leafCert,
			"tls.key":    leafKey,
			"sa.pub":     saPub,
			"sa.key":     saKey,
		},
	}
	if err := controllerutil.SetControllerReference(kt, secret, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (r *DecoyReconciler) reconcileKubeconfig(ctx context.Context, kt *honeypodv1alpha1.Decoy, name string, secret *corev1.Secret, server string) error {
	// The identity (token/ca.crt/tls.*) is never regenerated -- reconcileSecret
	// guarantees that -- but the server address embedded in the rendered
	// kubeconfig depends on spec.Port, which *can* change across reconciles.
	// Re-render from the stable identity every time and only write back when
	// it actually differs, so a port change doesn't leave a stale kubeconfig
	// pointing at the old port forever.
	kubeconfig, err := renderKubeconfig(kt.Name, server, secret.Data["ca.crt"], string(secret.Data["token"]))
	if err != nil {
		return err
	}
	if bytes.Equal(secret.Data["kubeconfig"], kubeconfig) {
		return nil
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var latest corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: name}, &latest); err != nil {
			return err
		}
		if latest.Data == nil {
			latest.Data = map[string][]byte{}
		}
		latest.Data["kubeconfig"] = kubeconfig
		return r.Update(ctx, &latest)
	})
}

// reconcileConfigMap renders and applies the single ConfigMap the decoy
// pod mounts (seed.json, token-auth.csv, audit-policy.yaml,
// audit-webhook-kubeconfig.yaml), and returns a checksum covering all of
// their contents so buildDeployment's pod-template annotation forces a
// rollout whenever any of them changes.
func (r *DecoyReconciler) reconcileConfigMap(ctx context.Context, kt *honeypodv1alpha1.Decoy, name string, joined []corev1.Pod, decoyToken, shimToken, kcmToken string) (string, error) {
	managerURL := r.ManagerAuditWebhookURL
	if managerURL == "" {
		managerURL = defaultManagerAuditWebhookURL()
	}
	data, err := renderConfigData(kt, joined, decoyToken, shimToken, kcmToken, managerURL)
	if err != nil {
		return "", err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: kt.Namespace, Labels: commonLabels(kt.Name)},
		Data:       data,
	}
	if err := controllerutil.SetControllerReference(kt, cm, r.Scheme); err != nil {
		return "", err
	}
	if err := r.applyConfigMap(ctx, cm); err != nil {
		return "", err
	}
	// Checksum drives the pod rollout, so it deliberately leaves seed.json
	// out. The other three files are read once by kube-apiserver at
	// startup, so changing them means restarting the pod. The seed is not:
	// kubelet-shim re-reads it from the mounted ConfigMap on every
	// heartbeat.
	//
	// Including it used to restart the whole decoy every time a pod was
	// joined or unjoined, and kine's SQLite lives in an emptyDir, so that
	// discarded everything an attacker had created inside the honeypot
	// mid-session. Objects vanishing while pod ages reset is a far louder
	// tell than anything it was worth.
	rollout := make(map[string]string, len(data))
	for k, v := range data {
		if k == seedFileName {
			continue
		}
		rollout[k] = v
	}
	// Map-key order is deterministic: Go's json.Marshal sorts map keys.
	combined, err := json.Marshal(rollout)
	if err != nil {
		return "", err
	}
	return checksum(combined), nil
}

// A create-or-update against a Deployment/Service/ConfigMap/NetworkPolicy
// this same reconcile just wrote a moment earlier (e.g. the Secret, or a
// previous reconcile still in flight after a fast requeue) routinely loses
// the object to a resourceVersion conflict in between the Get and the
// Update below. That is not a real failure -- retry.RetryOnConflict
// re-fetches and retries in place, so it resolves within this call instead
// of surfacing as a Reconciler error with a stack trace and a full
// requeue-with-backoff for what is actually an ordinary, self-healing race.

// applyResource creates desired if it does not exist, and otherwise brings
// the live object into line with it via mutate, returning whichever object
// now exists on the API server.
//
// Only mutate's fields are written, so anything the API server owns on an
// existing object survives -- a Service's assigned ClusterIP above all,
// which is immutable and would be rejected if this replaced the whole spec.
// Returning the live object is what lets applyService share this body rather
// than keeping a near-identical copy of it just to read that ClusterIP back.
//
// The operator's own labels and controller reference are re-applied on every
// pass, so an object stripped of either (a hand edit, a re-apply from a stale
// manifest) is repaired instead of silently escaping both this controller's
// List selectors and garbage collection.
func applyResource[T client.Object](ctx context.Context, c client.Client, desired T, mutate func(live, desired T)) (T, error) {
	var zero T
	live, ok := desired.DeepCopyObject().(T)
	if !ok {
		return zero, fmt.Errorf("deep-copying %T lost its type", desired)
	}
	key := client.ObjectKeyFromObject(desired)

	err := c.Get(ctx, key, live)
	if apierrors.IsNotFound(err) {
		if err := c.Create(ctx, desired); err != nil {
			return zero, err
		}
		return desired, nil
	}
	if err != nil {
		return zero, err
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, key, live); err != nil {
			return err
		}
		mutate(live, desired)
		live.SetLabels(mergedLabels(live.GetLabels(), desired.GetLabels()))
		live.SetOwnerReferences(desired.GetOwnerReferences())
		return c.Update(ctx, live)
	}); err != nil {
		return zero, err
	}
	return live, nil
}

// mergedLabels overlays the labels this operator manages onto whatever the
// object already carries, rather than replacing the set outright, so labels
// another tool applied (a service mesh, a cost allocator) are left alone.
func mergedLabels(live, desired map[string]string) map[string]string {
	if len(desired) == 0 {
		return live
	}
	if live == nil {
		live = make(map[string]string, len(desired))
	}
	for k, v := range desired {
		live[k] = v
	}
	return live
}

func (r *DecoyReconciler) applyConfigMap(ctx context.Context, cm *corev1.ConfigMap) error {
	_, err := applyResource(ctx, r.Client, cm, func(live, desired *corev1.ConfigMap) {
		live.Data = desired.Data
	})
	return err
}

func (r *DecoyReconciler) applyDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	_, err := applyResource(ctx, r.Client, dep, func(live, desired *appsv1.Deployment) {
		live.Spec = desired.Spec
	})
	return err
}

// applyService creates or updates the Service and returns its ClusterIP --
// this is what every seeded fake Node reports as its own InternalIP (see
// kubeletshim.Config.NodeInternalIP's doc comment), so the caller needs it
// back to bake into the Deployment's kubelet-shim container args.
func (r *DecoyReconciler) applyService(ctx context.Context, svc *corev1.Service) (string, error) {
	live, err := applyResource(ctx, r.Client, svc, func(live, desired *corev1.Service) {
		live.Spec.Ports = desired.Spec.Ports
		live.Spec.Selector = desired.Spec.Selector
	})
	if err != nil {
		return "", err
	}
	return live.Spec.ClusterIP, nil
}

// ensureDataPVC creates the decoy's data PVC if it does not exist. It is
// create-only: an existing claim is left untouched, since it holds the state
// persistence is meant to keep (resizing or replacing it would defeat that).
func (r *DecoyReconciler) ensureDataPVC(ctx context.Context, kt *honeypodv1alpha1.Decoy) error {
	name := kt.Name + "-data"
	var existing corev1.PersistentVolumeClaim
	err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: name}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}

	size := kt.Spec.Persistence.Size
	if size.IsZero() {
		size = resource.MustParse("1Gi")
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: kt.Namespace, Labels: commonLabels(kt.Name)},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: kt.Spec.Persistence.StorageClassName,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: size},
			},
		},
	}
	if err := controllerutil.SetControllerReference(kt, pvc, r.Scheme); err != nil {
		return err
	}
	return r.Create(ctx, pvc)
}

func (r *DecoyReconciler) applyNetworkPolicy(ctx context.Context, np *networkingv1.NetworkPolicy) error {
	_, err := applyResource(ctx, r.Client, np, func(live, desired *networkingv1.NetworkPolicy) {
		live.Spec = desired.Spec
	})
	return err
}

func (r *DecoyReconciler) updateStatus(ctx context.Context, kt *honeypodv1alpha1.Decoy, secretName, server string, joined []corev1.Pod, log logr.Logger) error {
	var dep appsv1.Deployment
	phase := honeypodv1alpha1.DecoyPhasePending
	if err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: kt.Name}, &dep); err == nil {
		if dep.Status.ReadyReplicas > 0 {
			phase = honeypodv1alpha1.DecoyPhaseReady
		}
	}

	condStatus := metav1.ConditionFalse
	if phase == honeypodv1alpha1.DecoyPhaseReady {
		condStatus = metav1.ConditionTrue
	}

	joinedStatus := make([]honeypodv1alpha1.JoinedPod, 0, len(joined))
	for _, p := range joined {
		joinedStatus = append(joinedStatus, honeypodv1alpha1.JoinedPod{
			Name:       p.Name,
			Namespace:  p.Namespace,
			Redirected: podIsRedirected(p),
		})
	}

	// Log at INFO only when the phase actually changes -- a decoy going
	// Pending->Ready is worth one line. Every steady-state reconcile after
	// that (fast requeues from the Pod watch, periodic resync) would
	// otherwise repeat the same line and bury anything real, so those drop
	// to V(1), off by default.
	if phase != kt.Status.Phase {
		log.Info("Decoy phase changed", "phase", phase, "endpoint", server)
	} else {
		log.V(1).Info("reconciled Decoy", "phase", phase, "endpoint", server)
	}

	// Captured before the RetryOnConflict below re-fetches and overwrites
	// kt.Status.Phase, so it reflects the phase this reconcile started from.
	becameReady := phase == honeypodv1alpha1.DecoyPhaseReady && kt.Status.Phase != honeypodv1alpha1.DecoyPhaseReady

	metrics.SetPhase(kt.Namespace, kt.Name, string(phase))
	metrics.JoinedPods.WithLabelValues(kt.Namespace, kt.Name).Set(float64(len(joined)))

	// A concurrent write to this same Decoy (a fast requeue from the Pod
	// watch, or another reconcile still in flight) routinely makes this
	// Update lose kt's resourceVersion. Re-fetching and reapplying inside
	// RetryOnConflict resolves that in place instead of surfacing an
	// ordinary, self-healing race as a Reconciler error.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, types.NamespacedName{Namespace: kt.Namespace, Name: kt.Name}, kt); err != nil {
			return err
		}
		kt.Status.Phase = phase
		kt.Status.Endpoint = server
		kt.Status.CredentialsSecret = secretName
		kt.Status.ObservedGeneration = kt.Generation
		kt.Status.JoinedPods = joinedStatus
		apimeta.SetStatusCondition(&kt.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             condStatus,
			Reason:             string(phase),
			Message:            fmt.Sprintf("Decoy is %s", phase),
			ObservedGeneration: kt.Generation,
		})
		return r.Status().Update(ctx, kt)
	})
	if err == nil && becameReady && r.Recorder != nil {
		r.Recorder.Event(kt, corev1.EventTypeNormal, "Ready", "Decoy is ready")
	}
	return err
}

func (r *DecoyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Scheme = mgr.GetScheme()
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("honeypod")
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&honeypodv1alpha1.Decoy{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapJoinedPodToDecoy),
			builder.WithPredicates(podJoinAnnotationPredicate())).
		Complete(r)
}

// podJoinAnnotationPredicate gates the Pod watch so only Pods that actually
// carry the honeypod.io/join annotation wake the reconciler. Without it the
// controller reconciles on every Pod create/update/delete in the whole
// cluster (the Pod watch is unscoped, since the annotation can't be
// expressed as a watch selector), which does not scale on a busy cluster.
//
// The Update case checks both the old and new object: removing the
// annotation must still enqueue the Decoy the Pod used to point at, so it
// drops the pod from its status. mapJoinedPodToDecoy maps both objects on
// an update, so the right Decoy is still reconciled once this predicate
// lets the event through.
func podJoinAnnotationPredicate() predicate.Predicate {
	has := func(o client.Object) bool {
		if o == nil {
			return false
		}
		_, ok := o.GetAnnotations()[joinAnnotation]
		return ok
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return has(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return has(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return has(e.ObjectOld) || has(e.ObjectNew) },
		GenericFunc: func(e event.GenericEvent) bool { return has(e.Object) },
	}
}

// podIsRedirected reports whether the join webhook actually rewrote this
// Pod, which only happens at CREATE. The decoy ServiceAccount volume is the
// marker: a Pod annotated after it was already running is mirrored into the
// decoy but never passed through admission, so its traffic still reaches the
// real cluster. Reporting the two states identically would say a workload is
// trapped when it is not.
func podIsRedirected(p corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		if v.Name == decoyVolumeName {
			return true
		}
	}
	return false
}
