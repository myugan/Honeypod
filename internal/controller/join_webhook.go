// This file implements the honeypod.io/join admission webhook: an HTTPS
// admission-review endpoint (started from cmd/manager, alongside the
// internal/auditwebhook receiver) that injects an in-cluster-API redirect
// and the decoy ServiceAccount-token volume/mounts into a real,
// externally-owned Pod at CREATE time, when it carries that annotation.
//
// The redirect mechanism here is an env-var override, not a network-layer
// (iptables/eBPF) interception: this webhook overrides
// KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT directly in every
// container's declared env. kubelet builds a container's final environment
// by starting from the vars it auto-injects for every active Service
// (including the real cluster's own "kubernetes" Service) and then
// applying the container spec's own declared Env on top, so an explicit
// entry of the same name here wins. client-go's rest.InClusterConfig() --
// and the equivalent convention in every other official Kubernetes client
// SDK -- reads exactly those two variables to find "the" API server. That
// means this mechanism needs no packet-level interception at all: no
// iptables, no NET_ADMIN, no CNI dependency, and nothing for a kube-proxy
// replacement to race against, because there's no packet to intercept in
// the first place. The trade-off, honestly: it only catches discovery via
// this env-var convention, not a client that resolves kubernetes.default.svc
// by DNS or has the real ClusterIP hardcoded from prior recon -- there is
// no portable network-layer fallback for that broader case.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
)

// PodJoinMutator implements the mutation decision for one admitted Pod.
// It's kept separate from the HTTP/AdmissionReview framing (below) so a
// test can call MutatePod directly with a plain *corev1.Pod, and so review
// can call it and turn the result into a JSON patch without either knowing
// about the other's format.
type PodJoinMutator struct {
	// Client is used read-only here: looking up the Decoy the
	// annotation names and its Service's ClusterIP. It's expected to be
	// the manager's own cached client (mgr.GetClient()) -- by the time a
	// Pod carrying honeypod.io/join is actually created, the referenced
	// Decoy has normally already been reconciled at least once, so its
	// Service exists with an allocated ClusterIP.
	Client client.Client
}

// MutatePod returns a deep-copied, mutated Pod if pod carries a
// honeypod.io/join annotation naming a Decoy whose Service has a known
// ClusterIP; nil (no mutation, not an error) if the annotation is absent,
// malformed, or names a Decoy/Service that doesn't exist (yet, or ever)
// -- matching this project's existing "a dangling honeypod.io/join
// annotation is silently ignored" convention for the reconciler's own
// listJoinedPods, and matching this webhook's failurePolicy: Ignore
// design: a lookup problem here must never block ordinary pod creation.
func (m *PodJoinMutator) MutatePod(ctx context.Context, pod *corev1.Pod) (*corev1.Pod, error) {
	ktNamespace, ktName, ok := resolveJoinAnnotation(ctx, m.Client, pod.Namespace, pod.Annotations[joinAnnotation])
	if !ok {
		return nil, nil
	}

	var kt honeypodv1alpha1.Decoy
	if err := m.Client.Get(ctx, types.NamespacedName{Namespace: ktNamespace, Name: ktName}, &kt); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var svc corev1.Service
	if err := m.Client.Get(ctx, types.NamespacedName{Namespace: ktNamespace, Name: ktName}, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			// The Decoy exists but hasn't been reconciled yet (no
			// Service/ClusterIP to redirect to). Skip this admission
			// rather than block pod creation; a subsequent pod
			// create/recreate after the Decoy is Ready will pick up
			// the treatment.
			return nil, nil
		}
		return nil, err
	}
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone {
		return nil, nil
	}

	// Same-namespace joined pods can mount the primary "-decoy" Secret
	// directly (a Secret volume only needs to be in the pod's own
	// namespace, which it already is); a different-namespace pod needs
	// the mirrored per-namespace credentials Secret that
	// reconcileMirroredSecrets maintains (see that function's and
	// buildMirroredSecret's doc comments for why OwnerReferences
	// can't do this and labels are used instead).
	secretName := decoySecretName(ktName)
	if pod.Namespace != ktNamespace {
		secretName = mirroredSecretName(ktName)
	}

	mutated := pod.DeepCopy()

	// The built-in ServiceAccount admission plugin may have already added
	// its own real token volume/mount at this same path. A cluster webhook
	// that also touches automountServiceAccountToken (e.g. Kyverno) can
	// cause a duplicate mount here too, confirmed live. Stripping by path,
	// not just by the real auto-mount's volume-name convention, keeps this
	// idempotent either way: the decoy ends up as the only thing mounted
	// at the ServiceAccount path.
	wantPath := strings.TrimSuffix(serviceAccountTokenMountPath, "/")
	autoVolNames := map[string]bool{}
	for _, v := range mutated.Spec.Volumes {
		if strings.HasPrefix(v.Name, "kube-api-access-") {
			autoVolNames[v.Name] = true
		}
	}
	stripAutoMount := func(mounts []corev1.VolumeMount) []corev1.VolumeMount {
		kept := mounts[:0]
		for _, m := range mounts {
			if autoVolNames[m.Name] || strings.TrimSuffix(m.MountPath, "/") == wantPath {
				autoVolNames[m.Name] = true
				continue
			}
			kept = append(kept, m)
		}
		return kept
	}
	for i := range mutated.Spec.Containers {
		mutated.Spec.Containers[i].VolumeMounts = stripAutoMount(mutated.Spec.Containers[i].VolumeMounts)
	}
	for i := range mutated.Spec.InitContainers {
		mutated.Spec.InitContainers[i].VolumeMounts = stripAutoMount(mutated.Spec.InitContainers[i].VolumeMounts)
	}
	keptVolumes := mutated.Spec.Volumes[:0]
	for _, v := range mutated.Spec.Volumes {
		if autoVolNames[v.Name] {
			continue
		}
		keptVolumes = append(keptVolumes, v)
	}
	mutated.Spec.Volumes = keptVolumes
	falseVal := false
	mutated.Spec.AutomountServiceAccountToken = &falseVal

	vol := decoyServiceAccountVolume(secretName)
	mutated.Spec.Volumes = append(mutated.Spec.Volumes, vol)

	// "you don't know which container is 'the app'" -- apply both the
	// token-volume mount and the API-server env override to every
	// container already in the pod spec (main containers and any
	// pre-existing init containers).
	mount := corev1.VolumeMount{Name: vol.Name, MountPath: serviceAccountTokenMountPath, ReadOnly: true}
	svcEnv := kubernetesServiceEnv(svc.Spec.ClusterIP, servicePort(&kt), realKubernetesServicePort(ctx, m.Client))
	for i := range mutated.Spec.Containers {
		mutated.Spec.Containers[i].VolumeMounts = append(mutated.Spec.Containers[i].VolumeMounts, mount)
		mutated.Spec.Containers[i].Env = append(mutated.Spec.Containers[i].Env, svcEnv...)
	}
	for i := range mutated.Spec.InitContainers {
		mutated.Spec.InitContainers[i].VolumeMounts = append(mutated.Spec.InitContainers[i].VolumeMounts, mount)
		mutated.Spec.InitContainers[i].Env = append(mutated.Spec.InitContainers[i].Env, svcEnv...)
	}

	// kubelet also injects one env-var family per Service that exists in
	// the Pod's own namespace at CREATE time (the legacy "service links"
	// feature), named after the Service. The join webhook's own Service
	// (this Decoy's own name) matches that whenever the Decoy and
	// the Pod it joins share a namespace, so without this a pod would
	// carry a second, unexplained *_SERVICE_HOST/*_PORT_<n>_TCP family
	// naming the honeypot's own ClusterIP and, worse, its kubelet-shim
	// port 10250 -- a far louder tell than anything above. False here
	// only suppresses that per-Service family; the special "kubernetes"
	// one above is unconditional and unaffected.
	falsePtr := false
	mutated.Spec.EnableServiceLinks = &falsePtr

	return mutated, nil
}

// realKubernetesServicePortDefault is the near-universal port of every
// real cluster's own "kubernetes" Service (kubeadm, EKS, GKE, AKS, kind,
// k3s all use it), used only if the live lookup below fails.
const realKubernetesServicePortDefault = 443

// realKubernetesServicePort returns the real cluster's own "kubernetes"
// Service port -- kubelet names its per-port env vars
// (KUBERNETES_PORT_<port>_TCP and friends) after that Service's actual
// port, not this Decoy's, and that injection happens unconditionally
// regardless of EnableServiceLinks. Building our override under any other
// number leaves kubelet's own real-cluster family sitting right beside
// ours under a different name instead of being replaced by it -- observed
// live: KUBERNETES_PORT_443_TCP_ADDR still named the real cluster while
// KUBERNETES_PORT_6443_TCP_ADDR named the decoy, in the same pod's env.
func realKubernetesServicePort(ctx context.Context, c client.Client) int32 {
	var svc corev1.Service
	if err := c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, &svc); err == nil {
		for _, p := range svc.Spec.Ports {
			if p.Name == "https" || len(svc.Spec.Ports) == 1 {
				return p.Port
			}
		}
	}
	return realKubernetesServicePortDefault
}

// kubernetesServiceEnv renders every env var kubelet would inject for the
// "kubernetes" Service if it had a single port named "https" at port --
// matching the full shape of what every pod normally gets, so nothing
// about this pod's environment looks inconsistent once host/clusterIP is
// the decoy's. Left at just SERVICE_HOST/SERVICE_PORT before, the
// PORT_<real-port>_TCP* family for the actual "kubernetes" Service still
// named the real cluster's IP right next to these two, which is exactly
// the kind of contradiction that gives a decoy away under inspection.
//
// realPort names the per-port vars (KUBERNETES_PORT_<realPort>_TCP*),
// matching what kubelet already injected for the real "kubernetes"
// Service so this override replaces it outright instead of merely adding
// a second family alongside it under the decoy's own port number.
func kubernetesServiceEnv(clusterIP string, decoyPort, realPort int32) []corev1.EnvVar {
	decoyPortStr := strconv.Itoa(int(decoyPort))
	realPortStr := strconv.Itoa(int(realPort))
	tcpAddr := fmt.Sprintf("tcp://%s:%s", clusterIP, decoyPortStr)
	return []corev1.EnvVar{
		{Name: "KUBERNETES_SERVICE_HOST", Value: clusterIP},
		{Name: "KUBERNETES_SERVICE_PORT", Value: decoyPortStr},
		{Name: "KUBERNETES_SERVICE_PORT_HTTPS", Value: decoyPortStr},
		{Name: "KUBERNETES_PORT", Value: tcpAddr},
		{Name: "KUBERNETES_PORT_" + realPortStr + "_TCP", Value: tcpAddr},
		{Name: "KUBERNETES_PORT_" + realPortStr + "_TCP_PROTO", Value: "tcp"},
		{Name: "KUBERNETES_PORT_" + realPortStr + "_TCP_PORT", Value: decoyPortStr},
		{Name: "KUBERNETES_PORT_" + realPortStr + "_TCP_ADDR", Value: clusterIP},
	}
}

// parseJoinTarget splits an explicit honeypod.io/join annotation value
// into its "<namespace>/<name>" halves -- empty, missing-slash, or
// empty-segment values are all rejected (ok=false). Does not handle the
// "true" shorthand; see resolveJoinAnnotation for that.
func parseJoinTarget(value string) (namespace, name string, ok bool) {
	if value == "" {
		return "", "", false
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// resolveJoinAnnotation resolves a honeypod.io/join annotation value for a
// Pod in podNamespace to a target Decoy namespace/name. Handles both
// forms: an explicit "<namespace>/<name>" (parseJoinTarget), and
// joinAnnotationImplicit ("true").
//
// For "true" the resolution is single-decoy first: if exactly one Decoy
// exists in the whole cluster, a "true" pod in ANY namespace relays to it --
// so one decoy can be the target of bait scattered across the cluster without
// naming it (see docs/architecture.md). Only when there is more than one
// Decoy does it fall back to the per-namespace rule (the sole Decoy in
// the pod's own namespace). Zero Decoys, or an ambiguous pod namespace with
// several, resolves to ok=false, matching the "a dangling honeypod.io/join
// annotation is silently ignored" convention. Shared by MutatePod here and by
// mapJoinedPodToDecoy (honeypod_controller.go) so both resolve identically.
func resolveJoinAnnotation(ctx context.Context, c client.Client, podNamespace, value string) (namespace, name string, ok bool) {
	if value == joinAnnotationImplicit {
		var all honeypodv1alpha1.DecoyList
		if err := c.List(ctx, &all); err != nil {
			return "", "", false
		}
		// Single decoy in the cluster: any "true" pod relays to it.
		if len(all.Items) == 1 {
			return all.Items[0].Namespace, all.Items[0].Name, true
		}
		// Otherwise, the sole Decoy in the pod's own namespace.
		var inNS []honeypodv1alpha1.Decoy
		for i := range all.Items {
			if all.Items[i].Namespace == podNamespace {
				inNS = append(inNS, all.Items[i])
			}
		}
		if len(inNS) == 1 {
			return podNamespace, inNS[0].Name, true
		}
		return "", "", false
	}
	return parseJoinTarget(value)
}

// NewPodMutationHandler builds the HTTPS handler the
// MutatingWebhookConfiguration (config/manager/webhook.yaml) sends
// AdmissionReview requests to. A Pod without a valid honeypod.io/join
// annotation -- the overwhelming majority of admission requests, since
// failurePolicy: Ignore + no reliable "has this annotation" object
// selector means this webhook's rules can't be scoped any tighter than
// "all Pod CREATEs" at the MutatingWebhookConfiguration level -- gets an
// allowed response with no patch: a pure no-op, never a rejection.
func NewPodMutationHandler(m *PodJoinMutator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var review admissionv1.AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		out := admissionv1.AdmissionReview{
			TypeMeta: review.TypeMeta,
			Response: m.review(r.Context(), review.Request),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

// review is the core admission-review decision logic, kept separate from
// NewPodMutationHandler's HTTP/JSON framing so a test can construct an
// *admissionv1.AdmissionRequest by hand and call this directly, exercising
// the real decision code (MutatePod, the JSON-patch construction) without
// any HTTP layer involved.
func (m *PodJoinMutator) review(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req == nil {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		// Fail open: a malformed object we can't even parse must not
		// block pod creation over a webhook bug -- failurePolicy: Ignore
		// already makes this the apiserver's own fallback for a timeout
		// or connection error, so an explicit parse failure gets the
		// same treatment for consistency.
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}

	mutated, err := m.MutatePod(ctx, &pod)
	if err != nil || mutated == nil {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}

	mutatedRaw, err := json.Marshal(mutated)
	if err != nil {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}
	patch, err := jsonpatch.CreatePatch(req.Object.Raw, mutatedRaw)
	if err != nil {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}

	pt := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		UID:       req.UID,
		Allowed:   true,
		Patch:     patchBytes,
		PatchType: &pt,
	}
}
