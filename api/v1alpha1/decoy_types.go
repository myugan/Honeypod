package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FakeNode is a decoy Node the honeypot serves.
type FakeNode struct {
	// Name of the fake node.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// InternalIP reported for the fake node.
	// +optional
	InternalIP string `json:"internalIP,omitempty"`
	// KubeletVersion reported for the fake node.
	// +optional
	KubeletVersion string `json:"kubeletVersion,omitempty"`
}

// FakeContainer is one container of a decoy Pod.
type FakeContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

// FakePod is a decoy Pod, or a set of replicas, the honeypot serves.
type FakePod struct {
	// Name is the base name for the fake pod(s).
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Namespace the fake pod(s) live in.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
	// Replicas is how many fake pod objects to synthesize.
	// +kubebuilder:default=1
	// +optional
	Replicas int32 `json:"replicas,omitempty"`
	// Containers making up each fake pod.
	Containers []FakeContainer `json:"containers"`
	// NodeName the fake pod(s) claim to be scheduled on. Must name one of
	// spec.fakeNodes. Defaults to the first one.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	NodeName string `json:"nodeName,omitempty"`
	// LogLines are the fake lines served by `kubectl logs` for this pod, in order.
	// +optional
	LogLines []string `json:"logLines,omitempty"`
	// Labels are applied to each fake pod object. Defaults to {"app": Name}.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// FakeSecret is a decoy Secret the honeypot serves, to bait credential theft.
type FakeSecret struct {
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:MinLength=1
	Namespace string            `json:"namespace"`
	Data      map[string]string `json:"data"`
}

// DecoySpec defines the desired state of a Decoy environment.
// +kubebuilder:validation:XValidation:rule="!has(self.fakePods) || self.fakePods.all(p, !has(p.nodeName) || size(p.nodeName) == 0 || (has(self.fakeNodes) && self.fakeNodes.exists(n, n.name == p.nodeName)))",message="each fakePods[].nodeName must name one of spec.fakeNodes"
// +kubebuilder:validation:XValidation:rule="!has(self.execIsolation) || !self.execIsolation || (has(self.runtimeClassName) && size(self.runtimeClassName) > 0)",message="spec.execIsolation requires spec.runtimeClassName so the added privilege (root, CAP_SYS_ADMIN, no seccomp) is bounded by a sandboxed runtime such as gVisor rather than the host kernel"
type DecoySpec struct {
	// KubeletShimImage overrides the kubelet-shim image, for a private
	// registry or a custom build. Defaults to honeypod/kubelet-shim:latest.
	// +optional
	KubeletShimImage string `json:"kubeletShimImage,omitempty"`

	// ExecProfile selects the environment a `kubectl exec` session presents,
	// to match the kind of image the pods claim to run:
	//   - "shell" (default): a full /bin/sh with the usual tools.
	//   - "minimal": a busybox shell (busybox applets only), like alpine.
	//   - "distroless": no shell; exec fails with the real "executable file
	//     not found" error like a distroless image (and runs no process).
	// +kubebuilder:validation:Enum=shell;minimal;distroless
	// +kubebuilder:default=shell
	// +optional
	ExecProfile string `json:"execProfile,omitempty"`

	// ExecIsolation runs each `kubectl exec` session in its own PID/mount/UTS
	// namespace, so `ps` and /proc/1 show only that session and each pod
	// reports its own hostname. Off by default. It needs the exec container to
	// run as root with CAP_SYS_ADMIN and seccomp unconfined, which on the host
	// runtime is a real container-escape surface, so it is only allowed when
	// spec.runtimeClassName is also set: a CRD validation rejects
	// execIsolation without a runtime, so the added privilege is always
	// bounded by a sandboxed runtime such as gVisor rather than the host
	// kernel. It does not give the pod's real image contents; use the
	// distroless profile for pods that should have no shell.
	// +optional
	ExecIsolation bool `json:"execIsolation,omitempty"`

	// KubernetesVersion is the version this decoy claims to be, e.g.
	// "v1.35.0". It picks the real kube-apiserver image to run and the
	// version fake nodes report, keeping the two consistent: a node newer
	// than the control plane is impossible in a real cluster and gives the
	// decoy away. Set spec.fakeNodes[].kubeletVersion to make a specific
	// node lag behind, which real clusters do during an upgrade.
	// +kubebuilder:default="v1.35.0"
	// +optional
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`

	// KubeAPIServerImage overrides the image KubernetesVersion would pick,
	// for a private registry or a repackaged build. Its tag should still
	// match KubernetesVersion.
	// +optional
	KubeAPIServerImage string `json:"kubeAPIServerImage,omitempty"`

	// KineImage overrides the kine image, which stores the honeypot's data
	// in SQLite so no real etcd is needed.
	// +kubebuilder:default="rancher/kine:latest"
	// +optional
	KineImage string `json:"kineImage,omitempty"`

	// Port is the port the Service exposes to decoy clients, routed
	// directly to the inner kube-apiserver's own secure port.
	// +kubebuilder:default=6443
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int32 `json:"port,omitempty"`

	// SANs are extra DNS names or IPs added to the honeypot's TLS
	// certificate, to make it resemble a real cluster's apiserver, e.g.
	// "kubernetes.default.svc". Only applied when the certificate is first
	// issued: to change it later, delete the "<name>-decoy" Secret.
	// +optional
	SANs []string `json:"sans,omitempty"`

	// AuditLevel is how much the decoy apiserver records for every request:
	// None logs nothing, Metadata logs who/what/when without bodies, Request
	// adds the request body, and RequestResponse (the default) adds the
	// response too. The operator filters this stream itself for alerts and the
	// activity summary, so a lower level also captures less attacker detail.
	// +kubebuilder:validation:Enum=None;Metadata;Request;RequestResponse
	// +kubebuilder:default=RequestResponse
	// +optional
	AuditLevel string `json:"auditLevel,omitempty"`

	// FakeNodes are the Nodes an attacker sees inside the honeypot.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	// +optional
	FakeNodes []FakeNode `json:"fakeNodes,omitempty"`

	// FakePods are the Pods an attacker sees inside the honeypot. Write an
	// entry here for a pod that exists nowhere for real. To make a pod that
	// already exists show up instead, leave it out and annotate that real
	// Pod with honeypod.io/join, which mirrors it in automatically.
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	// +optional
	FakePods []FakePod `json:"fakePods,omitempty"`

	// FakeSecrets are the Secrets an attacker sees inside the honeypot.
	// Put believable-looking credentials here to bait theft, never real ones.
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=100
	// +optional
	FakeSecrets []FakeSecret `json:"fakeSecrets,omitempty"`

	// Resources applied to every container of the honeypot pod. The
	// default is small but explicit, so this still deploys in a namespace
	// with a ResourceQuota that requires limits.
	// +kubebuilder:default={"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"cpu":"250m","memory":"256Mi"}}
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// RuntimeClassName runs the honeypot pod under a sandboxed container
	// runtime, e.g. "gvisor". `kubectl exec` into a decoy pod runs a real
	// process, so this adds a stronger boundary around it. Unset, the pod
	// uses the cluster's normal runtime and is still hardened: non-root,
	// no capabilities, no privilege escalation, seccomp. Only set this to
	// a RuntimeClass your cluster already has, or the pod won't schedule.
	// +optional
	RuntimeClassName *string `json:"runtimeClassName,omitempty"`

	// SeedSystemComponents adds the standard kube-system pods every real
	// cluster has (etcd, kube-apiserver, kube-controller-manager,
	// kube-scheduler, kube-proxy, coredns) so `kubectl get pods -A` looks
	// like a real cluster with no extra authoring. Defaults to true.
	//
	// Set false to control kube-system yourself: nothing is auto-added,
	// and you declare exactly what an attacker sees via fakePods. Use this
	// to match a specific cluster's real shape, e.g. adding the CNI's own
	// pods (cilium, calico-node) or dropping etcd on a managed cluster
	// like EKS that hides its control plane.
	// +kubebuilder:default=true
	// +optional
	SeedSystemComponents *bool `json:"seedSystemComponents,omitempty"`

	// FakeCRDs are CustomResourceDefinitions installed into the decoy's
	// inner apiserver as real CRDs, so `kubectl get crds` lists them and
	// their custom resource types are served -- making the decoy look like
	// it runs the operators a real cluster would (cert-manager, Argo, etc.).
	// A believable default set is seeded automatically when
	// seedSystemComponents is true; entries here are added on top.
	// +listType=map
	// +listMapKey=plural
	// +kubebuilder:validation:MaxItems=100
	// +optional
	FakeCRDs []FakeCRD `json:"fakeCRDs,omitempty"`

	// Persistence backs the decoy's storage (kine's SQLite and the
	// apiserver's audit.log) with a PersistentVolumeClaim instead of an
	// emptyDir. Left unset, that storage is ephemeral: a pod reschedule
	// starts the inner cluster fresh and drops whatever an attacker created
	// and the audit.log on disk. Set it for a long-running engagement where
	// that state must survive a reschedule.
	// +optional
	Persistence *PersistenceSpec `json:"persistence,omitempty"`
}

// FakeCRD describes a CustomResourceDefinition to install into the decoy.
// The served schema is permissive (unknown fields preserved): a decoy only
// needs the type to appear in discovery and `kubectl get crds`, and custom
// resources of it to be creatable/listable, not full field validation.
type FakeCRD struct {
	// Group is the API group, e.g. "cert-manager.io".
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`

	// Kind is the resource kind, e.g. "Certificate".
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Kind string `json:"kind"`

	// Plural is the lowercase plural name, e.g. "certificates". It is the
	// list-map key, so it must be unique within spec.fakeCRDs.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Plural string `json:"plural"`

	// Singular is the lowercase singular; defaults to the lowercased Kind.
	// +optional
	Singular string `json:"singular,omitempty"`

	// ShortNames are optional CLI aliases, e.g. ["cert","certs"].
	// +optional
	ShortNames []string `json:"shortNames,omitempty"`

	// Versions served by this CRD; defaults to ["v1"]. The first entry is
	// the storage version.
	// +optional
	Versions []string `json:"versions,omitempty"`

	// Scope is "Namespaced" (default) or "Cluster".
	// +kubebuilder:validation:Enum=Namespaced;Cluster
	// +optional
	Scope string `json:"scope,omitempty"`
}

// PersistenceSpec configures durable storage for a decoy.
type PersistenceSpec struct {
	// StorageClassName selects the StorageClass for the claim. Unset uses
	// the cluster's default class.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`

	// Size is the requested volume size. Defaults to 1Gi.
	// +kubebuilder:default="1Gi"
	// +optional
	Size resource.Quantity `json:"size,omitempty"`
}

// JoinedPod is a real Pod mirrored into the honeypot by the
// honeypod.io/join annotation. Only its metadata is copied: name,
// namespace, images, and labels, never its Secrets or volumes. The real
// node it runs on is left out too, so the honeypot places it on one of
// spec.fakeNodes instead of naming a real one.
type JoinedPod struct {
	// Name of the real Pod.
	Name string `json:"name"`
	// Namespace of the real Pod.
	Namespace string `json:"namespace"`

	// Redirected reports whether this Pod's own traffic goes to the
	// honeypot. It is true only when the Pod passed through the join
	// webhook at creation, which is what swaps in the decoy API address
	// and token.
	//
	// Annotating a Pod that is already running still mirrors it here, so
	// an attacker inside the honeypot sees it, but a Pod's env and volumes
	// cannot be changed after creation, so its traffic keeps reaching the
	// real cluster until it is recreated. False means exactly that: listed
	// inside the decoy, not yet trapped.
	// +optional
	Redirected bool `json:"redirected,omitempty"`
}

// IntrusionActivity is a running summary of the requests a decoy has drawn.
// It exists so `kubectl get decoys` can show which traps have been poked at
// without anyone having to open the audit log.
type IntrusionActivity struct {
	// FirstSeen is when this decoy got its first request from someone who
	// should not have been talking to it.
	// +optional
	FirstSeen *metav1.Time `json:"firstSeen,omitempty"`
	// LastSeen is the most recent such request.
	// +optional
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
	// RequestCount is how many of those requests we have counted so far.
	// +optional
	RequestCount int64 `json:"requestCount,omitempty"`
	// LastSourceIP is where the most recent one came from.
	// +optional
	LastSourceIP string `json:"lastSourceIP,omitempty"`
}

// DecoyPhase is the coarse lifecycle phase of a Decoy.
type DecoyPhase string

const (
	DecoyPhasePending DecoyPhase = "Pending"
	DecoyPhaseReady   DecoyPhase = "Ready"
	DecoyPhaseFailed  DecoyPhase = "Failed"
)

// DecoyStatus defines the observed state of a Decoy environment.
type DecoyStatus struct {
	// Phase is Pending, Ready, or Failed. On Failed, the Ready condition
	// carries the reason.
	// +optional
	Phase DecoyPhase `json:"phase,omitempty"`

	// Endpoint is the in-cluster address clients reach the honeypot on.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// CredentialsSecret names the Secret holding everything needed to reach
	// this honeypot: the decoy token, the CA, the TLS keypair, and a
	// ready-to-use kubeconfig.
	// +optional
	CredentialsSecret string `json:"credentialsSecret,omitempty"`

	// ObservedGeneration is the most recent generation reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// JoinedPods are the real Pods currently mirrored into the honeypot
	// by the honeypod.io/join annotation.
	// +optional
	JoinedPods []JoinedPod `json:"joinedPods,omitempty"`

	// IntrusionActivity summarizes the traffic this decoy has drawn, so
	// `kubectl get decoys` surfaces which traps have been touched without
	// reading the audit log. Only requests under a non-system identity
	// (someone holding the decoy token) are counted here, never the
	// operator's own housekeeping.
	// +optional
	IntrusionActivity *IntrusionActivity `json:"intrusionActivity,omitempty"`

	// Conditions represent the latest available observations of the Decoy's state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Hits",type=integer,JSONPath=`.status.intrusionActivity.requestCount`
// +kubebuilder:printcolumn:name="Last-Seen",type=date,JSONPath=`.status.intrusionActivity.lastSeen`
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.credentialsSecret`,priority=1
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.status.endpoint`,priority=1
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:resource:shortName=dc

// Decoy is the Schema for the decoys API. It describes an isolated,
// fully decoy Kubernetes control plane -- a real kube-apiserver (backed by
// kine, no real etcd), seeded by kubelet-shim with synthetic Nodes/Pods/
// Secrets -- authenticated only by a decoy token with zero access to any
// real cluster, with every request recorded in real Kubernetes audit-log
// format via kube-apiserver's own audit webhook.
type Decoy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DecoySpec   `json:"spec,omitempty"`
	Status DecoyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DecoyList contains a list of Decoy.
type DecoyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Decoy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Decoy{}, &DecoyList{})
}
