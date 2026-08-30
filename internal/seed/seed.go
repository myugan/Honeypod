// Package seed defines the on-disk (ConfigMap-mounted) description of what a
// Decoy's inner Kubernetes control plane should be seeded with -- the one
// shared shape both the operator (which renders it into a ConfigMap from
// DecoySpec) and kubelet-shim (which reads it and turns it into real
// Node/Pod/Secret objects against the inner apiserver) agree on. This is the
// single code path that turns a Decoy's Fake* spec fields into running
// objects: the operator never talks to the inner apiserver itself, and
// kubelet-shim never reads DecoySpec directly -- both go through this
// type.
package seed

import (
	"encoding/json"
	"fmt"
	"os"

	"honeypod.io/honeypod/api/v1alpha1"
)

// Seed is a direct subset of DecoySpec so the operator can render it with
// no translation, and kubelet-shim can load it with no translation either.
//
// Controllers are seed-only (they have no DecoySpec field): the operator
// synthesizes them for the auto-seeded kube-system components so a seeded
// pod shows a real owning object under `kubectl describe`/`get rs|ds|deploy`
// instead of "Controlled By: <none>".
type Seed struct {
	FakeNodes   []v1alpha1.FakeNode   `json:"fakeNodes"`
	FakePods    []Pod                 `json:"fakePods"`
	FakeSecrets []v1alpha1.FakeSecret `json:"fakeSecrets"`
	Controllers []Controller          `json:"controllers,omitempty"`

	// CRDs are installed as real CustomResourceDefinitions in the inner
	// apiserver, so `kubectl get crds` lists them and the custom resource
	// types they define are served -- making the decoy look like it runs the
	// operators a real cluster would. This is the one class of object no
	// running component creates on its own: RBAC defaults come from the
	// apiserver's own bootstrap, and ServiceAccounts / tokens /
	// kube-root-ca.crt / endpoints / lifecycle Events are produced for real
	// by the kube-controller-manager the decoy now runs (see render.go).
	// Installing a CRD is exactly how a real cluster gets one, so these are
	// genuine objects too, not cosmetic strings.
	CRDs []CRD `json:"crds,omitempty"`

	// The objects below are the standard fixtures every real cluster carries
	// that no component here recreates on its own -- a decoy that returns an
	// empty `get svc -n kube-system` / `get cm -n kube-system` / `get leases`
	// is an obvious tell. The shim creates them as real objects.

	// Services (with their EndpointSlice, when a ClusterIP is set) the decoy
	// should serve, e.g. the kube-dns Service every cluster has.
	Services []Service `json:"services,omitempty"`
	// ConfigMaps the decoy should carry, e.g. the kube-system kubeadm-config/
	// kubelet-config/coredns/kube-proxy set and kube-public/cluster-info.
	// These are static kubeadm install artifacts that no running component
	// recreates, so seeding them into kine is how a real cluster carries them
	// too. The leader-election Leases a real control plane holds
	// (kube-controller-manager, kube-scheduler) are NOT seeded here: the
	// decoy now runs the real KCM and scheduler with --leader-elect, so they
	// write their own Leases for real.
	ConfigMaps []ConfigMap `json:"configMaps,omitempty"`
}

// Service is a real Service to create in the decoy. When ClusterIP is set the
// shim also creates a matching EndpointSlice, so `get endpoints`/`get
// endpointslices` for it are non-empty like a real Service's.
type Service struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	ClusterIP string            `json:"clusterIP,omitempty"`
	Ports     []ServicePort     `json:"ports,omitempty"`
	Selector  map[string]string `json:"selector,omitempty"`
	// EndpointIPs back the Service's EndpointSlice, e.g. the seeded coredns
	// pod IPs for kube-dns. Ignored when ClusterIP is empty.
	EndpointIPs []string `json:"endpointIPs,omitempty"`
}

// ServicePort is a compact Service port.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort int32  `json:"targetPort,omitempty"`
	Protocol   string `json:"protocol,omitempty"` // TCP (default) or UDP
}

// ConfigMap is a real ConfigMap to create in the decoy.
type ConfigMap struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
	Data      map[string]string `json:"data,omitempty"`
}

// CRD is a compact description of a CustomResourceDefinition to install. The
// shim builds a permissive (preserve-unknown-fields) served schema from it,
// which is all a decoy needs: the resource type shows up in discovery and
// `kubectl get crds`, and custom resources of it can be listed/created.
type CRD struct {
	// Group is the API group, e.g. "cert-manager.io".
	Group string `json:"group"`
	// Kind is the resource kind, e.g. "Certificate".
	Kind string `json:"kind"`
	// Plural is the lowercase plural resource name, e.g. "certificates".
	Plural string `json:"plural"`
	// Singular is the lowercase singular; defaults to lowercased Kind.
	Singular string `json:"singular,omitempty"`
	// ShortNames are optional CLI aliases, e.g. ["cert","certs"].
	ShortNames []string `json:"shortNames,omitempty"`
	// Versions served; defaults to ["v1"]. The first is the storage version.
	Versions []string `json:"versions,omitempty"`
	// Scope is "Namespaced" (default) or "Cluster".
	Scope string `json:"scope,omitempty"`
}

// Pod is a fake pod plus the ownership/metadata a real controller-owned or
// static pod carries. The embedded FakePod keeps the DecoySpec shape; the
// extra fields are set only by the operator, never by a Decoy author.
type Pod struct {
	v1alpha1.FakePod `json:",inline"`

	// OwnerRefs are put on the pod (and each replica) so it reports a real
	// controller under `kubectl describe pod`. Empty means a standalone pod.
	OwnerRefs []OwnerRef `json:"ownerRefs,omitempty"`
	// Annotations are merged onto the pod. Used for the static/mirror-pod
	// markers (kubernetes.io/config.source etc.) on control-plane pods.
	Annotations map[string]string `json:"annotations,omitempty"`

	// HostNetwork marks the pod as host-networked, which the shim reflects by
	// reporting podIP == hostIP (the node IP) -- the real shape of a static
	// control-plane pod (etcd, kube-apiserver, kube-proxy). A separate pod IP
	// on those pods is a tell.
	HostNetwork bool `json:"hostNetwork,omitempty"`
	// CPURequest/MemoryRequest, when set, are applied as resource requests on
	// each container, so a control-plane pod reports a Burstable QoS class
	// like the real thing instead of BestEffort.
	CPURequest    string `json:"cpuRequest,omitempty"`
	MemoryRequest string `json:"memoryRequest,omitempty"`
}

// Controller is an owning object (Deployment, ReplicaSet, DaemonSet) the shim
// creates so a seeded pod's owner reference resolves to a real object.
type Controller struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Labels     map[string]string `json:"labels,omitempty"`
	Replicas   int32             `json:"replicas,omitempty"`
	Image      string            `json:"image,omitempty"`
	OwnerRefs  []OwnerRef        `json:"ownerRefs,omitempty"`
}

// OwnerRef is the minimal owner reference the seed carries.
type OwnerRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller bool   `json:"controller"`
}

// Load reads and parses a seed JSON file from disk.
func Load(path string) (*Seed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading seed file: %w", err)
	}
	var s Seed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parsing seed file: %w", err)
	}
	return &s, nil
}
