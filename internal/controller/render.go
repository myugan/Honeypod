package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/seed"
)

const (
	labelApp       = "app.kubernetes.io/name"
	labelInstance  = "app.kubernetes.io/instance"
	labelManagedBy = "app.kubernetes.io/managed-by"
	managedByValue = "honeypod-operator"

	// innerAPIPort is the inner kube-apiserver's own --secure-port. The
	// Service targets it directly (kube-apiserver already terminates real
	// TLS with the decoy cert itself -- there is nothing left for a
	// reverse-proxy hop to add); the iptables redirect init container also
	// targets it directly for a pod's own outbound "in-cluster config"
	// traffic.
	innerAPIPort = 8443
	// kineListenAddr is kine's loopback-only listen address -- kine and
	// kube-apiserver are containers in the same pod, so this never needs
	// to leave the pod's network namespace, and is plain HTTP (loopback
	// trust) rather than TLS, avoiding a third certificate to manage.
	kineListenAddr = "127.0.0.1:2379"
	// kubeletPort is kubelet-shim's own HTTPS server port, advertised via
	// each seeded fake Node's status.daemonEndpoints.kubeletEndpoint --
	// this is what the real kube-apiserver's kubelet-client proxy dials
	// for pods/exec, pods/attach, and pods/log against a pod scheduled on
	// one of these fake nodes.
	kubeletPort = 10250

	seedFileName                   = "seed.json"
	tokenAuthFileName              = "token-auth.csv"
	auditPolicyFileName            = "audit-policy.yaml"
	auditWebhookKubeconfigFileName = "audit-webhook-kubeconfig.yaml"
	// kcmKubeconfigFileName is the kubeconfig the decoy's own
	// kube-controller-manager uses to reach the inner apiserver (loopback,
	// so insecure-skip-tls-verify rather than shipping the CA here).
	kcmKubeconfigFileName = "kcm-kubeconfig.yaml"

	// seedDirPath is where seed.json is mounted for kubelet-shim. It is a
	// directory rather than a single file so kubelet keeps it up to date;
	// see buildDeployment's seedMount.
	//
	// Deliberately an ordinary-looking app config path, not something
	// under /etc/kubernetes: this mount shows up in /proc/mounts, which an
	// attacker can read in an exec session, and a control-plane-shaped
	// path there on what claims to be an application pod is a tell. A
	// ConfigMap mounted at /etc/config is what a normal workload looks
	// like.
	seedDirPath = "/etc/config"

	// shimSecretDirPath is where the decoy's own keys/tokens are mounted
	// into the kubelet-shim container specifically. kube-apiserver keeps
	// them at the real /etc/kubernetes/pki, which is exactly right for a
	// control-plane container -- but the kubelet-shim container is the one
	// a real `kubectl exec` lands in, and it claims to be an ordinary
	// application pod. A control-plane PKI path showing up in
	// /proc/mounts there is the same tell as the seed mount above, so this
	// container gets a path an app with TLS material would plausibly have.
	shimSecretDirPath = "/etc/ssl/app"

	// shimBinaryPath is where docker/Dockerfile.kubelet-shim installs the
	// kubelet-shim binary. Kept off the filesystem root and named "app"
	// so `ls /` in an exec session doesn't show the component's own name.
	shimBinaryPath = "/usr/local/bin/app"

	// auditLogDir/auditLogPath are where the decoy's own kube-apiserver
	// writes its audit.log (the file audit backend), matching a real
	// kubeadm cluster's /var/log/kubernetes/audit.log.
	auditLogDir  = "/var/log/kubernetes"
	auditLogPath = auditLogDir + "/audit.log"

	// managerNamespace/managerServiceName/auditWebhookPort locate the
	// operator's own audit-webhook receiver (see internal/auditwebhook and
	// cmd/manager/main.go) -- every Decoy's inner apiserver is
	// configured to POST its real audit events there. These match
	// config/manager/namespace.yaml, manager.yaml, and the new
	// config/manager/service.yaml. A DecoyReconciler can override the
	// base URL via ManagerAuditWebhookURL for a non-default manager
	// deployment; see defaultManagerAuditWebhookURL.
	managerNamespace   = "honeypod"
	managerServiceName = "honeypod-controller-manager"
	auditWebhookPort   = 9880

	// joinAnnotation on a real Pod marks it for mirroring into a Decoy's
	// fake API. Value is "<namespace>/<honeypod-name>" (explicit target),
	// or joinAnnotationImplicit ("true", quoted since it's a real
	// annotation string, not a YAML boolean) to join the one Decoy in
	// the Pod's own namespace.
	joinAnnotation = "honeypod.io/join"

	// joinAnnotationImplicit is the joinAnnotation shorthand for "the one
	// Decoy in my own namespace" -- see resolveJoinAnnotation.
	joinAnnotationImplicit = "true"
)

func defaultManagerAuditWebhookURL() string {
	return fmt.Sprintf("http://%s.%s.svc:%d", managerServiceName, managerNamespace, auditWebhookPort)
}

func selectorLabels(name string) map[string]string {
	return map[string]string{
		labelApp:      "honeypod",
		labelInstance: name,
	}
}

func commonLabels(name string) map[string]string {
	l := selectorLabels(name)
	l[labelManagedBy] = managedByValue
	return l
}

func checksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// renderSeedJSON builds the inner control plane's seed from the Decoy's
// own spec.fakePods plus any joined real Pods, mirrored to
// FakePod-equivalent entries. kubelet-shim is the one code path that
// turns this into running objects (real Node/Pod/Secret objects against the
// inner apiserver) -- the operator itself never talks to the inner
// apiserver. Joined pods flow through here just like hand-authored
// fakePods, so they're covered by the same honeypod.io/seed-checksum
// rollout mechanism the caller computes from this function's output.
func renderSeedJSON(kt *honeypodv1alpha1.Decoy, joined []corev1.Pod) ([]byte, error) {
	// Fill in each node's version from the Decoy's own so the seed is
	// explicit: nodes must never report a version newer than the control
	// plane, which is impossible in a real cluster.
	nodes := make([]honeypodv1alpha1.FakeNode, 0, len(kt.Spec.FakeNodes))
	for _, n := range kt.Spec.FakeNodes {
		if n.KubeletVersion == "" {
			n.KubeletVersion = kubernetesVersion(kt)
		}
		nodes = append(nodes, n)
	}

	systemPods, controllers := defaultKubeSystemPods(kt, nodes)
	workloads := make([]seed.Pod, 0, len(kt.Spec.FakePods)+len(joined)+len(systemPods))
	// The author's own fakePods and any joined real pod go first:
	// servedNamespace() (an exec session's reported namespace) picks the
	// *first* entry here, and that must stay whatever the author actually
	// intended, not whichever kube-system pod happens to be synthesized.
	// These stay standalone (no owner) -- a real bare Pod is fine, and a
	// Decoy author who wants a controller can declare one via fakePods.
	for _, p := range kt.Spec.FakePods {
		workloads = append(workloads, seed.Pod{FakePod: p})
	}
	for _, p := range joined {
		workloads = append(workloads, seed.Pod{FakePod: mirrorJoinedPod(p)})
	}
	workloads = append(workloads, systemPods...)

	services, configMaps := renderStandardObjects(kt)
	s := seed.Seed{
		FakeNodes:   nodes,
		FakePods:    workloads,
		FakeSecrets: kt.Spec.FakeSecrets,
		Controllers: controllers,
		CRDs:        renderCRDs(kt),
		Services:    services,
		ConfigMaps:  configMaps,
	}
	return json.Marshal(s)
}

// defaultCRDs is a small, believable set of CustomResourceDefinitions a real
// cluster commonly has installed (cert-manager, an ingress controller, and
// metrics-server's APIService-adjacent CRD-shaped types are avoided; these
// are all plain CRDs). Seeded when seedSystemComponents is on, so `kubectl
// get crds` on a fresh decoy lists real operators' types instead of nothing.
// An author's spec.fakeCRDs are added on top (and win on a name collision).
var defaultCRDs = []seed.CRD{
	{Group: "cert-manager.io", Kind: "Certificate", Plural: "certificates", ShortNames: []string{"cert", "certs"}},
	{Group: "cert-manager.io", Kind: "Issuer", Plural: "issuers"},
	{Group: "cert-manager.io", Kind: "ClusterIssuer", Plural: "clusterissuers", Scope: "Cluster"},
	{Group: "monitoring.coreos.com", Kind: "ServiceMonitor", Plural: "servicemonitors", ShortNames: []string{"smon"}},
	{Group: "monitoring.coreos.com", Kind: "PrometheusRule", Plural: "prometheusrules", ShortNames: []string{"promrule"}},
}

// renderCRDs is the CRD set installed into the decoy: the believable default
// operators' types (when seedSystemComponents is on) plus the author's own
// spec.fakeCRDs. On a name collision (same plural.group) the author's entry
// wins, so a Decoy can override a default's versions/scope.
func renderCRDs(kt *honeypodv1alpha1.Decoy) []seed.CRD {
	byName := map[string]seed.CRD{}
	order := []string{}
	add := func(c seed.CRD) {
		key := c.Plural + "." + c.Group
		if _, seen := byName[key]; !seen {
			order = append(order, key)
		}
		byName[key] = c
	}
	if seedSystemComponents(kt) {
		for _, c := range defaultCRDs {
			add(c)
		}
	}
	for _, fc := range kt.Spec.FakeCRDs {
		add(seed.CRD{
			Group:      fc.Group,
			Kind:       fc.Kind,
			Plural:     fc.Plural,
			Singular:   fc.Singular,
			ShortNames: fc.ShortNames,
			Versions:   fc.Versions,
			Scope:      fc.Scope,
		})
	}
	if len(order) == 0 {
		return nil
	}
	out := make([]seed.CRD, 0, len(order))
	for _, key := range order {
		out = append(out, byName[key])
	}
	return out
}

// renderStandardObjects returns the static kubeadm install artifacts every
// real cluster carries that no running component recreates: the kube-dns
// Service (+ its EndpointSlice, backed by the seeded coredns pod IPs) and the
// kube-system / kube-public ConfigMaps (kubeadm-config, kubelet-config,
// coredns, kube-proxy, cluster-info). Only when seedSystemComponents is on.
func renderStandardObjects(kt *honeypodv1alpha1.Decoy) ([]seed.Service, []seed.ConfigMap) {
	// Same gate as the kube-system pods: without any fake node there is no
	// cluster to dress up, so seed no kube-system fixtures either.
	if !seedSystemComponents(kt) || len(kt.Spec.FakeNodes) == 0 {
		return nil, nil
	}
	version := kubernetesVersion(kt)
	services := []seed.Service{
		{
			Name: "kube-dns", Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "kube-dns", "kubernetes.io/name": "CoreDNS"},
			ClusterIP: "10.96.0.10",
			Selector:  map[string]string{"k8s-app": "kube-dns"},
			Ports: []seed.ServicePort{
				{Name: "dns", Port: 53, TargetPort: 53, Protocol: "UDP"},
				{Name: "dns-tcp", Port: 53, TargetPort: 53, Protocol: "TCP"},
				{Name: "metrics", Port: 9153, TargetPort: 9153, Protocol: "TCP"},
			},
			// Believable coredns backend IPs so the EndpointSlice is
			// non-empty; the seeded coredns pods report IPs in the same range.
			EndpointIPs: []string{"10.244.0.2", "10.244.0.3"},
		},
	}
	configMaps := []seed.ConfigMap{
		{
			Name: "kubeadm-config", Namespace: "kube-system",
			Data: map[string]string{"ClusterConfiguration": "apiServer: {}\napiVersion: kubeadm.k8s.io/v1beta4\ncertificatesDir: /etc/kubernetes/pki\nclusterName: kubernetes\ncontrolPlaneEndpoint: \"\"\nkind: ClusterConfiguration\nkubernetesVersion: " + version + "\nnetworking:\n  dnsDomain: cluster.local\n  serviceSubnet: 10.96.0.0/12\n"},
		},
		{
			Name: "kubelet-config", Namespace: "kube-system",
			Data: map[string]string{"kubelet": "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nclusterDNS:\n- 10.96.0.10\nclusterDomain: cluster.local\ncgroupDriver: systemd\n"},
		},
		{
			Name: "kube-proxy", Namespace: "kube-system",
			Labels: map[string]string{"app": "kube-proxy"},
			Data:   map[string]string{"config.conf": "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\nclusterCIDR: 10.244.0.0/16\nmode: iptables\n"},
		},
		{
			Name: "coredns", Namespace: "kube-system",
			Data: map[string]string{"Corefile": ".:53 {\n    errors\n    health {\n       lameduck 5s\n    }\n    ready\n    kubernetes cluster.local in-addr.arpa ip6.arpa {\n       pods insecure\n       fallthrough in-addr.arpa ip6.arpa\n    }\n    prometheus :9153\n    forward . /etc/resolv.conf\n    cache 30\n    loop\n    reload\n    loadbalance\n}\n"},
		},
		{
			// kube-public/cluster-info: the kubeadm bootstrap artifact every
			// cluster exposes (anonymously, for join discovery).
			Name: "cluster-info", Namespace: "kube-public",
			Data: map[string]string{"kubeconfig": "apiVersion: v1\nkind: Config\nclusters:\n- name: \"\"\n  cluster:\n    server: https://kubernetes.default.svc:6443\n"},
		},
	}
	return services, configMaps
}

// seedSystemComponents reports whether the auto kube-system realism
// (system pods, default CRDs) is on. Nil (unset) defaults to true, matching
// the CRD default on spec.seedSystemComponents.
func seedSystemComponents(kt *honeypodv1alpha1.Decoy) bool {
	return kt.Spec.SeedSystemComponents == nil || *kt.Spec.SeedSystemComponents
}

// defaultKubeSystemPods synthesizes the kube-system pods every real cluster
// has, so `kubectl get pods -A` never shows a suspiciously bare cluster
// with only whatever an author declared in spec.fakePods. etcd,
// kube-apiserver, kube-controller-manager, and kube-scheduler are static
// pods bound to one control-plane node in a real cluster, so they get the
// first fakeNode by name, no replicas (real static pods are singletons).
// kube-proxy is a real per-node DaemonSet, so every fakeNode gets its own.
// coredns is a Deployment, unrelated to any specific node, at its usual
// replica count.
//
// Always on, unconditional -- there is no field to opt out, matching this
// project's "keep the CRD simple" rule elsewhere. A Decoy with no
// fakeNodes at all seeds nothing here either: these pods still need
// somewhere to claim they're scheduled.
func defaultKubeSystemPods(kt *honeypodv1alpha1.Decoy, nodes []honeypodv1alpha1.FakeNode) ([]seed.Pod, []seed.Controller) {
	// Opt-out: an author who wants full control over kube-system sets this
	// false and declares everything via fakePods instead. Nil (the field
	// unset) means the default true, so existing Decoys keep the pods.
	if kt.Spec.SeedSystemComponents != nil && !*kt.Spec.SeedSystemComponents {
		return nil, nil
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	version := kubernetesVersion(kt)
	controlPlaneNode := nodes[0].Name

	var pods []seed.Pod
	var controllers []seed.Controller

	// etcd, kube-apiserver, kube-controller-manager, kube-scheduler are
	// static pods in a real cluster: the kubelet reads them from a manifest
	// file and creates a mirror pod owned by its Node, carrying the
	// kubernetes.io/config.* markers. Reproduce exactly that -- no
	// controller object exists for these.
	for _, c := range []struct{ name, image string }{
		{"etcd", "registry.k8s.io/etcd:3.5.16-0"},
		{"kube-apiserver", "registry.k8s.io/kube-apiserver:" + version},
		{"kube-controller-manager", "registry.k8s.io/kube-controller-manager:" + version},
		{"kube-scheduler", "registry.k8s.io/kube-scheduler:" + version},
	} {
		podName := c.name + "-" + controlPlaneNode
		hash := checksum([]byte(podName))[:32]
		pods = append(pods, seed.Pod{
			FakePod: honeypodv1alpha1.FakePod{
				Name:       podName,
				Namespace:  "kube-system",
				NodeName:   controlPlaneNode,
				Containers: []honeypodv1alpha1.FakeContainer{{Name: c.name, Image: c.image}},
			},
			OwnerRefs: []seed.OwnerRef{{APIVersion: "v1", Kind: "Node", Name: controlPlaneNode, Controller: true}},
			Annotations: map[string]string{
				"kubernetes.io/config.source": "file",
				"kubernetes.io/config.hash":   hash,
				"kubernetes.io/config.mirror": hash,
			},
			// Real static control-plane pods run on the host network (so
			// podIP == the node IP) and declare CPU requests (QoS Burstable,
			// not BestEffort). Both are load-bearing tells.
			HostNetwork: true,
			CPURequest:  "100m",
		})
	}

	// coredns is a Deployment -> ReplicaSet -> Pods. Seed ONLY the Deployment
	// object: the decoy runs the real deployment and replicaset controllers
	// (see kcmDisabledControllers), which build the ReplicaSet and the pods
	// for real, and kubelet-shim marks those pods Running once the real
	// scheduler binds them (adoptScheduledPods). Pre-seeding a hand-made RS +
	// pods here would collide with what those controllers compute (a
	// different pod-template-hash) and churn. `get deploy/rs/pods -n
	// kube-system` all resolve, and an attacker's own Deployment behaves
	// identically -- which is the whole point.
	corednsImage := "registry.k8s.io/coredns/coredns:v1.11.3"
	controllers = append(controllers,
		seed.Controller{APIVersion: "apps/v1", Kind: "Deployment", Name: "coredns", Namespace: "kube-system",
			Labels: map[string]string{"k8s-app": "kube-dns"}, Replicas: 2, Image: corednsImage},
	)

	// kube-proxy is a DaemonSet: one pod per node, all owned by it.
	proxyImage := "registry.k8s.io/kube-proxy:" + version
	controllers = append(controllers, seed.Controller{
		APIVersion: "apps/v1", Kind: "DaemonSet", Name: "kube-proxy", Namespace: "kube-system",
		Labels: map[string]string{"k8s-app": "kube-proxy"}, Replicas: int32(len(nodes)), Image: proxyImage,
	})
	for _, n := range nodes {
		pods = append(pods, seed.Pod{
			FakePod: honeypodv1alpha1.FakePod{
				Name: "kube-proxy-" + n.Name, Namespace: "kube-system", NodeName: n.Name,
				Containers: []honeypodv1alpha1.FakeContainer{{Name: "kube-proxy", Image: proxyImage}},
				Labels:     map[string]string{"k8s-app": "kube-proxy"},
			},
			OwnerRefs: []seed.OwnerRef{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "kube-proxy", Controller: true}},
			// kube-proxy runs host-networked, like a real cluster's.
			HostNetwork: true,
			CPURequest:  "100m",
		})
	}
	return pods, controllers
}

// servedNamespace is the namespace an exec session's
// .../serviceaccount/namespace file reports. It has to be a namespace the
// attacker can actually see inside the decoy (the first fake pod's), not
// the Decoy CR's own outer-cluster namespace: that one is invisible
// from inside, usually named after this project, and would contradict the
// namespace of the pod they think they're in. Falls back to "default"
// when nothing is seeded. Every exec session shares one real container,
// so this can only hold one value; a seed spanning several namespaces
// still reports the first.
func servedNamespace(kt *honeypodv1alpha1.Decoy) string {
	if len(kt.Spec.FakePods) > 0 && kt.Spec.FakePods[0].Namespace != "" {
		return kt.Spec.FakePods[0].Namespace
	}
	if len(kt.Spec.FakeSecrets) > 0 && kt.Spec.FakeSecrets[0].Namespace != "" {
		return kt.Spec.FakeSecrets[0].Namespace
	}
	return "default"
}

// decoyHostname is the pod hostname the inner-control-plane pod claims,
// which is what an exec session's /etc/hostname and kernel hostname report.
// The first fake pod's name is the most believable value (a real pod's
// hostname is its own name); the first fake node is the fallback. Never the
// Decoy's own name, which the default pod hostname would leak. Sanitized
// to a valid DNS-1123 label so the pod always schedules.
func decoyHostname(kt *honeypodv1alpha1.Decoy) string {
	name := "worker"
	if len(kt.Spec.FakePods) > 0 && kt.Spec.FakePods[0].Name != "" {
		name = kt.Spec.FakePods[0].Name
	} else if len(kt.Spec.FakeNodes) > 0 && kt.Spec.FakeNodes[0].Name != "" {
		name = kt.Spec.FakeNodes[0].Name
	}
	return sanitizeDNSLabel(name)
}

// sanitizeDNSLabel coerces s into a valid RFC 1123 DNS label (lowercase
// alphanumeric and '-', not starting or ending with '-', at most 63 chars),
// falling back to "worker" if nothing usable remains.
func sanitizeDNSLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '-' || r == '.' || r == '_':
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		return "worker"
	}
	return out
}

// renderConfigData builds the merged ConfigMap data mounted into the
// inner-control-plane pod: kubelet-shim reads seed.json, kube-apiserver
// reads token-auth.csv/audit-policy.yaml/audit-webhook-kubeconfig.yaml --
// all from the same ConfigMap so the operator only has to create, checksum,
// and roll one object per Decoy.
func renderConfigData(kt *honeypodv1alpha1.Decoy, joined []corev1.Pod, decoyToken, shimToken, kcmToken, managerAuditWebhookURL string) (map[string]string, error) {
	seedJSON, err := renderSeedJSON(kt, joined)
	if err != nil {
		return nil, err
	}
	auditWebhookKubeconfig, err := renderAuditWebhookKubeconfig(kt, managerAuditWebhookURL)
	if err != nil {
		return nil, err
	}
	kcmKubeconfig, err := renderKCMKubeconfig(kcmToken)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		seedFileName:                   string(seedJSON),
		tokenAuthFileName:              string(renderTokenAuthFile(kt, decoyToken, shimToken, kcmToken)),
		auditPolicyFileName:            string(renderAuditPolicy(kt)),
		auditWebhookKubeconfigFileName: string(auditWebhookKubeconfig),
		kcmKubeconfigFileName:          string(kcmKubeconfig),
	}, nil
}

// renderKCMKubeconfig renders the kubeconfig the decoy's own
// kube-controller-manager authenticates with. It talks to the inner
// apiserver over loopback (127.0.0.1, same pod), so insecure-skip-tls-verify
// is used rather than shipping the CA into this ConfigMap -- there is no
// network hop for a MITM to sit on. The token is the kcm identity from the
// decoy Secret (system:kube-controller-manager, see renderTokenAuthFile).
func renderKCMKubeconfig(token string) ([]byte, error) {
	server := fmt.Sprintf("https://127.0.0.1:%d", innerAPIPort)
	kc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []any{
			map[string]any{"name": "decoy", "cluster": map[string]any{
				"server":                   server,
				"insecure-skip-tls-verify": true,
			}},
		},
		"users": []any{
			map[string]any{"name": "kube-controller-manager", "user": map[string]any{"token": token}},
		},
		"contexts": []any{
			map[string]any{"name": "decoy", "context": map[string]any{"cluster": "decoy", "user": "kube-controller-manager"}},
		},
		"current-context": "decoy",
	}
	return yaml.Marshal(kc)
}

// renderTokenAuthFile renders kube-apiserver's --token-auth-file: CSV
// lines of token,username,uid[,"group1,group2"], one per identity this
// inner cluster accepts.
//
// Two identities, deliberately:
//
//   - The decoy token, handed to anyone who finds it (the external
//     kubeconfig, the file a real exec session's `cat .../token` reads).
//     kubernetes-admin/system:masters mimics a real kubeadm cluster's own
//     bootstrap admin, which is what `kubectl auth whoami` (a near-certain
//     first recon command) shows on a real cluster, so it raises no
//     suspicion. system:masters also bypasses RBAC (see buildDeployment's
//     --authorization-mode=RBAC), so it is load-bearing for access, not
//     just cosmetic.
//
//   - A separate token for kubelet-shim's own client, under a
//     system:node/system:nodes identity, exactly what a real kubelet
//     authenticates as. Without this the shim seeded the cluster as
//     kubernetes-admin, indistinguishable from an attacker, so every
//     decoy restart fired a burst of Alerts for the shim's own seeding
//     (confirmed live). A system: username is what internal/notifier's
//     notability heuristic filters on, so this makes the shim's traffic
//     droppable without hiding anything a real attacker does. It never
//     leaves the inner-control-plane pod: only kube-apiserver mounts this
//     file, and the shim's copy is a separate Secret key never written to
//     the ServiceAccount path an attacker reads.
const (
	decoyUsername = "kubernetes-admin"
	decoyUID      = "admin"
	decoyGroups   = "system:masters"

	shimUID    = "kubelet"
	shimGroups = "system:nodes,system:masters"

	// The decoy's own kube-controller-manager. system:masters lets it act
	// without depending on the exact per-controller RBAC bootstrap, and a
	// system: username keeps its heavy housekeeping traffic out of attacker
	// alerts (notability heuristic drops system: identities), exactly like
	// the shim above. It never leaves the pod: only kube-apiserver reads the
	// token-auth file, and the kcm token lives in a separate Secret key
	// never written to the ServiceAccount path an attacker reads.
	kcmUsername = "system:kube-controller-manager"
	kcmUID      = "kube-controller-manager"
	kcmGroups   = "system:masters"
)

// shimUsername is the kubelet-shim client's own identity, shaped like a
// real kubelet's (system:node:<node name>). It uses the first fake node's
// name when there is one so it matches the cluster it is seeding. With no
// fake nodes to borrow from it falls back to a plain, node-shaped name:
// this identity can show up in the decoy's own audit stream, so the
// fallback stays neutral rather than spelling out the tool (an earlier
// "honeypod-node" gave the game away, and it also disagreed with the
// neutral "worker" that decoyHostname falls back to).
func shimUsername(kt *honeypodv1alpha1.Decoy) string {
	node := "worker-1"
	if len(kt.Spec.FakeNodes) > 0 && kt.Spec.FakeNodes[0].Name != "" {
		node = kt.Spec.FakeNodes[0].Name
	}
	return "system:node:" + node
}

func renderTokenAuthFile(kt *honeypodv1alpha1.Decoy, decoyToken, shimToken, kcmToken string) []byte {
	return fmt.Appendf(nil, "%s,%s,%s,%q\n%s,%s,%s,%q\n%s,%s,%s,%q\n",
		decoyToken, decoyUsername, decoyUID, decoyGroups,
		shimToken, shimUsername(kt), shimUID, shimGroups,
		kcmToken, kcmUsername, kcmUID, kcmGroups,
	)
}

// renderAuditPolicy returns a one-rule audit.k8s.io Policy logging every
// request at spec.auditLevel (default RequestResponse, i.e. log everything).
// This inner cluster is fully decoy with zero real data, and the operator
// filters this stream itself for alerts and the activity summary, so the
// default captures the most; a lower level records less.
func renderAuditPolicy(kt *honeypodv1alpha1.Decoy) []byte {
	level := kt.Spec.AuditLevel
	if level == "" {
		level = "RequestResponse"
	}
	return []byte("apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: " + level + "\n")
}

// renderAuditWebhookKubeconfig renders kube-apiserver's
// --audit-webhook-config-file: a kubeconfig-shaped file whose only
// meaningful field is the server URL, which bakes in this Decoy's own
// namespace/name so the operator's single shared audit-webhook receiver
// (internal/auditwebhook) can attribute every event without any other
// correlation step.
func renderAuditWebhookKubeconfig(kt *honeypodv1alpha1.Decoy, managerAuditWebhookURL string) ([]byte, error) {
	if managerAuditWebhookURL == "" {
		managerAuditWebhookURL = defaultManagerAuditWebhookURL()
	}
	server := fmt.Sprintf("%s/audit/%s/%s", managerAuditWebhookURL, kt.Namespace, kt.Name)
	kc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []any{
			map[string]any{"name": "honeypod-audit", "cluster": map[string]any{"server": server}},
		},
		"contexts": []any{
			map[string]any{"name": "honeypod-audit", "context": map[string]any{"cluster": "honeypod-audit"}},
		},
		"current-context": "honeypod-audit",
	}
	return yaml.Marshal(kc)
}

// mirrorJoinedPod synthesizes a FakePod from a real Pod's metadata
// only: name, namespace, containers[].image, nodeName, labels. It never
// copies Secrets, volumes, ServiceAccount, or any other live data -- cosmetic
// realism only, same as a hand-authored fakePods entry.
func mirrorJoinedPod(p corev1.Pod) honeypodv1alpha1.FakePod {
	containers := make([]honeypodv1alpha1.FakeContainer, 0, len(p.Spec.Containers))
	for _, c := range p.Spec.Containers {
		containers = append(containers, honeypodv1alpha1.FakeContainer{Name: c.Name, Image: c.Image})
	}

	var labels map[string]string
	if len(p.Labels) > 0 {
		labels = make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			labels[k] = v
		}
	}

	// NodeName is deliberately not copied. The real pod runs on a real
	// node, whose name means nothing inside the honeypot and would leak
	// the real cluster's node naming. Worse, a pod scheduled on a node
	// missing from `kubectl get nodes` is an obvious tell, and the inner
	// apiserver cannot proxy exec to a node it has no object for, so exec
	// on a joined pod failed. Left empty, kubelet-shim assigns the first
	// fake node, exactly like a fakePods entry with no nodeName.
	return honeypodv1alpha1.FakePod{
		Name:       p.Name,
		Namespace:  p.Namespace,
		Replicas:   1,
		Containers: containers,
		Labels:     labels,
	}
}

// renderKubeconfig builds a ready-to-use kubeconfig for talking directly to
// this Decoy's inner apiserver, authenticated only with the decoy
// bearer token.
func renderKubeconfig(clusterName, server string, caPEM []byte, token string) ([]byte, error) {
	kc := map[string]any{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []any{
			map[string]any{
				"name": clusterName,
				"cluster": map[string]any{
					"server":                     server,
					"certificate-authority-data": base64.StdEncoding.EncodeToString(caPEM),
				},
			},
		},
		"users": []any{
			map[string]any{
				"name": clusterName + "-admin",
				"user": map[string]any{"token": token},
			},
		},
		"contexts": []any{
			map[string]any{
				"name": clusterName,
				"context": map[string]any{
					"cluster": clusterName,
					"user":    clusterName + "-admin",
				},
			},
		},
		"current-context": clusterName,
	}
	return yaml.Marshal(kc)
}

func serviceDNSName(name, namespace string) string {
	return fmt.Sprintf("%s.%s.svc", name, namespace)
}

// defaultKubernetesVersion is used when spec.kubernetesVersion is empty,
// which only happens for objects created before that field existed (the
// CRD defaults it otherwise).
const defaultKubernetesVersion = "v1.35.0"

// kubernetesVersion is the version this decoy claims to be, driving both
// the real kube-apiserver image and the version fake nodes report.
func kubernetesVersion(kt *honeypodv1alpha1.Decoy) string {
	if kt.Spec.KubernetesVersion != "" {
		return kt.Spec.KubernetesVersion
	}
	return defaultKubernetesVersion
}

func kubeAPIServerImage(kt *honeypodv1alpha1.Decoy) string {
	if kt.Spec.KubeAPIServerImage != "" {
		return kt.Spec.KubeAPIServerImage
	}
	return "registry.k8s.io/kube-apiserver:" + kubernetesVersion(kt)
}

func kineImage(kt *honeypodv1alpha1.Decoy) string {
	if kt.Spec.KineImage != "" {
		return kt.Spec.KineImage
	}
	return "rancher/kine:latest"
}

func kubeletShimImage(kt *honeypodv1alpha1.Decoy) string {
	if kt.Spec.KubeletShimImage != "" {
		return kt.Spec.KubeletShimImage
	}
	return "honeypod/kubelet-shim:latest"
}

func servicePort(kt *honeypodv1alpha1.Decoy) int32 {
	if kt.Spec.Port != 0 {
		return kt.Spec.Port
	}
	return 6443
}

// execProfile is the exec-session environment the decoy presents, defaulting
// to "shell" for a Decoy created before the field existed (the CRD
// defaults it otherwise).
func execProfile(kt *honeypodv1alpha1.Decoy) string {
	switch kt.Spec.ExecProfile {
	case "minimal", "distroless":
		return kt.Spec.ExecProfile
	default:
		return "shell"
	}
}

// serviceAccountTokenMountPath is the conventional path kubelet's automatic
// ServiceAccount token injection uses. AutomountServiceAccountToken:false
// only disables *that* automatic mechanism -- it says nothing about a
// manually-declared volume at the same path, which is exactly what
// decoyServiceAccountVolume below is. Mounting a decoy-shaped token/ca.crt/namespace
// here, at the path a real pod would almost always have them, removes a
// fingerprint: a pod with nothing at all under this path is itself a tell
// that it's not a normal workload.
//
// Used two ways: by the (real, running) pods that carry this treatment
// (joined or mutating-webhook-injected pods, via
// PodJoinMutator/decoyServiceAccountVolume in join_webhook.go), and by the
// inner-control-plane pod's own kubelet-shim container, which kubelet-shim
// itself (not this operator) writes the same three files into at startup,
// since that's the one container a real `kubectl exec` actually runs a
// real process in (see internal/kubeletshim's exec.go).
const serviceAccountTokenMountPath = "/var/run/secrets/kubernetes.io/serviceaccount/"

// decoyVolumeName is the projected volume the join webhook adds in place of
// the real ServiceAccount one. Its presence on a Pod is how the reconciler
// tells a pod whose traffic was actually redirected from one that carries
// the annotation but was never passed through admission.
const decoyVolumeName = "kube-api-access-decoy"

// decoyDNSConfig returns the standard in-cluster resolv.conf a real pod in
// the decoy's served namespace would have: the cluster's DNS ClusterIP, the
// three-level search list rooted at that namespace, and ndots:5. Used with
// DNSPolicy: None so none of the real host node's resolv.conf (its search
// domains, its real nameservers) leaks into an exec session's
// /etc/resolv.conf. clusterDNSIP matches the seeded kube-dns Service.
func decoyDNSConfig(kt *honeypodv1alpha1.Decoy) *corev1.PodDNSConfig {
	const clusterDNSIP = "10.96.0.10"
	ns := servedNamespace(kt)
	ndots := "5"
	return &corev1.PodDNSConfig{
		Nameservers: []string{clusterDNSIP},
		Searches: []string{
			ns + ".svc.cluster.local",
			"svc.cluster.local",
			"cluster.local",
		},
		Options: []corev1.PodDNSConfigOption{{Name: "ndots", Value: &ndots}},
	}
}

func decoyServiceAccountVolume(secretName string) corev1.Volume {
	return corev1.Volume{
		Name: decoyVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
							Items: []corev1.KeyToPath{
								{Key: "token", Path: "token"},
								{Key: "ca.crt", Path: "ca.crt"},
							},
						},
					},
					{
						DownwardAPI: &corev1.DownwardAPIProjection{
							Items: []corev1.DownwardAPIVolumeFile{
								{Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}},
							},
						},
					},
				},
			},
		},
	}
}

func buildDeployment(kt *honeypodv1alpha1.Decoy, secretName, configMapName, configChecksum, certChecksum, nodeInternalIP string) *appsv1.Deployment {
	labels := commonLabels(kt.Name)
	replicas := int32(1)
	terminationGracePeriod := int64(5)

	secretMount := corev1.VolumeMount{Name: "decoy-secret", MountPath: "/etc/kubernetes/pki", ReadOnly: true}
	shimSecretMount := corev1.VolumeMount{Name: "decoy-shim-secret", MountPath: shimSecretDirPath, ReadOnly: true}
	configMount := func(file string) corev1.VolumeMount {
		return corev1.VolumeMount{Name: "config", MountPath: "/etc/kubernetes/" + file, SubPath: file, ReadOnly: true}
	}

	// kine's SQLite and the apiserver's audit.log are ephemeral (emptyDir)
	// by default. With spec.persistence set, both move onto one PVC (each
	// under its own subPath), and the Deployment switches to the Recreate
	// strategy so the single-writer RWO claim is never mounted by two pods
	// at once during a rollout.
	persistent := kt.Spec.Persistence != nil
	kineVolMount := corev1.VolumeMount{Name: "kine-data", MountPath: "/var/lib/kine"}
	auditVolMount := corev1.VolumeMount{Name: "audit-logs", MountPath: auditLogDir}
	var storageVolumes []corev1.Volume
	strategy := appsv1.DeploymentStrategy{}
	if persistent {
		kineVolMount = corev1.VolumeMount{Name: "data", MountPath: "/var/lib/kine", SubPath: "kine"}
		auditVolMount = corev1.VolumeMount{Name: "data", MountPath: auditLogDir, SubPath: "audit"}
		storageVolumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: kt.Name + "-data"},
		}}}
		strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
	} else {
		storageVolumes = []corev1.Volume{
			{Name: "kine-data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: "audit-logs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		}
	}

	// seed.json gets its own directory mount, deliberately not a SubPath
	// one like the files above. A SubPath mount is resolved once at
	// container start and never updated when the ConfigMap changes, so the
	// shim's re-read would keep seeing the seed it booted with. A plain
	// directory mount is refreshed by kubelet, which is what lets a pod
	// join or leave without restarting the decoy.
	//
	// It projects only seed.json. The other keys in this ConfigMap include
	// token-auth.csv, and this is the one container `kubectl exec` runs a
	// real shell in, so exposing the whole ConfigMap here would hand an
	// attacker both tokens and their identities.
	seedMount := corev1.VolumeMount{Name: "seed", MountPath: seedDirPath, ReadOnly: true}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: kt.Name, Namespace: kt.Namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Strategy: strategy,
			Selector: &metav1.LabelSelector{MatchLabels: selectorLabels(kt.Name)},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selectorLabels(kt.Name),
					Annotations: map[string]string{
						"honeypod.io/config-checksum": configChecksum,
						// kubelet-shim loads its serving keypair once at
						// startup, so a reissued cert only takes effect on a
						// new pod. Without this the Secret would hold a
						// correct cert while the running pod kept serving the
						// stale one and every exec stayed broken.
						"honeypod.io/cert-checksum": certChecksum,
					},
				},
				Spec: corev1.PodSpec{
					RuntimeClassName: kt.Spec.RuntimeClassName,
					// The kubelet-shim container is the one an exec session
					// runs a real shell in. Without this its /etc/hostname
					// (and the kernel hostname) would be the decoy pod's own
					// name, "<honeypod>-<hash>", literally containing the
					// Decoy's name -- a dead giveaway to `cat
					// /etc/hostname`. Pin it to a believable pod-shaped name
					// from the seed instead. The per-session `hostname`
					// command override (see exec.go) still reports the exact
					// pod an attacker thinks they're in; this only sets the
					// one static value the file can hold.
					Hostname:                      decoyHostname(kt),
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					// The decoy pod runs in the real host cluster, so by
					// default it inherits that node's /etc/resolv.conf -- which
					// an exec session reads and which leaks the real
					// environment (observed: an "incus" search domain and the
					// real cluster's kube-dns). Pin a clean, standard
					// in-cluster resolv.conf instead, exactly the shape a real
					// pod in this decoy's own namespace would have, so `cat
					// /etc/resolv.conf` reveals nothing about the host.
					DNSPolicy: corev1.DNSNone,
					DNSConfig: decoyDNSConfig(kt),
					// kubelet injects a *_SERVICE_HOST/PORT env family for
					// every Service in the pod's namespace at create time (the
					// legacy "service links"). In the operator's own namespace
					// those name real infra (the manager, webhook, audit
					// services) and would surface in an exec session's `env` --
					// a direct leak of the honeypot's control plane. Off, so
					// only the decoy KUBERNETES_* family set above remains.
					EnableServiceLinks: boolPtr(false),
					// Defense-in-depth: even though nothing in this pod's
					// own containers ever needs a real outer-cluster
					// ServiceAccount token, this disables kubelet's
					// *automatic* injection of one entirely.
					AutomountServiceAccountToken: boolPtr(false),
					// No redirect-init init container here: none of
					// kine/kube-apiserver/kubelet-shim ever perform
					// in-cluster API discovery via
					// KUBERNETES_SERVICE_HOST/PORT or
					// rest.InClusterConfig() -- kubelet-shim builds its
					// client explicitly from --apiserver/--ca-file/
					// --token-file flags (cmd/kubelet-shim/main.go), and
					// neither kine nor kube-apiserver ever calls out to
					// "the" Kubernetes API for their own purposes. A
					// redirect here would have redirected traffic that was
					// never going to be sent in the first place, so this
					// pod carries no NET_ADMIN init container at all.
					//
					// One init container, though: it writes the decoy
					// ServiceAccount into the sa-token volume in the exact
					// on-disk shape kubelet's atomic writer produces (a
					// ..data dir and per-file symlinks), running as root so
					// the files are root-owned like a real mount. The main
					// kubelet-shim container then serves exec against it
					// without needing root itself, so `ls -la` on the
					// ServiceAccount path inside an exec session is
					// indistinguishable from a real automount. It only
					// writes files and exits; an attacker can never reach a
					// completed init container.
					InitContainers: []corev1.Container{
						{
							Name:            "sa-setup",
							Image:           kubeletShimImage(kt),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{shimBinaryPath},
							Args: []string{
								"--write-sa-layout",
								"--token-file=/etc/kubernetes/pki/token",
								"--ca-file=/etc/kubernetes/pki/ca.crt",
								"--namespace=" + servedNamespace(kt),
								"--sa-dir=" + strings.TrimSuffix(serviceAccountTokenMountPath, "/"),
							},
							Resources: kt.Spec.Resources,
							VolumeMounts: []corev1.VolumeMount{
								secretMount,
								{Name: "sa-token", MountPath: strings.TrimSuffix(serviceAccountTokenMountPath, "/")},
							},
							SecurityContext: saSetupSecurityContext(),
						},
					},
					Containers: []corev1.Container{
						{
							// kine: SQLite-backed etcd v3 API shim backing
							// this Decoy's inner kube-apiserver, so no
							// real etcd cluster runs per decoy. State lives
							// on an emptyDir -- a pod restart (e.g. from a
							// seed-checksum-triggered rollout) starts this
							// inner cluster completely fresh, matching the
							// old fake-apiserver's from-scratch-on-restart
							// behavior.
							Name:            "kine",
							Image:           kineImage(kt),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								"--endpoint=sqlite:///var/lib/kine/kine.db",
								"--listen-address=" + kineListenAddr,
							},
							Resources:       kt.Spec.Resources,
							VolumeMounts:    []corev1.VolumeMount{kineVolMount},
							SecurityContext: hardenedSecurityContext(),
						},
						{
							// kube-apiserver: real, unmodified. --etcd-servers
							// points at kine above; --authorization-mode=RBAC,
							// same as a real cluster, so `kubectl auth
							// can-i --list`/`auth whoami` match a real
							// cluster's output (the auto-bootstrapped
							// system:discovery/system:basic-user
							// ClusterRoleBindings included), not just a
							// bare two-row wildcard. The isolation boundary
							// for this decoy is network/credential
							// separation from the real cluster, not RBAC,
							// so this is realism, not a security control:
							// the decoy token's system:masters group (see
							// decoyGroups below) bypasses RBAC checks
							// entirely, same full access as before.
							Name:            "kube-apiserver",
							Image:           kubeAPIServerImage(kt),
							ImagePullPolicy: corev1.PullIfNotPresent,
							// The real registry.k8s.io/kube-apiserver image's
							// own ENTRYPOINT is /go-runner (a stdout/stderr
							// logging wrapper), which does not understand
							// kube-apiserver's own flags -- pointing directly
							// at the real binary bypasses it. Our own
							// repackaged image (Dockerfile.kube-apiserver)
							// places the binary at this same path so both
							// variants work identically.
							Command: []string{"/usr/local/bin/kube-apiserver"},
							Args: []string{
								fmt.Sprintf("--etcd-servers=http://%s", kineListenAddr),
								fmt.Sprintf("--secure-port=%d", innerAPIPort),
								// 0.0.0.0, not 127.0.0.1: the Service targets
								// this container's port directly now (no
								// reverse-proxy hop), so it needs to be
								// reachable via the pod's real IP, not just
								// loopback.
								"--bind-address=0.0.0.0",
								"--tls-cert-file=/etc/kubernetes/pki/tls.crt",
								"--tls-private-key-file=/etc/kubernetes/pki/tls.key",
								"--token-auth-file=/etc/kubernetes/" + tokenAuthFileName,
								"--authorization-mode=RBAC",
								"--disable-admission-plugins=ServiceAccount",
								"--service-cluster-ip-range=10.96.0.0/16",
								// Required for kube-apiserver to start at
								// all, unused otherwise -- see
								// certs.GenerateServiceAccountSigningKey's
								// doc comment.
								"--service-account-issuer=https://kubernetes.default.svc.cluster.local",
								"--service-account-key-file=/etc/kubernetes/pki/sa.pub",
								"--service-account-signing-key-file=/etc/kubernetes/pki/sa.key",
								"--kubelet-preferred-address-types=InternalIP",
								// kubelet-shim's own HTTPS serving cert is
								// signed by this same decoy CA (it's the
								// same tls.crt/tls.key the inner
								// kube-apiserver itself serves with), so
								// kube-apiserver's kubelet-client proxy can
								// verify it properly instead of relying on
								// version-dependent default behavior when
								// this flag is left unset.
								"--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt",
								"--audit-policy-file=/etc/kubernetes/" + auditPolicyFileName,
								"--audit-webhook-config-file=/etc/kubernetes/" + auditWebhookKubeconfigFileName,
								"--audit-webhook-mode=blocking",
								// Dual audit backend, exactly like a real
								// kubeadm cluster: besides the webhook to the
								// operator, kube-apiserver also writes its
								// own audit.log to a file on disk. Read with
								// `kubectl exec <decoy> -c kube-apiserver --
								// cat /var/log/kubernetes/audit.log`. The
								// volume is an emptyDir by default (lost on
								// reschedule, like the rest of the decoy);
								// spec.persistence backs it with a PVC.
								"--audit-log-path=" + auditLogPath,
								"--audit-log-maxage=30",
								"--audit-log-maxbackup=10",
								"--audit-log-maxsize=100",
							},
							Resources: kt.Spec.Resources,
							// Named "decoy" -- the Service's targetPort
							// points directly at this container port now;
							// kube-apiserver already terminates real TLS
							// with the decoy cert itself, so there is
							// nothing a reverse-proxy hop in front of it
							// would add.
							Ports: []corev1.ContainerPort{{Name: "decoy", ContainerPort: innerAPIPort}},
							VolumeMounts: []corev1.VolumeMount{
								configMount(tokenAuthFileName),
								configMount(auditPolicyFileName),
								configMount(auditWebhookKubeconfigFileName),
								secretMount,
								auditVolMount,
							},
							SecurityContext: kubeAPIServerSecurityContext(),
						},
						kcmContainer(kt),
						schedulerContainer(kt),
						{
							// kubelet-shim: seeds the inner apiserver from
							// seed.json, serves the kubelet-side
							// exec/attach/logs endpoints, and (see
							// internal/kubeletshim's exec.go) is where a real
							// `kubectl exec`/`attach -it` actually runs a
							// real process -- the one real execution
							// backend a Decoy has, hardened below.
							Name:            "kubelet-shim",
							Image:           kubeletShimImage(kt),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Args: []string{
								fmt.Sprintf("--apiserver=https://127.0.0.1:%d", innerAPIPort),
								"--ca-file=" + shimSecretDirPath + "/ca.crt",
								"--token-file=" + shimSecretDirPath + "/token",
								"--client-token-file=" + shimSecretDirPath + "/shim.token",
								"--seed=" + seedDirPath + "/" + seedFileName,
								"--node-internal-ip=" + nodeInternalIP,
								fmt.Sprintf("--kubelet-port=%d", kubeletPort),
								fmt.Sprintf("--listen=:%d", kubeletPort),
								"--tls-cert-file=" + shimSecretDirPath + "/tls.crt",
								"--tls-key-file=" + shimSecretDirPath + "/tls.key",
								"--namespace=" + servedNamespace(kt),
								"--sa-dir=" + strings.TrimSuffix(serviceAccountTokenMountPath, "/"),
								"--kubernetes-version=" + kubernetesVersion(kt),
								fmt.Sprintf("--kubernetes-service-port=%d", servicePort(kt)),
								"--exec-profile=" + execProfile(kt),
								fmt.Sprintf("--exec-isolation=%t", kt.Spec.ExecIsolation),
							},
							Resources: kt.Spec.Resources,
							// Present the decoy's own apiserver as the in-cluster
							// KUBERNETES_* family on this (the exec-target)
							// container, so `env` / `cat /proc/1/environ` inside
							// a decoy points here, not at the real host cluster's
							// kubernetes Service. The exec sandbox scrubs the
							// child env too (decoyExecEnv); this covers the
							// container's own process env.
							Env:   kubernetesServiceEnv(nodeInternalIP, servicePort(kt), realKubernetesServicePortDefault),
							Ports: []corev1.ContainerPort{{Name: "kubelet", ContainerPort: kubeletPort}},
							VolumeMounts: []corev1.VolumeMount{
								seedMount,
								shimSecretMount,
								// Writable: kubelet-shim writes
								// token/namespace/ca.crt here at startup, so
								// a real `cat` during a real exec session
								// sees this Decoy's own decoy
								// credentials at the standard path, same as
								// decoyServiceAccountVolume does for joined real
								// pods.
								{Name: "sa-token", MountPath: strings.TrimSuffix(serviceAccountTokenMountPath, "/")},
							},
							SecurityContext: execSandboxSecurityContext(kt.Spec.ExecIsolation),
						},
					},
					Volumes: append([]corev1.Volume{
						{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configMapName}}}},
						{Name: "seed", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
							Items:                []corev1.KeyToPath{{Key: seedFileName, Path: seedFileName}},
						}}},
						{Name: "decoy-secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName}}},
						// A shim-scoped projection of the decoy Secret carrying
						// only what kubelet-shim serves with: ca.crt, the two
						// tokens, and the serving keypair. This is the volume
						// the kubelet-shim container mounts, and that container
						// is the one `kubectl exec` runs an attacker shell in,
						// so the CA private key, the ServiceAccount signing
						// key, and the kube-controller-manager token that the
						// full "-decoy" Secret also holds are never reachable
						// from an exec session. The kube-apiserver and sa-setup
						// containers still mount the full Secret above, but
						// neither is reachable by an attacker.
						{Name: "decoy-shim-secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
							SecretName: secretName,
							Items: []corev1.KeyToPath{
								{Key: "ca.crt", Path: "ca.crt"},
								{Key: "token", Path: "token"},
								{Key: "shim.token", Path: "shim.token"},
								{Key: "tls.crt", Path: "tls.crt"},
								{Key: "tls.key", Path: "tls.key"},
							},
						}}},
						// Memory-backed (tmpfs), matching a real projected
						// ServiceAccount mount: a disk-backed emptyDir shows
						// a larger `total`/dir size under `ls -la`, another
						// small tell.
						{Name: "sa-token", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}},
					}, storageVolumes...),
				},
			},
		},
	}
}

func kcmImage(kt *honeypodv1alpha1.Decoy) string {
	return "registry.k8s.io/kube-controller-manager:" + kubernetesVersion(kt)
}

// kcmDisabledControllers are the kube-controller-manager controllers the
// decoy runs with '*' minus this list. They are turned off because they
// would disturb the hand-seeded illusion rather than add to it:
//
//   - the node/eviction/pod-GC controllers would notice the fake nodes have
//     no real kubelet and evict or delete the seeded pods (node-lifecycle,
//     taint/device-taint eviction, pod-garbage-collector, node-ipam/route,
//     cloud-node-lifecycle);
//   - the workload controllers (deployment/replicaset/daemonset/statefulset/
//     replicationcontroller/job/cronjob) would fight the seeded static
//     kube-system pods, whose owning objects the shim creates directly;
//   - the volume/claim controllers have nothing real to act on.
//
// Everything left on is exactly what makes the decoy look alive for real:
// serviceaccount + serviceaccount-token (default SAs and their tokens in
// every namespace), root-ca-certificate-publisher (kube-root-ca.crt
// ConfigMaps), endpoints/endpointslice (Endpoints for Services),
// namespace/garbage-collector/resourcequota, and the CSR + clusterrole-
// aggregation controllers -- all producing genuine objects and Events under
// the system:kube-controller-manager identity (filtered from attacker
// alerts, see renderTokenAuthFile).
// Kept off:
//   - the node/eviction/pod-GC controllers would notice the fake nodes have
//     no real kubelet and evict or delete the seeded pods;
//   - daemonset would fight the seeded static kube-proxy DaemonSet pods, which
//     the shim creates directly (it would compute a different pod hash and
//     churn them);
//   - the volume/claim controllers have nothing real to act on.
//
// Left on (in addition to the SA/token/root-ca/endpoints/namespace/GC/quota/
// CSR set): deployment, replicaset, statefulset, replicationcontroller, job,
// cronjob, horizontal-pod-autoscaler, disruption. So an attacker's own
// Deployment/Job/StatefulSet/etc reconciles for real -- deployment ->
// replicaset -> pods -- the pods are bound by the decoy's real scheduler, and
// kubelet-shim marks them Running (see adoptScheduledPods). The one seeded
// object the deployment/replicaset controllers touch is the coredns
// Deployment, seeded WITHOUT a pre-made ReplicaSet or pods (see
// defaultKubeSystemPods) precisely so the real controllers build them cleanly
// instead of colliding with a hand-made set.
var kcmDisabledControllers = []string{
	"node-lifecycle-controller",
	"pod-garbage-collector-controller",
	"taint-eviction-controller",
	"device-taint-eviction-controller",
	"node-ipam-controller",
	"node-route-controller",
	"cloud-node-lifecycle-controller",
	"daemonset-controller",
	"persistentvolume-attach-detach-controller",
	"persistentvolume-binder-controller",
	"persistentvolume-expander-controller",
	"persistentvolume-protection-controller",
	"persistentvolumeclaim-protection-controller",
	"ephemeral-volume-controller",
	"resourceclaim-controller",
	"ttl-controller",
}

// kcmContainer builds the decoy's own real kube-controller-manager. The
// honeypot's control plane is a real kube-apiserver, so running the real
// controller-manager against it makes the ordinary housekeeping a live
// cluster has -- default ServiceAccounts and their tokens, kube-root-ca.crt
// ConfigMaps, Endpoints, and the lifecycle Events those controllers emit --
// genuinely present instead of absent (an empty `get sa`/`get events`/`get
// endpoints` is an obvious tell). It authenticates over loopback to the
// inner apiserver with its own system: identity (see renderKCMKubeconfig and
// renderTokenAuthFile); the controllers that would disrupt the seeded
// pods/nodes are turned off (see kcmDisabledControllers).
func kcmContainer(kt *honeypodv1alpha1.Decoy) corev1.Container {
	controllers := "*"
	for _, c := range kcmDisabledControllers {
		controllers += ",-" + c
	}
	return corev1.Container{
		Name:            "kube-controller-manager",
		Image:           kcmImage(kt),
		ImagePullPolicy: corev1.PullIfNotPresent,
		// Same reason as the apiserver container: the upstream image's
		// ENTRYPOINT is /go-runner, which doesn't understand the binary's
		// flags. Point straight at the binary; our repackaged image keeps
		// it at this same path.
		Command: []string{"/usr/local/bin/kube-controller-manager"},
		Args: []string{
			"--kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			"--authentication-kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			"--authorization-kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			// Sign legacy ServiceAccount tokens and publish the root CA into
			// each namespace's kube-root-ca.crt, exactly as a real cluster.
			"--service-account-private-key-file=/etc/kubernetes/pki/sa.key",
			"--root-ca-file=/etc/kubernetes/pki/ca.crt",
			// All controllers run under the single kcm identity; no
			// per-controller ServiceAccount RBAC to bootstrap.
			"--use-service-account-credentials=false",
			"--controllers=" + controllers,
			// Leader-elect on, so KCM writes a real kube-controller-manager
			// Lease in kube-system -- a real control plane holds one, and its
			// absence is a tell. Single replica, so it wins immediately.
			"--leader-elect=true",
			// Serve on the standard secure port bound to loopback: the inner
			// apiserver (same pod) probes 127.0.0.1:10257 for the legacy
			// componentstatuses "controller-manager" health check, which
			// reads Unhealthy/"connection refused" when nothing listens.
			"--secure-port=10257",
			"--bind-address=127.0.0.1",
		},
		Resources: kt.Spec.Resources,
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/kubernetes/" + kcmKubeconfigFileName, SubPath: kcmKubeconfigFileName, ReadOnly: true},
			{Name: "decoy-secret", MountPath: "/etc/kubernetes/pki", ReadOnly: true},
		},
		// Same accommodation as the apiserver: the upstream binary can carry
		// a file capability, and stripping the bounding set to nothing makes
		// the kernel refuse to exec it (EPERM). It never serves a privileged
		// port here, so the capability is never used -- only the exec-time
		// check needs satisfying.
		SecurityContext: kubeAPIServerSecurityContext(),
	}
}

func schedulerImage(kt *honeypodv1alpha1.Decoy) string {
	return "registry.k8s.io/kube-scheduler:" + kubernetesVersion(kt)
}

// schedulerContainer builds the decoy's own real kube-scheduler. A real
// cluster has one, and without it an attacker's own Pod (directly, or created
// by the real controllers) is never bound to a node -- it sits Pending
// forever, an obvious tell -- and `componentstatuses`/`get lease kube-scheduler`
// both show it missing. It reuses the kcm kubeconfig (loopback, system
// identity, filtered from alerts) and, like KCM, serves on its standard
// loopback secure port so the apiserver's componentstatuses check passes.
// kubelet-shim then marks the pods it schedules Running (see
// adoptScheduledPods), so the whole create->schedule->run chain looks real.
func schedulerContainer(kt *honeypodv1alpha1.Decoy) corev1.Container {
	return corev1.Container{
		Name:            "kube-scheduler",
		Image:           schedulerImage(kt),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/usr/local/bin/kube-scheduler"},
		Args: []string{
			"--kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			"--authentication-kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			"--authorization-kubeconfig=/etc/kubernetes/" + kcmKubeconfigFileName,
			// Writes a real kube-scheduler Lease in kube-system.
			"--leader-elect=true",
			"--secure-port=10259",
			"--bind-address=127.0.0.1",
		},
		Resources: kt.Spec.Resources,
		VolumeMounts: []corev1.VolumeMount{
			{Name: "config", MountPath: "/etc/kubernetes/" + kcmKubeconfigFileName, SubPath: kcmKubeconfigFileName, ReadOnly: true},
			{Name: "decoy-secret", MountPath: "/etc/kubernetes/pki", ReadOnly: true},
		},
		// Same exec-time file-capability accommodation as the apiserver/KCM.
		SecurityContext: kubeAPIServerSecurityContext(),
	}
}

func hardenedSecurityContext() *corev1.SecurityContext {
	nonRoot := true
	uid := int64(65532)
	noPriv := false
	return &corev1.SecurityContext{
		RunAsNonRoot:             &nonRoot,
		RunAsUser:                &uid,
		AllowPrivilegeEscalation: &noPriv,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// kubeAPIServerSecurityContext is hardenedSecurityContext without
// Capabilities.Drop: ["ALL"]. The real upstream kube-apiserver binary
// carries a Linux file capability (security.capability xattr, for binding
// privileged ports as non-root) baked into the image layer; the kernel
// requires a process's bounding capability set to be able to satisfy a
// binary's file capabilities in order to exec it at all -- stripping the
// bounding set to nothing makes exec fail outright with EPERM ("operation
// not permitted"), regardless of whether the capability is ever actually
// used at runtime (confirmed live on zeno by bisecting Capabilities.Drop
// and AllowPrivilegeEscalation independently -- AllowPrivilegeEscalation:
// false alone is NOT the problem and stays on here; only the drop-all was).
// This container never listens on a privileged port here
// (--secure-port=8443), so the capability itself is never exercised; only
// the exec-time kernel check needs accommodating.
func kubeAPIServerSecurityContext() *corev1.SecurityContext {
	nonRoot := true
	uid := int64(65532)
	noPriv := false
	return &corev1.SecurityContext{
		RunAsNonRoot:             &nonRoot,
		RunAsUser:                &uid,
		AllowPrivilegeEscalation: &noPriv,
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// execSandboxSecurityContext is hardenedSecurityContext without a pinned
// RunAsUser: a real exec session (see exec.go) runs `whoami`/`id` for
// real, and a hardcoded UID with no matching /etc/passwd entry answers
// "unknown uid" instead of a real username. Leaving RunAsUser unset lets
// the image's own nonroot user (Dockerfile.kubelet-shim) take effect
// instead, which does have a real passwd entry. RunAsNonRoot: true still
// guarantees it can never be uid 0. spec.runtimeClassName adds a further,
// optional layer (e.g. gVisor) on top of this if the cluster has one.
func execSandboxSecurityContext(execIsolation bool) *corev1.SecurityContext {
	nonRoot := true
	noPriv := false
	if execIsolation {
		// spec.execIsolation runs each exec session in its own PID/mount/UTS
		// namespace; creating those namespaces and mounting a fresh /proc
		// needs CAP_SYS_ADMIN, and the default seccomp profile blocks the
		// unshare/mount syscalls, so it must be relaxed too. This is the
		// deliberate containment trade-off documented on the field -- pair it
		// with spec.runtimeClassName (gVisor) so this added privilege is
		// bounded by a real sandbox rather than the host kernel. Still
		// non-root, still no privilege escalation.
		// Runs as root so the added CAP_SYS_ADMIN is EFFECTIVE (a non-root
		// process gets added caps only in its permitted set, not effective, so
		// unshare/mount would be denied). The exec session itself is NOT root:
		// the shim's --exec-init sets the namespaces up as root, then drops to
		// the image's app uid before exec'ing the attacker's command (see
		// RunExecInit), so `id`/`whoami` still read as a normal user.
		allowPriv := true
		root := int64(0)
		isFalse := false
		return &corev1.SecurityContext{
			RunAsNonRoot:             &isFalse,
			RunAsUser:                &root,
			AllowPrivilegeEscalation: &allowPriv,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"SYS_ADMIN"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
		}
	}
	return &corev1.SecurityContext{
		RunAsNonRoot:             &nonRoot,
		AllowPrivilegeEscalation: &noPriv,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// saSetupSecurityContext runs the sa-setup init container as root, so the
// ServiceAccount files it writes are root-owned like a real automount. This
// is the only root in the pod, and it is tightly scoped: it writes files
// into an emptyDir and exits before the pod is running, so it never runs
// attacker-reachable code. All capabilities are still dropped and privilege
// escalation is off -- it needs none of them to write files as uid 0.
func saSetupSecurityContext() *corev1.SecurityContext {
	root := int64(0)
	noPriv := false
	return &corev1.SecurityContext{
		RunAsUser:                &root,
		AllowPrivilegeEscalation: &noPriv,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func boolPtr(b bool) *bool { return &b }

// buildService fronts the inner-control-plane pod with two ports: "decoy"
// (kube-apiserver's own secure port directly, spec.port, for external
// decoy clients) and "kubelet" (kubelet-shim's own port, for the real
// kube-apiserver's kubelet-client proxy). Its ClusterIP is what every
// seeded fake Node reports as its own
// InternalIP -- stable across pod restarts, unlike the pod's own IP; see
// kubeletshim.Config.NodeInternalIP's doc comment.
func buildService(kt *honeypodv1alpha1.Decoy) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: kt.Name, Namespace: kt.Namespace, Labels: commonLabels(kt.Name)},
		Spec: corev1.ServiceSpec{
			Selector: selectorLabels(kt.Name),
			Ports: []corev1.ServicePort{
				{Name: "decoy", Port: servicePort(kt), TargetPort: intstr.FromString("decoy")},
				{Name: "kubelet", Port: kubeletPort, TargetPort: intstr.FromString("kubelet")},
			},
		},
	}
}

// buildNetworkPolicy denies all egress from the inner-control-plane pod
// except DNS and the operator's own audit-webhook receiver. Neither
// kubelet-shim nor kube-apiserver has any configured route to the real
// cluster's own API, so this is defense-in-depth: even a compromised
// container in this pod cannot reach the real cluster's control plane over
// the network, beyond delivering audit events to the operator that
// deployed it. There is deliberately no additional allow rule for the real
// cluster's own apiserver address here: an earlier version of this policy
// carried one, justified only by "the redirect-init container's iptables
// DNAT needs to get a chance to run before Cilium's pre-NAT egress
// enforcement drops the packet" -- now that redirect-init has been removed
// entirely (see buildDeployment's doc comment: none of this pod's
// containers ever actually attempt that connection), that justification is
// gone, and keeping the allow rule around would have been a real, if
// small, loosening of isolation with no remaining purpose.
func buildNetworkPolicy(kt *honeypodv1alpha1.Decoy) *networkingv1.NetworkPolicy {
	udp := corev1.ProtocolUDP
	tcp := corev1.ProtocolTCP
	dnsPort := intstr.FromInt(53)
	auditPort := intstr.FromInt(auditWebhookPort)
	egress := []networkingv1.NetworkPolicyEgressRule{
		{
			// Deliberately not scoped to a destination. Port 53 is allowed
			// outward to any address, which does leave a DNS-shaped channel
			// out of the decoy -- that is an accepted trade-off here, not an
			// oversight. Scoping it to the DNS service's own namespace
			// breaks the clusters that do not run their resolver there:
			// NodeLocal DNSCache answers on a link-local address on the node
			// itself, and several distributions place CoreDNS outside
			// kube-system. Letting an attacker's lookups out also has its own
			// value to a honeypot, since what they try to resolve is itself
			// intelligence, and every query is still audited.
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &udp, Port: &dnsPort},
				{Protocol: &tcp, Port: &dnsPort},
			},
		},
		{
			To: []networkingv1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": managerNamespace}}},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &tcp, Port: &auditPort},
			},
		},
	}
	return &networkingv1.NetworkPolicy{
		// Suffixed so it does not share the bare decoy name with the
		// Deployment and Service (which keep <name>: the Service name is the
		// decoy's DNS endpoint, and Deployment-plus-Service sharing a name is
		// conventional). Nothing references this NetworkPolicy by name.
		ObjectMeta: metav1.ObjectMeta{Name: kt.Name + "-egress", Namespace: kt.Namespace, Labels: commonLabels(kt.Name)},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: selectorLabels(kt.Name)},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      egress,
		},
	}
}

// mirroredSecretLabel{KTNamespace,KTName,Role} identify which Decoy
// a cross-namespace mirrored credentials Secret (see
// reconcileMirroredSecrets in honeypod_controller.go) belongs to. A
// Kubernetes Secret volume can only reference a Secret in the same
// namespace as the pod mounting it, so the primary "<name>-decoy" Secret
// can't be mounted directly by PodJoinMutator onto a pod joined from a
// different namespace (see config/samples/honeypod_joined_pod.yaml,
// where the joined pod and its Decoy deliberately live in different
// namespaces, on purpose, to exercise exactly this). OwnerReferences can't
// be used to garbage-collect these mirrors: the OwnerReference type has no
// namespace field, and Kubernetes's garbage collector only ever acts on an
// owner reference within the dependent's own namespace -- a cross-namespace
// one is accepted by the API but silently never collected. These labels are
// what reconcileMirroredSecrets uses instead, to find and delete a
// stale mirror once a namespace no longer has any joined pod for this
// Decoy.
const (
	mirroredSecretLabelDecoyNamespace = "honeypod.io/honeypod-namespace"
	mirroredSecretLabelDecoyName      = "honeypod.io/honeypod-name"
	mirroredSecretLabelRole           = "honeypod.io/role"
	mirroredSecretRoleValue           = "joined-pod-credentials"
)

// decoySecretName is the in-namespace Secret that holds the decoy's own
// credentials (token, CA, TLS keypair, signing key). The reconciler creates it
// under this name and PodJoinMutator references it for a same-namespace join,
// so both derive the name here rather than each concatenating "-decoy"
// independently, which would drift on a rename. Cross-namespace joins use
// mirroredSecretName instead.
func decoySecretName(ktName string) string {
	return ktName + "-decoy"
}

// mirroredSecretName is deterministic from the Decoy's own name
// alone (not the namespace it's mirrored into) -- each mirror lives in a
// different namespace, so there's no collision, and PodJoinMutator can
// compute the name it needs to reference without doing a lookup first.
func mirroredSecretName(ktName string) string {
	return ktName + "-decoy-creds"
}

// buildMirroredSecret renders the cross-namespace credentials mirror:
// deliberately just token + ca.crt, never the full "-decoy" Secret, which
// also carries the service-account signing keypair and TLS private key --
// neither of which a webhook-injected decoyServiceAccountVolume needs, and both of
// which would be needlessly duplicated (and needlessly exposed) in every
// namespace that happens to join this Decoy.
func buildMirroredSecret(kt *honeypodv1alpha1.Decoy, namespace string, token, caCert []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mirroredSecretName(kt.Name),
			Namespace: namespace,
			Labels: map[string]string{
				mirroredSecretLabelDecoyNamespace: kt.Namespace,
				mirroredSecretLabelDecoyName:      kt.Name,
				mirroredSecretLabelRole:           mirroredSecretRoleValue,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"token":  token,
			"ca.crt": caCert,
		},
	}
}
