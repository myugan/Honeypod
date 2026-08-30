// Package kubeletshim seeds a Decoy's inner kube-apiserver with real
// Node/Pod/Secret objects from spec.fakeNodes/fakePods/fakeSecrets, keeps
// those nodes reporting Ready, and serves the kubelet endpoint the inner
// apiserver proxies logs/exec/attach to. Its client-go client points at
// the inner apiserver, which is a decoy control plane, never a route to a
// real cluster.
package kubeletshim

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/seed"
)

// Config configures one kubelet-shim instance: which inner apiserver to
// seed/watch, what to seed it with, and the stable network identity
// (Service ClusterIP + kubelet port) fake nodes should advertise.
type Config struct {
	// RestConfig points at the inner apiserver -- our own decoy control
	// plane. A real client-go client against it is fine; it is not a route
	// to any real Kubernetes API.
	RestConfig *rest.Config

	Seed *seed.Seed

	// SeedPath, if set, is re-read on every heartbeat so a seed change
	// reaches the decoy without restarting it. The operator mounts
	// seed.json from a ConfigMap and updates that ConfigMap when a pod
	// joins or leaves, and kubelet propagates the new content into the
	// volume within about a minute. Empty means seed once from Seed and
	// never look again, which is what tests do.
	SeedPath string

	// NodeInternalIP is the Service ClusterIP fronting this shim's
	// kubelet-endpoint port. Every seeded Node reports it as its
	// InternalIP, overriding spec.fakeNodes[].internalIP, because the
	// inner apiserver dials it for every logs/exec/attach call and it
	// must survive this pod restarting. A pod IP would not.
	NodeInternalIP string

	// KubeletPort is the port kubelet-shim's own HTTPS server (see
	// kubeletserver.go) listens on, advertised via each seeded Node's
	// status.daemonEndpoints.kubeletEndpoint.
	KubeletPort int32

	// KubernetesServicePort is the decoy apiserver's own Service port (spec.
	// Port). Together with NodeInternalIP (the decoy Service's ClusterIP) it
	// is the KUBERNETES_SERVICE_HOST/PORT an exec session's environment
	// reports, so `env` inside a decoy points at this decoy -- not the real
	// host cluster (whose kubernetes Service the pod would otherwise leak).
	KubernetesServicePort int32

	// ExecProfile selects the environment an exec session presents: "shell"
	// (full /bin/sh, the default), "minimal" (busybox), or "distroless" (no
	// shell -- exec fails like a real distroless image). See spec.execProfile.
	ExecProfile string

	// ExecIsolation runs each exec session in its own PID/mount/UTS namespace
	// (see spec.execIsolation), so `ps` shows only that session and each pod
	// reports its own hostname. Requires the container to hold CAP_SYS_ADMIN,
	// which the operator grants only when this is set.
	ExecIsolation bool

	// ServiceAccountToken is the decoy token written to
	// ServiceAccountDir/token, so a `cat` during an exec session reads
	// back the credential an attacker already holds. This is not the
	// token this process authenticates with: see RestConfig.BearerToken,
	// which carries a separate identity so seeding traffic stays
	// distinguishable from an attacker's.
	ServiceAccountToken string

	// ServiceAccountDir, if set, is where New writes token/namespace/ca.crt
	// in the standard ServiceAccount volume shape, so an exec session
	// finds them where any in-cluster client looks. In production this is
	// /var/run/secrets/kubernetes.io/serviceaccount, backed by an emptyDir
	// (see internal/controller/render.go). Tests leave it empty.
	ServiceAccountDir string

	// Namespace is written to ServiceAccountDir/namespace. It must be a
	// namespace visible inside the decoy, not the Decoy's own
	// outer-cluster one.
	Namespace string

	// CABundlePath, if set alongside ServiceAccountDir, is copied to
	// ServiceAccountDir/ca.crt -- the same CA the inner apiserver's own
	// serving cert is issued from.
	CABundlePath string

	// RecordExecSessions logs each exec/attach session's transcript to this
	// process's own stdout, so `kubectl logs <decoy-pod> -c kubelet-shim`
	// shows what an attacker did inside an interactive shell (the initial
	// command is already audited; the keystrokes inside are not). On by
	// default at the command layer.
	RecordExecSessions bool
}

// Shim is the seeding and heartbeat loop plus (via kubeletserver.go)
// the kubelet-endpoint HTTPS server for one Decoy's inner cluster.
type Shim struct {
	client kubernetes.Interface
	// crdClient installs the seed's CustomResourceDefinitions into the inner
	// apiserver. Separate from client because CRDs live in the
	// apiextensions.k8s.io group, which the typed kubernetes.Interface does
	// not cover. Nil is tolerated (createCRDs becomes a no-op), which keeps
	// tests that build a Shim without a real rest.Config working.
	crdClient apiextensionsclientset.Interface
	cfg       Config

	// logLinesMu guards logLines: a FakePod's configured LogLines,
	// keyed by "namespace/name" -- kept here rather than as an annotation
	// on the served Pod object, which anyone with the decoy token can read
	// back verbatim (a literal "honeypod.io/..." key on every fabricated
	// pod would be an immediate tell).
	logLinesMu sync.RWMutex
	logLines   map[string][]string

	// seedMu guards cfg.Seed, which reloadSeed swaps out from under
	// Seed's readers on every heartbeat.
	seedMu sync.RWMutex

	// installedCRDs remembers which CRDs this process has already installed,
	// so the per-heartbeat re-seed skips the apiserver round-trip for a CRD
	// it has already created instead of Get-ing all of them every tick. A
	// CRD is create-once and never mutated, so a cached "installed" is
	// safe. Populated only by createCRDs, which runs in the sequential Seed
	// pass, so it needs no lock.
	installedCRDs map[string]bool

	// objectUIDs maps "Kind/name" to the UID the apiserver actually
	// assigned a seeded Node or controller, so a pod's ownerReference
	// carries the same UID its owner really has (a real ownerRef does).
	// Rebuilt each Seed pass, which runs sequentially.
	objectUIDs map[string]types.UID

	// seededPrev/seededCur track which objects THIS shim created, so a Seed
	// pass can delete the ones dropped from the seed (an author removing a
	// fakePod, a joined pod leaving) instead of leaving them stranded in the
	// decoy. Keyed "Kind|namespace|name" -> a closure that deletes that
	// object. Tracking is in memory rather than via a marker label/annotation
	// on purpose: a "honeypod.io/..." key on every fabricated object would be
	// an immediate tell under `kubectl get -o yaml`. Only objects the shim
	// itself creates are recorded, so an attacker's own (or a real
	// controller's) objects are never pruned. seededPrev is last pass's set,
	// seededCur the one being built; both are touched only in the sequential
	// Seed pass, so no lock. (A shim restart forgets the set -- acceptable,
	// since without persistence a restart resets the whole inner cluster
	// anyway.)
	seededPrev map[string]func(context.Context) error
	seededCur  map[string]func(context.Context) error
}

// markSeeded records that this Seed pass created (or still owns) the object at
// key, with del the closure that would delete it. Used by prune to remove
// objects dropped from the seed since the previous pass.
func (sh *Shim) markSeeded(key string, del func(context.Context) error) {
	if sh.seededCur != nil {
		sh.seededCur[key] = del
	}
}

// pruneSeeded deletes every object this shim created in a previous pass that
// the current pass did not re-create -- i.e. entries removed from the seed.
// Best effort: a delete that fails (already gone, transient) is logged and
// skipped, to be retried next pass.
func (sh *Shim) pruneSeeded(ctx context.Context) {
	next := sh.seededCur
	for key, del := range sh.seededPrev {
		if _, stillDesired := next[key]; stillDesired {
			continue
		}
		if err := del(ctx); err != nil && !apierrors.IsNotFound(err) {
			// Keep the entry so the next pass retries it. Dropping it here
			// would forget the object forever, leaving it stranded in the
			// decoy after a single transient failure.
			log.Printf("kubelet-shim: pruning stale seeded object %s: %v", key, err)
			next[key] = del
		}
	}
	sh.seededPrev = next
}

// currentSeed returns the seed to apply right now.
func (sh *Shim) currentSeed() *seed.Seed {
	sh.seedMu.RLock()
	defer sh.seedMu.RUnlock()
	return sh.cfg.Seed
}

// reloadSeed re-reads SeedPath and swaps it in when it parses. A seed file
// that is missing or briefly unreadable (kubelet swaps the ConfigMap volume
// atomically, but the file can still be replaced under us) is not fatal:
// keep serving the seed already in memory and try again next tick.
func (sh *Shim) reloadSeed() {
	if sh.cfg.SeedPath == "" {
		return
	}
	next, err := seed.Load(sh.cfg.SeedPath)
	if err != nil {
		log.Printf("kubelet-shim: re-reading seed, keeping the previous one: %v", err)
		return
	}
	sh.seedMu.Lock()
	sh.cfg.Seed = next
	sh.seedMu.Unlock()
}

func New(cfg Config) (*Shim, error) {
	client, err := kubernetes.NewForConfig(cfg.RestConfig)
	if err != nil {
		return nil, fmt.Errorf("building inner apiserver client: %w", err)
	}
	crdClient, err := apiextensionsclientset.NewForConfig(cfg.RestConfig)
	if err != nil {
		return nil, fmt.Errorf("building inner apiserver CRD client: %w", err)
	}
	if cfg.ServiceAccountDir != "" {
		if err := writeServiceAccountFiles(cfg); err != nil {
			return nil, fmt.Errorf("writing serviceaccount files: %w", err)
		}
	}
	return &Shim{client: client, crdClient: crdClient, cfg: cfg, logLines: map[string][]string{}, installedCRDs: map[string]bool{}, seededPrev: map[string]func(context.Context) error{}}, nil
}

// writeServiceAccountFiles populates cfg.ServiceAccountDir so a real exec
// session's `cat` (and `ls -la`) on the standard path sees exactly what a
// real automounted ServiceAccount looks like -- not just the right file
// contents, but the same on-disk shape kubelet's atomic writer produces:
//
//	serviceaccount/
//	  ..2026_..._<n>/        the real data dir (0755)
//	    token, ca.crt, namespace   (0644)
//	  ..data -> ..2026_..._<n>     symlink
//	  token -> ..data/token        symlink
//	  ca.crt -> ..data/ca.crt      symlink
//	  namespace -> ..data/namespace
//
// with the mount dir itself at 1777 (sticky), matching a real projected
// volume. An attacker who `ls -la`s the path therefore sees the timestamped
// data dir and the symlink chain, not plain files, which a plainly-written
// set of files would give away.
//
// If the layout already exists (a root init container populated it, see
// render.go, so the files can be root-owned like a real mount instead of
// this non-root process's uid), this is a no-op.
func writeServiceAccountFiles(cfg Config) error {
	dir := cfg.ServiceAccountDir

	// Already populated (e.g. by the root init container): leave it.
	if _, err := os.Lstat(filepath.Join(dir, "..data")); err == nil {
		return nil
	}

	ca := []byte{}
	if cfg.CABundlePath != "" {
		b, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return err
		}
		ca = b
	}

	files := map[string][]byte{
		"token":     []byte(cfg.ServiceAccountToken),
		"namespace": []byte(cfg.Namespace),
		"ca.crt":    ca,
	}
	return WriteServiceAccountLayout(dir, files)
}

// WriteServiceAccountLayout writes the atomic-writer projected-volume layout
// (a timestamped data dir, a ..data symlink, and a leaf symlink per file)
// into dir, exactly as kubelet does for a real ServiceAccount mount. Shared
// by the shim's own startup write and the root init container that writes it
// as root (cmd/kubelet-shim --write-sa-layout).
func WriteServiceAccountLayout(dir string, files map[string][]byte) error {
	// Matches kubelet's atomic writer exactly: the data dir is named
	// "..<timestamp>" (no other prefix), and ..data symlinks to it.
	dataDir := ".." + time.Now().UTC().Format("2006_01_02_15_04_05.000000000")
	full := filepath.Join(dir, dataDir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(full, name), content, 0o644); err != nil {
			return err
		}
	}
	// ..data -> <dataDir>, replacing atomically via rename of a temp link.
	tmp := filepath.Join(dir, "..data.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(dataDir, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		return err
	}
	for name := range files {
		leaf := filepath.Join(dir, name)
		_ = os.Remove(leaf)
		if err := os.Symlink(filepath.Join("..data", name), leaf); err != nil {
			return err
		}
	}
	// Real projected SA mount dirs are 1777 (rwxrwxrwt, sticky). Go's
	// FileMode carries the sticky bit as os.ModeSticky, not the octal
	// 0o1000, so it must be OR'd in explicitly.
	return os.Chmod(dir, 0o777|os.ModeSticky)
}

func (sh *Shim) setLogLines(namespace, name string, lines []string) {
	sh.logLinesMu.Lock()
	defer sh.logLinesMu.Unlock()
	sh.logLines[namespace+"/"+name] = lines
}

func (sh *Shim) getLogLines(namespace, name string) ([]string, bool) {
	sh.logLinesMu.RLock()
	defer sh.logLinesMu.RUnlock()
	lines, ok := sh.logLines[namespace+"/"+name]
	return lines, ok
}

// APIServerReachable reports whether the inner apiserver is currently
// responding, so callers (see cmd/kubelet-shim) can wait out the startup
// race between containers in the same pod before seeding.
func (sh *Shim) APIServerReachable(ctx context.Context) bool {
	_, err := sh.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}

// Seed upserts every Namespace/Node/Pod/Secret named by cfg.Seed into the
// inner apiserver. It is safe to call more than once (e.g. from
// RunHeartbeat's periodic re-seed) -- existing objects are updated in
// place, never duplicated.
func (sh *Shim) Seed(ctx context.Context) error {
	// One snapshot for the whole pass, so a reload midway can't seed half
	// of one seed and half of the next.
	current := sh.currentSeed()

	// Fresh per pass: records the UID the apiserver assigns each Node and
	// controller, so pods can reference their owners' real UIDs.
	sh.objectUIDs = map[string]types.UID{}

	// Before seeding anything: finish off any namespace the attacker
	// deleted. ensureNamespace below treats a Terminating namespace as
	// present and skips it, so without this a deleted namespace would also
	// never come back.
	if err := sh.finalizeTerminatingNamespaces(ctx); err != nil {
		return fmt.Errorf("finalizing terminating namespaces: %w", err)
	}
	// Fresh per pass: what this pass creates, so pruneSeeded at the end can
	// delete objects dropped from the seed since last pass.
	sh.seededCur = map[string]func(context.Context) error{}

	defaultNode := ""
	for i, n := range current.FakeNodes {
		if i == 0 {
			defaultNode = n.Name
		}
		if err := sh.upsertNode(ctx, n, i == 0); err != nil {
			return fmt.Errorf("seeding node %q: %w", n.Name, err)
		}
		name := n.Name
		sh.markSeeded("Node|"+name, func(ctx context.Context) error {
			return sh.client.CoreV1().Nodes().Delete(ctx, name, metav1.DeleteOptions{})
		})
		sh.markSeeded("Lease|kube-node-lease|"+name, func(ctx context.Context) error {
			return sh.client.CoordinationV1().Leases("kube-node-lease").Delete(ctx, name, metav1.DeleteOptions{})
		})
	}

	// A real kubelet renews a Lease in kube-node-lease every few seconds;
	// its absence (an empty `kubectl get leases -n kube-node-lease`) is a
	// tell, and it is also what the real kube-controller-manager the decoy
	// now runs uses to judge node health. Renew one per node each heartbeat,
	// exactly as a real kubelet does.
	if err := sh.ensureNodeLeases(ctx, current.FakeNodes); err != nil {
		return fmt.Errorf("seeding node leases: %w", err)
	}

	if err := sh.createCRDs(ctx, current.CRDs); err != nil {
		return fmt.Errorf("seeding CRDs: %w", err)
	}
	for _, c := range current.CRDs {
		name := c.Plural + "." + c.Group
		sh.markSeeded("CRD|"+name, func(ctx context.Context) error {
			if sh.crdClient == nil {
				return nil
			}
			return sh.crdClient.ApiextensionsV1().CustomResourceDefinitions().Delete(ctx, name, metav1.DeleteOptions{})
		})
	}

	if err := sh.createControllers(ctx, current.Controllers); err != nil {
		return fmt.Errorf("seeding controllers: %w", err)
	}
	for _, c := range current.Controllers {
		ns, name, kind := c.Namespace, c.Name, c.Kind
		sh.markSeeded(kind+"|"+ns+"|"+name, func(ctx context.Context) error {
			switch kind {
			case "Deployment":
				return sh.client.AppsV1().Deployments(ns).Delete(ctx, name, metav1.DeleteOptions{})
			case "ReplicaSet":
				return sh.client.AppsV1().ReplicaSets(ns).Delete(ctx, name, metav1.DeleteOptions{})
			case "DaemonSet":
				return sh.client.AppsV1().DaemonSets(ns).Delete(ctx, name, metav1.DeleteOptions{})
			}
			return nil
		})
	}

	nsSeen := map[string]bool{}
	for _, w := range current.FakePods {
		if !nsSeen[w.Namespace] {
			if err := sh.ensureNamespace(ctx, w.Namespace); err != nil {
				return err
			}
			nsSeen[w.Namespace] = true
		}
		nodeName := w.NodeName
		if nodeName == "" {
			nodeName = defaultNode
		}
		if err := sh.upsertWorkload(ctx, w, nodeName); err != nil {
			return fmt.Errorf("seeding workload %q: %w", w.Name, err)
		}
	}

	for _, s := range current.FakeSecrets {
		if !nsSeen[s.Namespace] {
			if err := sh.ensureNamespace(ctx, s.Namespace); err != nil {
				return err
			}
			nsSeen[s.Namespace] = true
		}
		if err := sh.upsertSecret(ctx, s); err != nil {
			return fmt.Errorf("seeding secret %q: %w", s.Name, err)
		}
		ns, name := s.Namespace, s.Name
		sh.markSeeded("Secret|"+ns+"|"+name, func(ctx context.Context) error {
			return sh.client.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{})
		})
	}

	// Static kubeadm install artifacts (kube-system/kube-public ConfigMaps)
	// and the standard Services (kube-dns) a real cluster carries. No running
	// component recreates these, so the shim seeds them.
	if err := sh.createConfigMaps(ctx, current.ConfigMaps); err != nil {
		return fmt.Errorf("seeding configmaps: %w", err)
	}
	for _, c := range current.ConfigMaps {
		ns, name := c.Namespace, c.Name
		sh.markSeeded("ConfigMap|"+ns+"|"+name, func(ctx context.Context) error {
			return sh.client.CoreV1().ConfigMaps(ns).Delete(ctx, name, metav1.DeleteOptions{})
		})
	}
	if err := sh.createServices(ctx, current.Services); err != nil {
		return fmt.Errorf("seeding services: %w", err)
	}
	for _, s := range current.Services {
		ns, name := s.Namespace, s.Name
		sh.markSeeded("Service|"+ns+"|"+name, func(ctx context.Context) error {
			_ = sh.client.DiscoveryV1().EndpointSlices(ns).Delete(ctx, name, metav1.DeleteOptions{})
			return sh.client.CoreV1().Services(ns).Delete(ctx, name, metav1.DeleteOptions{})
		})
	}

	// The decoy runs a real scheduler, so an attacker's own pods (directly or
	// via the real controllers) get bound to a fake node. kubelet-shim is the
	// decoy's kubelet, so it marks those bound pods Running -- otherwise they
	// sit Pending forever, a dead giveaway. Runs last, after the seeded pods
	// (which are already Running and skipped).
	nodeNames := make(map[string]bool, len(current.FakeNodes))
	for _, n := range current.FakeNodes {
		nodeNames[n.Name] = true
	}
	if err := sh.adoptScheduledPods(ctx, nodeNames); err != nil {
		log.Printf("kubelet-shim: adopting scheduled pods: %v", err)
	}

	// Delete objects this shim created in a previous pass that are no longer
	// in the seed (a removed fakePod/Secret, a pod that has un-joined), so the
	// decoy actually converges to the desired state instead of accumulating
	// stranded objects. Attacker- and controller-created objects are never
	// tracked, so never touched. Runs after adoption so a just-adopted pod is
	// never mistaken for stale.
	sh.pruneSeeded(ctx)

	log.Printf("kubelet-shim: seeded %d node(s), %d workload(s), %d secret(s)",
		len(current.FakeNodes), len(current.FakePods), len(current.FakeSecrets))
	return nil
}

// createCRDs installs each seed CRD as a real CustomResourceDefinition with
// a permissive (unknown-fields-preserved) served schema. A decoy only needs
// the type to show up in discovery and `kubectl get crds`, and custom
// resources of it to be creatable/listable -- not full field validation. It
// is create-only: an existing CRD (a prior seed, or a re-seed) is left as
// is, so an attacker's own custom resources are never disturbed by a
// heartbeat re-seed.
func (sh *Shim) createCRDs(ctx context.Context, crds []seed.CRD) error {
	if len(crds) == 0 || sh.crdClient == nil {
		return nil
	}
	if sh.installedCRDs == nil {
		sh.installedCRDs = map[string]bool{}
	}
	for _, c := range crds {
		obj := buildCRD(c)
		// Already handled by this process in an earlier heartbeat: skip the
		// apiserver round-trip entirely.
		if sh.installedCRDs[obj.Name] {
			continue
		}
		_, err := sh.crdClient.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, obj.Name, metav1.GetOptions{})
		if err == nil {
			sh.installedCRDs[obj.Name] = true
			continue
		}
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("getting CRD %q: %w", obj.Name, err)
		}
		if _, err := sh.crdClient.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, obj, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating CRD %q: %w", obj.Name, err)
		}
		sh.installedCRDs[obj.Name] = true
	}
	return nil
}

// buildCRD turns a compact seed.CRD into a full apiextensions CRD object
// with a permissive schema. The plural+group form the CRD name
// (<plural>.<group>), matching the convention every real CRD follows.
func buildCRD(c seed.CRD) *apiextensionsv1.CustomResourceDefinition {
	scope := apiextensionsv1.NamespaceScoped
	if c.Scope == string(apiextensionsv1.ClusterScoped) {
		scope = apiextensionsv1.ClusterScoped
	}
	singular := c.Singular
	if singular == "" {
		singular = strings.ToLower(c.Kind)
	}
	versions := c.Versions
	if len(versions) == 0 {
		versions = []string{"v1"}
	}
	preserve := true
	crdVersions := make([]apiextensionsv1.CustomResourceDefinitionVersion, 0, len(versions))
	for i, v := range versions {
		crdVersions = append(crdVersions, apiextensionsv1.CustomResourceDefinitionVersion{
			Name: v,
			// First version is the storage version, exactly one must be.
			Served:  true,
			Storage: i == 0,
			Schema: &apiextensionsv1.CustomResourceValidation{
				OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
					Type:                   "object",
					XPreserveUnknownFields: &preserve,
				},
			},
		})
	}
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: c.Plural + "." + c.Group},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: c.Group,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:     c.Plural,
				Singular:   singular,
				Kind:       c.Kind,
				ListKind:   c.Kind + "List",
				ShortNames: c.ShortNames,
			},
			Scope:    scope,
			Versions: crdVersions,
		},
	}
}

// nodeImages returns a believable set of cached container images a real
// control-plane node would report in node.status.images -- a node reporting
// zero images is a tell. Sizes are realistic byte counts.
func nodeImages(version string) []corev1.ContainerImage {
	img := func(name string, size int64) corev1.ContainerImage {
		return corev1.ContainerImage{Names: []string{name}, SizeBytes: size}
	}
	return []corev1.ContainerImage{
		img("registry.k8s.io/kube-apiserver:"+version, 91000000),
		img("registry.k8s.io/kube-controller-manager:"+version, 88000000),
		img("registry.k8s.io/kube-scheduler:"+version, 67000000),
		img("registry.k8s.io/kube-proxy:"+version, 92000000),
		img("registry.k8s.io/etcd:3.5.16-0", 151000000),
		img("registry.k8s.io/coredns/coredns:v1.11.3", 61000000),
		img("registry.k8s.io/pause:3.10", 736000),
	}
}

// createConfigMaps upserts the seed's ConfigMaps (the static kubeadm install
// artifacts a real cluster carries in kube-system/kube-public). Create or
// update in place; never deletes, so an attacker's own edits are not clobbered
// beyond the seeded keys.
func (sh *Shim) createConfigMaps(ctx context.Context, cms []seed.ConfigMap) error {
	for _, c := range cms {
		if err := sh.ensureNamespace(ctx, c.Namespace); err != nil {
			return err
		}
		desired := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: c.Namespace, Labels: c.Labels},
			Data:       c.Data,
		}
		existing, err := sh.client.CoreV1().ConfigMaps(c.Namespace).Get(ctx, c.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, err := sh.client.CoreV1().ConfigMaps(c.Namespace).Create(ctx, desired, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		existing.Data = c.Data
		existing.Labels = c.Labels
		if _, err := sh.client.CoreV1().ConfigMaps(c.Namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// createServices upserts the seed's Services and, for each with a ClusterIP,
// a matching EndpointSlice so `get endpoints`/`get endpointslices` are
// non-empty like a real Service's (e.g. the kube-dns Service every cluster
// has).
func (sh *Shim) createServices(ctx context.Context, svcs []seed.Service) error {
	for _, s := range svcs {
		if err := sh.ensureNamespace(ctx, s.Namespace); err != nil {
			return err
		}
		ports := make([]corev1.ServicePort, 0, len(s.Ports))
		for _, p := range s.Ports {
			proto := corev1.ProtocolTCP
			if p.Protocol == "UDP" {
				proto = corev1.ProtocolUDP
			}
			sp := corev1.ServicePort{Name: p.Name, Port: p.Port, Protocol: proto}
			if p.TargetPort != 0 {
				sp.TargetPort = intstr.FromInt32(p.TargetPort)
			}
			ports = append(ports, sp)
		}
		desired := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace, Labels: s.Labels},
			Spec: corev1.ServiceSpec{
				ClusterIP: s.ClusterIP,
				Selector:  s.Selector,
				Ports:     ports,
			},
		}
		_, err := sh.client.CoreV1().Services(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, cerr := sh.client.CoreV1().Services(s.Namespace).Create(ctx, desired, metav1.CreateOptions{})
			// The seeded ClusterIP is the standard one (e.g. 10.96.0.10 for
			// kube-dns), which matches the decoy apiserver's own
			// --service-cluster-ip-range. If that IP is outside the range
			// this particular apiserver was configured with, fall back to a
			// server-assigned ClusterIP rather than failing the whole seed.
			if cerr != nil && apierrors.IsInvalid(cerr) {
				desired.Spec.ClusterIP = ""
				desired.Spec.ClusterIPs = nil
				_, cerr = sh.client.CoreV1().Services(s.Namespace).Create(ctx, desired, metav1.CreateOptions{})
			}
			if cerr != nil && !apierrors.IsAlreadyExists(cerr) {
				return cerr
			}
		} else if err != nil {
			return err
		}
		if s.ClusterIP != "" && len(s.EndpointIPs) > 0 {
			if err := sh.ensureEndpointSlice(ctx, s); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureEndpointSlice creates the EndpointSlice backing a seeded Service, so
// its Endpoints resolve to the seeded backend IPs (e.g. the coredns pod IPs
// for kube-dns).
func (sh *Shim) ensureEndpointSlice(ctx context.Context, s seed.Service) error {
	name := s.Name
	endpoints := make([]discoveryv1.Endpoint, 0, len(s.EndpointIPs))
	ready := true
	for _, ip := range s.EndpointIPs {
		endpoints = append(endpoints, discoveryv1.Endpoint{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
		})
	}
	ports := make([]discoveryv1.EndpointPort, 0, len(s.Ports))
	for _, p := range s.Ports {
		port := p.Port
		proto := corev1.ProtocolTCP
		if p.Protocol == "UDP" {
			proto = corev1.ProtocolUDP
		}
		name := p.Name
		ports = append(ports, discoveryv1.EndpointPort{Name: &name, Port: &port, Protocol: &proto})
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: s.Namespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: s.Name},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports:       ports,
	}
	_, err := sh.client.DiscoveryV1().EndpointSlices(s.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := sh.client.DiscoveryV1().EndpointSlices(s.Namespace).Create(ctx, slice, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		return nil
	}
	return err
}

// adoptScheduledPods marks any pod bound to one of the decoy's fake nodes that
// is not yet Running as Running, with a fake container status per container.
// The decoy runs a real scheduler, so an attacker's own Pod (directly, or via
// a Deployment/Job the real controllers expand) gets bound to a fake node --
// but no real kubelet runs it, so it would sit Pending forever, an obvious
// tell. kubelet-shim is the decoy's kubelet, so it "runs" those pods the same
// way it runs the seeded ones. Pods the shim itself seeded are already
// Running and skipped.
func (sh *Shim) adoptScheduledPods(ctx context.Context, nodeNames map[string]bool) error {
	if len(nodeNames) == 0 {
		return nil
	}
	pods, err := sh.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if !nodeNames[p.Spec.NodeName] {
			continue
		}
		if p.Status.Phase == corev1.PodRunning {
			continue
		}
		start := podStartTime(p)
		statuses := runningContainerStatuses(p.Name, p.Spec.Containers, start)
		p.Status = podStatus(start, p.Name, p.Spec.NodeName, sh.cfg.NodeInternalIP, statuses, p.Spec.HostNetwork)
		if _, err := sh.client.CoreV1().Pods(p.Namespace).UpdateStatus(ctx, p, metav1.UpdateOptions{}); err != nil {
			// Best effort: a pod deleted mid-loop or a conflict is not fatal
			// to the heartbeat.
			continue
		}
	}
	return nil
}

// ensureNodeLeases creates or renews one Lease per fake node in
// kube-node-lease, holderIdentity set to the node name and renewTime bumped
// to now, owned by the node -- byte-for-byte the shape a real kubelet's node
// lease has. Renewed on every heartbeat pass.
func (sh *Shim) ensureNodeLeases(ctx context.Context, nodes []v1alpha1.FakeNode) error {
	if len(nodes) == 0 {
		return nil
	}
	const ns = "kube-node-lease"
	if err := sh.ensureNamespace(ctx, ns); err != nil {
		return err
	}
	now := metav1.NewMicroTime(time.Now())
	dur := int32(40)
	for _, n := range nodes {
		holder := n.Name
		var owners []metav1.OwnerReference
		if uid, ok := sh.objectUIDs["Node/"+n.Name]; ok {
			owners = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: n.Name, UID: uid}}
		}
		existing, err := sh.client.CoordinationV1().Leases(ns).Get(ctx, n.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			lease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: n.Name, Namespace: ns, OwnerReferences: owners},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holder,
					LeaseDurationSeconds: &dur,
					RenewTime:            &now,
				},
			}
			if _, err := sh.client.CoordinationV1().Leases(ns).Create(ctx, lease, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		existing.Spec.RenewTime = &now
		if existing.Spec.HolderIdentity == nil {
			existing.Spec.HolderIdentity = &holder
		}
		if existing.Spec.LeaseDurationSeconds == nil {
			existing.Spec.LeaseDurationSeconds = &dur
		}
		if len(existing.OwnerReferences) == 0 && owners != nil {
			existing.OwnerReferences = owners
		}
		if _, err := sh.client.CoordinationV1().Leases(ns).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

// finalizeTerminatingNamespaces stands in for the namespace controller,
// which lives in kube-controller-manager -- a component a Decoy's inner
// control plane deliberately does not run. `kubectl delete namespace` only
// stamps a deletionTimestamp and leaves the "kubernetes" finalizer in
// place; something then has to purge the namespace's contents and clear
// that finalizer before the apiserver will drop the object. With nothing
// doing it, an attacker's `kubectl delete ns` hangs until its own timeout
// and the namespace sits in Terminating forever, which is both a broken
// verb and a tell -- the same failure `kubectl delete pod` used to have
// (see upsertPod).
//
// The contents are deleted first, the way the real controller does it, so
// the store is not left holding pods and secrets belonging to a namespace
// that no longer exists.
func (sh *Shim) finalizeTerminatingNamespaces(ctx context.Context) error {
	list, err := sh.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range list.Items {
		ns := &list.Items[i]
		if ns.DeletionTimestamp == nil {
			continue
		}
		sh.purgeNamespace(ctx, ns.Name)

		// Finalize, not Update: spec.finalizers is only writable through
		// the namespace's own /finalize subresource, which is exactly what
		// the real namespace controller calls.
		ns.Spec.Finalizers = nil
		if _, err := sh.client.CoreV1().Namespaces().Finalize(ctx, ns, metav1.UpdateOptions{}); err != nil {
			if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
				continue
			}
			return err
		}
	}
	return nil
}

// purgeNamespace force-deletes the object kinds a decoy actually serves out
// of a namespace on its way out. Best-effort by design: a failure here
// should not block clearing the finalizer, since a namespace wedged in
// Terminating is a worse tell than a leftover object inside one that is
// about to disappear.
func (sh *Shim) purgeNamespace(ctx context.Context, name string) {
	var grace int64
	opts := metav1.DeleteOptions{GracePeriodSeconds: &grace}
	all := metav1.ListOptions{}
	_ = sh.client.CoreV1().Pods(name).DeleteCollection(ctx, opts, all)
	_ = sh.client.CoreV1().Secrets(name).DeleteCollection(ctx, opts, all)
	_ = sh.client.CoreV1().ConfigMaps(name).DeleteCollection(ctx, opts, all)
	_ = sh.client.AppsV1().Deployments(name).DeleteCollection(ctx, opts, all)
	_ = sh.client.AppsV1().ReplicaSets(name).DeleteCollection(ctx, opts, all)
	_ = sh.client.AppsV1().DaemonSets(name).DeleteCollection(ctx, opts, all)
}

func (sh *Shim) ensureNamespace(ctx context.Context, name string) error {
	_, err := sh.client.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	_, err = sh.client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// upsertNode creates or updates one fake Node object. status.conditions is
// always set explicitly (never left nil) and InternalIP always points at
// cfg.NodeInternalIP -- see the Config.NodeInternalIP doc comment for why
// both of these are load-bearing, not cosmetic choices.
// stripNotReadyTaints removes the not-ready/unreachable NoSchedule taints from
// a node's taint list. A real Ready node has neither; see the call site in
// upsertNode for why the shim clears them itself.
func stripNotReadyTaints(taints []corev1.Taint) []corev1.Taint {
	if len(taints) == 0 {
		return taints
	}
	kept := taints[:0]
	for _, t := range taints {
		if t.Key == "node.kubernetes.io/not-ready" || t.Key == "node.kubernetes.io/unreachable" {
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

// fakeMachineID/fakeSystemUUID/fakeBootID synthesize the machine identity a
// real kubelet reads off the host (/etc/machine-id, DMI, /proc/sys/kernel/
// random/boot_id). They are stable per node name, and shaped exactly like
// the real thing: machineID is 32 lowercase hex characters with no dashes,
// the other two are dashed UUIDs.
func fakeMachineID(nodeName string) string {
	return hexBlob("machine-id/"+nodeName, 16)
}

func fakeSystemUUID(nodeName string) string {
	return uuidFrom("system-uuid/" + nodeName)
}

func fakeBootID(nodeName string) string {
	return uuidFrom("boot-id/" + nodeName)
}

func (sh *Shim) upsertNode(ctx context.Context, n v1alpha1.FakeNode, controlPlane bool) error {
	now := metav1.Now()
	kubeletVersion := n.KubeletVersion
	if kubeletVersion == "" {
		kubeletVersion = "v1.35.0"
	}

	build := func(existing *corev1.Node) *corev1.Node {
		node := existing
		if node == nil {
			node = &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.Name}}
		}
		// The Ready condition's transition time is when the node BECAME
		// ready and must stay put; only the heartbeat time advances. Resetting
		// both to now each cycle made the node read "became ready just now"
		// on every heartbeat, a tell. Preserve an existing transition time;
		// otherwise anchor it to the node's creationTimestamp (falling back to
		// now for a not-yet-created node).
		readyTransition := now
		if node.CreationTimestamp.IsZero() {
			readyTransition = now
		} else {
			readyTransition = node.CreationTimestamp
		}
		for _, c := range node.Status.Conditions {
			if c.Type == corev1.NodeReady && !c.LastTransitionTime.IsZero() {
				readyTransition = c.LastTransitionTime
			}
		}
		if node.Labels == nil {
			node.Labels = map[string]string{}
		}
		node.Labels["kubernetes.io/hostname"] = n.Name
		node.Labels["kubernetes.io/os"] = "linux"
		node.Labels["kubernetes.io/arch"] = "amd64"
		node.Labels["node.kubernetes.io/instance-type"] = "c2-m4"
		if controlPlane {
			// The decoy pins etcd/kube-apiserver/kube-controller-manager/
			// kube-scheduler to this node (see the operator's
			// defaultKubeSystemPods). Without the role label `kubectl get
			// nodes` prints ROLES=<none> for a node visibly running the
			// entire control plane, which no real cluster looks like.
			//
			// The label, deliberately not the matching NoSchedule taint: a
			// single-node cluster with the control-plane taint removed is an
			// ordinary, coherent setup, whereas adding the taint would leave
			// the decoy's own real scheduler unable to place coredns.
			node.Labels["node-role.kubernetes.io/control-plane"] = ""
			node.Labels["node.kubernetes.io/exclude-from-external-load-balancers"] = ""
		}

		// A real Ready node carries no not-ready/unreachable taint. The
		// apiserver's TaintNodesByCondition admission adds not-ready when a
		// node first appears without a Ready status, and the node-lifecycle
		// controller normally removes it once Ready -- but that controller is
		// disabled here (it would evict the seeded pods), so strip it
		// ourselves. Without this the real scheduler refuses to place any pod
		// an attacker (or the coredns Deployment) creates: they sit Pending
		// with "untolerated taint node.kubernetes.io/not-ready", which both
		// breaks the "attacker workloads run for real" behaviour and is itself
		// a tell.
		node.Spec.Taints = stripNotReadyTaints(node.Spec.Taints)
		node.Status = corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				KubeletVersion: kubeletVersion,
				// KernelVersion matches the `uname` an exec session reports
				// (see kernelRelease) and a real Ubuntu 24.04 node; left unset
				// it renders as "<unknown>" under `kubectl get nodes -o wide`,
				// a tell.
				KernelVersion:           kernelRelease,
				OperatingSystem:         "linux",
				Architecture:            "amd64",
				OSImage:                 "Ubuntu 24.04.3 LTS",
				ContainerRuntimeVersion: "containerd://2.2.0",
				// Every real kubelet reports these three. Left empty they
				// render as machineID: "" / systemUUID: "" under `kubectl
				// get node -o yaml`, which no real node ever shows -- a
				// one-command tell. Derived from the node name so they stay
				// put across heartbeats and restarts, the way a real
				// machine's identity does.
				MachineID:  fakeMachineID(n.Name),
				SystemUUID: fakeSystemUUID(n.Name),
				BootID:     fakeBootID(n.Name),
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: sh.cfg.NodeInternalIP},
				{Type: corev1.NodeHostName, Address: n.Name},
			},
			// Explicit, never nil -- see Config.NodeInternalIP doc comment /
			// kwok-honeypot-zeno gotcha #2.
			Conditions: []corev1.NodeCondition{
				{
					Type: corev1.NodeReady, Status: corev1.ConditionTrue,
					// Message text matches a real kubelet's own wording
					// exactly -- this is served to anyone with the decoy
					// token, so it must not read as anything but real.
					Reason: "KubeletReady", Message: "kubelet is posting ready status",
					LastHeartbeatTime: now, LastTransitionTime: readyTransition,
				},
			},
			DaemonEndpoints: corev1.NodeDaemonEndpoints{
				KubeletEndpoint: corev1.DaemonEndpoint{Port: sh.cfg.KubeletPort},
			},
			// Every real node reports ephemeral-storage alongside cpu/memory
			// /pods; a node missing it entirely is visible in one `kubectl
			// describe node`. And a real node's allocatable is never equal to
			// its capacity for memory and storage -- kubelet holds back its
			// hard-eviction thresholds (100Mi of memory, 10% of imagefs by
			// default), so identical capacity and allocatable is itself the
			// anomaly.
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("2"),
				corev1.ResourceMemory:           resource.MustParse("4Gi"),
				corev1.ResourcePods:             resource.MustParse("110"),
				corev1.ResourceEphemeralStorage: resource.MustParse("50620216Ki"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("2"),
				corev1.ResourceMemory:           resource.MustParse("4093952Ki"),
				corev1.ResourcePods:             resource.MustParse("110"),
				corev1.ResourceEphemeralStorage: resource.MustParse("46663523866"),
			},
			// A real node caches the images of everything that has run on it.
			// A node reporting zero images is a tell, so report a believable
			// control-plane set at this cluster's version.
			Images: nodeImages(kubeletVersion),
		}
		return node
	}

	existing, err := sh.client.CoreV1().Nodes().Get(ctx, n.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		created, err := sh.client.CoreV1().Nodes().Create(ctx, build(nil), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		sh.recordUID("Node/"+n.Name, created.UID)
		created.Status = build(created).Status
		_, err = sh.client.CoreV1().Nodes().UpdateStatus(ctx, created, metav1.UpdateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	sh.recordUID("Node/"+n.Name, existing.UID)
	updated := build(existing)
	// The spec Update now actually changes the node when it strips the
	// not-ready taint, so it bumps the resourceVersion. Carry that fresh
	// object (not the pre-Update one) into UpdateStatus, or the status write
	// fails with a "the object has been modified" conflict.
	out, err := sh.client.CoreV1().Nodes().Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	out.Status = updated.Status
	_, err = sh.client.CoreV1().Nodes().UpdateStatus(ctx, out, metav1.UpdateOptions{})
	return err
}

func (sh *Shim) upsertWorkload(ctx context.Context, w seed.Pod, nodeName string) error {
	replicas := w.Replicas
	if replicas < 1 {
		replicas = 1
	}
	for r := int32(0); r < replicas; r++ {
		name := w.Name
		if replicas > 1 {
			name = fmt.Sprintf("%s-%s", w.Name, replicaSuffix(w.Name, r))
		}
		if err := sh.upsertPod(ctx, w, name, nodeName); err != nil {
			return err
		}
		ns, podName := w.Namespace, name
		sh.markSeeded("Pod|"+ns+"|"+podName, func(ctx context.Context) error {
			// Force (grace 0): there is no real kubelet to confirm a graceful
			// pod deletion, so without this the pruned pod hangs in
			// Terminating forever.
			zero := int64(0)
			return sh.client.CoreV1().Pods(ns).Delete(ctx, podName, metav1.DeleteOptions{GracePeriodSeconds: &zero})
		})
	}
	return nil
}

func (sh *Shim) upsertPod(ctx context.Context, w seed.Pod, name, nodeName string) error {
	// Requests, when the seed sets them, make a control-plane pod report a
	// Burstable QoS class like the real thing instead of BestEffort.
	var requests corev1.ResourceList
	if w.CPURequest != "" || w.MemoryRequest != "" {
		requests = corev1.ResourceList{}
		if w.CPURequest != "" {
			requests[corev1.ResourceCPU] = resource.MustParse(w.CPURequest)
		}
		if w.MemoryRequest != "" {
			requests[corev1.ResourceMemory] = resource.MustParse(w.MemoryRequest)
		}
	}
	var containers []corev1.Container
	for _, c := range w.Containers {
		container := corev1.Container{Name: c.Name, Image: c.Image}
		if requests != nil {
			container.Resources = corev1.ResourceRequirements{Requests: requests}
		}
		containers = append(containers, container)
	}

	labels := w.Labels
	if len(labels) == 0 {
		labels = map[string]string{"app": w.Name}
	}

	if len(w.LogLines) > 0 {
		sh.setLogLines(w.Namespace, name, w.LogLines)
	}

	ownerRefs := sh.resolveOwnerRefs(w.OwnerRefs)

	existing, err := sh.client.CoreV1().Pods(w.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: w.Namespace, Labels: labels, Annotations: w.Annotations, OwnerReferences: ownerRefs},
			Spec: corev1.PodSpec{
				// Setting NodeName directly at creation time is the
				// standard "static/mirror pod" pattern -- it skips the
				// scheduler entirely, exactly what a real kubelet does
				// for pods it owns. There is no real kube-scheduler
				// running against this inner apiserver at all.
				NodeName:    nodeName,
				HostNetwork: w.HostNetwork,
				Containers:  containers,
			},
		}
		created, err := sh.client.CoreV1().Pods(w.Namespace).Create(ctx, pod, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		start := podStartTime(created)
		created.Status = podStatus(start, name, nodeName, sh.cfg.NodeInternalIP, runningContainerStatuses(name, containers, start), w.HostNetwork)
		_, err = sh.client.CoreV1().Pods(w.Namespace).UpdateStatus(ctx, created, metav1.UpdateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	// A pod the attacker just deleted comes back from the Get carrying a
	// deletionTimestamp: kube-apiserver only marks it for graceful
	// deletion and then waits for the kubelet that owns it to confirm the
	// containers are gone. Nothing else plays kubelet here, so without
	// this the object never leaves the store -- `kubectl delete pod` hangs
	// until its own timeout and the pod sits in Terminating forever, which
	// both breaks the verb and is an obvious tell. Completing it the way a
	// real kubelet does (delete again with grace period 0) lets the delete
	// return immediately; the next heartbeat re-seeds the pod, matching a
	// controller-managed pod being recreated after it is killed.
	if existing.DeletionTimestamp != nil {
		var grace int64
		err := sh.client.CoreV1().Pods(w.Namespace).Delete(ctx, name, metav1.DeleteOptions{
			GracePeriodSeconds: &grace,
			Preconditions:      &metav1.Preconditions{UID: &existing.UID},
		})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return err
		}
		return nil
	}
	existing.Labels = labels
	existing.Annotations = w.Annotations
	existing.OwnerReferences = ownerRefs
	existing.Spec.NodeName = nodeName
	existing.Spec.HostNetwork = w.HostNetwork
	existing.Spec.Containers = containers
	if _, err := sh.client.CoreV1().Pods(w.Namespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return err
	}
	start := podStartTime(existing)
	existing.Status = podStatus(start, name, nodeName, sh.cfg.NodeInternalIP, runningContainerStatuses(name, containers, start), w.HostNetwork)
	_, err = sh.client.CoreV1().Pods(w.Namespace).UpdateStatus(ctx, existing, metav1.UpdateOptions{})
	return err
}

// podStartTime is the time a pod reports as its start (and its containers'
// StartedAt, and its Ready-condition transition). It is the pod's own
// immutable creationTimestamp, NOT time.Now(): re-deriving "now" on every
// heartbeat made every pod perpetually read "started 0s ago" under `kubectl
// describe`, a tell. Anchored to creationTimestamp, a pod's reported uptime
// grows with the decoy exactly as a real one's does. Falls back to now for a
// pod not yet persisted (no creationTimestamp).
func podStartTime(p *corev1.Pod) metav1.Time {
	if !p.CreationTimestamp.IsZero() {
		return p.CreationTimestamp
	}
	return metav1.Now()
}

// stableRestartCount gives a pod's container a small, deterministic restart
// count. A whole cluster where every container reports exactly 0 restarts is
// itself faintly unusual; a stable per-container value (mostly 0, occasionally
// 1-2) that never changes across heartbeats reads like an ordinary workload.
func stableRestartCount(podName, containerName string) int32 {
	// Map the hash into [0,32); most land under the first threshold, so most
	// containers report 0 restarts, a few 1, fewer 2.
	b := int(hash32(podName+"/"+containerName) % 32)
	switch {
	case b < 24:
		return 0
	case b < 30:
		return 1
	default:
		return 2
	}
}

// runningContainerStatuses builds Ready/Running container statuses for a pod,
// with StartedAt anchored to the pod's start time (see podStartTime) and a
// stable restart count (see stableRestartCount), reused by both the seed path
// and the adopt-scheduled-pod path.
func runningContainerStatuses(podName string, containers []corev1.Container, startedAt metav1.Time) []corev1.ContainerStatus {
	statuses := make([]corev1.ContainerStatus, 0, len(containers))
	started := true
	for _, c := range containers {
		statuses = append(statuses, corev1.ContainerStatus{
			Name: c.Name, Image: c.Image, Ready: true, Started: &started,
			RestartCount: stableRestartCount(podName, c.Name),
			ContainerID:  fakeContainerID(podName, c.Name),
			ImageID:      fakeImageID(c.Image),
			State:        corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: startedAt}},
		})
	}
	return statuses
}

// fakePodIP is the address a fabricated pod reports. A real cluster gives
// each node its own pod CIDR (a /24 out of the cluster's pod network) and
// every pod on it a distinct address inside that. This used to derive the
// whole address from the node name alone, so every pod on a node reported
// the *same* IP -- `kubectl get pods -o wide` listing two pods sharing an
// address is not something a real cluster can produce, and it is one
// column of one command away from anyone looking. Node picks the /24, pod
// picks the host octet, both stable across heartbeats so a pod's IP does
// not change under a watching attacker.
func fakePodIP(nodeName, podName string) string {
	third := hash32(nodeName) % 200
	// .1 is the node's own gateway on a real pod CIDR, and .0/.255 are the
	// network and broadcast addresses, so keep clear of them.
	fourth := 2 + hash32(nodeName+"/"+podName)%250
	return fmt.Sprintf("10.244.%d.%d", third, fourth)
}

// podStatus builds a Running pod status. A host-networked pod (a real static
// control-plane pod: etcd, kube-apiserver, kube-proxy) reports podIP == hostIP
// (the node's own address); a separate pod IP on those is a tell. startTime
// anchors the reported uptime (see podStartTime).
func podStatus(startTime metav1.Time, podName, nodeName, hostIP string, statuses []corev1.ContainerStatus, hostNetwork bool) corev1.PodStatus {
	podIP := fakePodIP(nodeName, podName)
	if hostNetwork {
		podIP = hostIP
	}
	return corev1.PodStatus{
		Phase:     corev1.PodRunning,
		StartTime: &startTime,
		Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
			LastTransitionTime: startTime,
		}},
		// HostIP is the node's own address. Empty renders as "Node:
		// <name>/" (trailing slash) under `kubectl describe`, a tell; it
		// matches what every fake Node reports as its InternalIP.
		HostIP:            hostIP,
		PodIP:             podIP,
		PodIPs:            []corev1.PodIP{{IP: podIP}},
		ContainerStatuses: statuses,
	}
}

func (sh *Shim) upsertSecret(ctx context.Context, s v1alpha1.FakeSecret) error {
	data := map[string][]byte{}
	for kk, v := range s.Data {
		data[kk] = []byte(v)
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: s.Name, Namespace: s.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
	existing, err := sh.client.CoreV1().Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sh.client.CoreV1().Secrets(s.Namespace).Create(ctx, sec, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	existing.Data = data
	_, err = sh.client.CoreV1().Secrets(s.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// RunHeartbeat re-seeds (idempotently) and refreshes every fake Node's Ready
// condition + LastHeartbeatTime every interval, until ctx is cancelled, so
// the fake nodes look continuously live rather than only briefly at
// process startup. Errors are logged, not fatal -- a transient inner
// apiserver hiccup shouldn't crash kubelet-shim.
func (sh *Shim) RunHeartbeat(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-read first: this is what carries a joined or unjoined
			// pod into the decoy without restarting it.
			sh.reloadSeed()
			if err := sh.Seed(ctx); err != nil {
				log.Printf("kubelet-shim: heartbeat re-seed failed: %v", err)
			}
		}
	}
}
