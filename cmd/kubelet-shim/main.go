// Command kubelet-shim is a controller-style process, deployed as a
// container in a Decoy's inner-control-plane pod alongside kine,
// kube-apiserver. It uses a real client-go client pointed at
// that pod's own inner kube-apiserver -- our own decoy control plane, not a
// route to anything real -- to seed Node/Pod/Secret objects from
// spec.fakeNodes/spec.fakePods/spec.fakeSecrets, keep those fake nodes
// reporting Ready, and serve the kubelet-side HTTPS debugging endpoints
// (exec/attach/logs) the real kube-apiserver proxies to when a client acts
// on a Pod scheduled on one of them. See internal/kubeletshim for the
// implementation.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/rest"

	"honeypod.io/honeypod/internal/kubeletshim"
	"honeypod.io/honeypod/internal/seed"
)

func main() {
	// Re-exec entry point for an isolated exec session (spec.execIsolation):
	// the shim re-execs itself with --exec-init inside a fresh PID/mount/UTS
	// namespace, sets the session up (hostname, /proc), then execs the target.
	// Handled before any flag parsing, since its args are the target command.
	if len(os.Args) > 1 && os.Args[1] == "--exec-init" {
		kubeletshim.RunExecInit(os.Args[2:])
		return
	}

	apiServerURL := flag.String("apiserver", "https://127.0.0.1:8443", "URL of this Decoy's own inner kube-apiserver")
	caFile := flag.String("ca-file", "/etc/kubernetes/pki/ca.crt", "path to the inner apiserver's CA certificate")
	tokenFile := flag.String("token-file", "/etc/kubernetes/pki/token", "path to the decoy bearer token served back to a real exec session reading the ServiceAccount path")
	clientTokenFile := flag.String("client-token-file", "", "path to this process's own bearer token for the inner apiserver, a separate system: identity so its seeding is distinguishable from attacker traffic; falls back to --token-file when empty")
	seedPath := flag.String("seed", "/etc/kubernetes/seed.json", "path to the seed JSON file")
	nodeInternalIP := flag.String("node-internal-ip", "", "stable Service ClusterIP fronting this kubelet-shim's own kubelet-endpoint port; every seeded Node's InternalIP is set to this")
	kubeletPort := flag.Int("kubelet-port", 10250, "port advertised via each seeded Node's status.daemonEndpoints.kubeletEndpoint, and the port --listen binds")
	kubernetesServicePort := flag.Int("kubernetes-service-port", 6443, "the decoy apiserver Service port reported as KUBERNETES_SERVICE_PORT in an exec session's environment (paired with --node-internal-ip as the host), so `env` inside a decoy points at this decoy and not the real host cluster")
	execProfile := flag.String("exec-profile", "shell", "environment a `kubectl exec` session presents: \"shell\" (full /bin/sh), \"minimal\" (busybox), or \"distroless\" (no shell -- exec fails like a distroless image)")
	execIsolation := flag.Bool("exec-isolation", false, "run each exec session in its own PID/mount/UTS namespace so `ps` shows only that session and each pod has its own hostname; requires CAP_SYS_ADMIN (see spec.execIsolation)")
	listen := flag.String("listen", ":10250", "address the kubelet-endpoint HTTPS server listens on")
	tlsCertFile := flag.String("tls-cert-file", "/etc/kubernetes/pki/tls.crt", "path to the PEM TLS certificate for the kubelet-endpoint HTTPS server")
	tlsKeyFile := flag.String("tls-key-file", "/etc/kubernetes/pki/tls.key", "path to the matching PEM TLS key")
	heartbeatInterval := flag.Duration("heartbeat-interval", 20*time.Second, "how often to re-seed and refresh fake Node Ready status")
	saDir := flag.String("sa-dir", "/var/run/secrets/kubernetes.io/serviceaccount", "directory to write token/namespace/ca.crt into, so a real exec session's `cat` on the standard ServiceAccount path sees this Decoy's own decoy credentials (an emptyDir volume in production; a temp dir in tests)")
	namespace := flag.String("namespace", "", "the Decoy CR's own namespace, written to <sa-dir>/namespace")
	kubernetesVersion := flag.String("kubernetes-version", "v1.35.0", "version this decoy claims to be, used to build a real kubelet's User-Agent so seeded objects carry a believable managedFields manager")
	recordExec := flag.Bool("record-exec-sessions", true, "log each exec/attach session's transcript to stdout, so `kubectl logs <decoy-pod> -c kubelet-shim` shows what an attacker typed inside an interactive shell")
	writeSALayout := flag.Bool("write-sa-layout", false, "write the real automount ServiceAccount layout (atomic-writer data dir + symlinks) to --sa-dir and exit; run as root in an init container so the files are root-owned like a real mount, then exit")
	flag.Parse()

	// Init-container mode: populate the ServiceAccount path to look exactly
	// like a real automount (root-owned, symlinked into a ..data dir) and
	// exit. The main container then serves exec against it without needing
	// to write it (and without root).
	if *writeSALayout {
		tok, err := os.ReadFile(*tokenFile)
		if err != nil {
			log.Fatalf("loading decoy token: %v", err)
		}
		files := map[string][]byte{
			"token":     []byte(strings.TrimSpace(string(tok))),
			"namespace": []byte(*namespace),
		}
		if *caFile != "" {
			ca, err := os.ReadFile(*caFile)
			if err != nil {
				log.Fatalf("loading ca: %v", err)
			}
			files["ca.crt"] = ca
		}
		if err := kubeletshim.WriteServiceAccountLayout(*saDir, files); err != nil {
			log.Fatalf("writing serviceaccount layout: %v", err)
		}
		return
	}

	if *nodeInternalIP == "" {
		log.Fatalf("--node-internal-ip is required (the fronting Service's stable ClusterIP)")
	}

	// A string flag's value aliases the raw argv memory that MaskProcessTitle
	// is about to overwrite; re-set every flag to a heap copy first, or a flag
	// read after masking (e.g. --seed below) comes back empty/corrupt.
	flag.VisitAll(func(f *flag.Flag) {
		_ = f.Value.Set(strings.Clone(f.Value.String()))
	})

	// Flags are safely copied off; hide this process's own argv/comm now. An
	// exec session runs in this (the kubelet-shim) container, whose PID 1 is
	// this binary -- unmasked, `ps` / `cat /proc/1/cmdline` inside a decoy
	// would print "/kubelet-shim --seed=..." and name the honeypot outright.
	kubeletshim.MaskProcessTitle()

	s, err := seed.Load(*seedPath)
	if err != nil {
		log.Fatalf("loading seed: %v", err)
	}

	tokBytes, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatalf("loading decoy token: %v", err)
	}
	token := strings.TrimSpace(string(tokBytes))

	// The token this process authenticates with is deliberately not the
	// decoy token it serves back: a separate system: identity keeps its
	// own seeding out of attacker-activity alerts.
	clientToken := token
	if *clientTokenFile != "" {
		b, err := os.ReadFile(*clientTokenFile)
		if err != nil {
			log.Fatalf("loading client token: %v", err)
		}
		clientToken = strings.TrimSpace(string(b))
	}

	// kube-apiserver derives managedFields[].manager from the User-Agent's
	// first token. Left alone, client-go sends this binary's own name and
	// every seeded object carries "manager: kubelet-shim", which appears
	// nowhere in a real cluster and is visible to any raw API read. Present
	// as the kubelet this process stands in for instead.
	restConfig := &rest.Config{
		Host:        *apiServerURL,
		BearerToken: clientToken,
		UserAgent:   fmt.Sprintf("kubelet/%s (%s/%s) kubernetes/$Format", *kubernetesVersion, runtime.GOOS, runtime.GOARCH),
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: *caFile,
		},
	}

	shim, err := kubeletshim.New(kubeletshim.Config{
		RestConfig:            restConfig,
		Seed:                  s,
		SeedPath:              *seedPath,
		NodeInternalIP:        *nodeInternalIP,
		KubeletPort:           int32(*kubeletPort),
		KubernetesServicePort: int32(*kubernetesServicePort),
		ExecProfile:           *execProfile,
		ExecIsolation:         *execIsolation,
		ServiceAccountToken:   token,
		ServiceAccountDir:     *saDir,
		Namespace:             *namespace,
		CABundlePath:          *caFile,
		RecordExecSessions:    *recordExec,
	})
	if err != nil {
		log.Fatalf("building kubelet-shim: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := waitForAPIServer(ctx, shim); err != nil {
		log.Fatalf("inner apiserver never became reachable: %v", err)
	}

	srv, err := shim.NewServer(*tlsCertFile, *tlsKeyFile)
	if err != nil {
		log.Fatalf("building kubelet-endpoint server: %v", err)
	}
	srv.Addr = *listen

	// Seed in the background so the kubelet endpoint below starts serving
	// straight away. Seeding is one API call per object and takes a while
	// on a large spec; blocking on it first left exec, attach, and logs
	// refusing connections for that whole window while the Decoy
	// already reported Ready. Serving first turns that into a clean 404
	// for an object that genuinely isn't seeded yet.
	//
	// A bad seed entry must not take the decoy down either: everything
	// that did seed stays usable, and RunHeartbeat retries the rest on
	// every tick, rather than crash-looping the container and leaving the
	// Decoy stuck in Pending with no explanation.
	go func() {
		if err := shim.Seed(ctx); err != nil {
			log.Printf("initial seed incomplete, continuing and retrying on the next heartbeat: %v", err)
		}
		shim.RunHeartbeat(ctx, *heartbeatInterval)
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("kubelet-shim listening on %s (TLS) -- node-internal-ip=%s kubelet-port=%d", *listen, *nodeInternalIP, *kubeletPort)
	if err := srv.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

// waitForAPIServer polls the inner apiserver's own /readyz (or /healthz)
// until it responds, since kubelet-shim and kube-apiserver start as
// containers in the same pod with no guaranteed startup ordering.
func waitForAPIServer(ctx context.Context, shim *kubeletshim.Shim) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	deadline := time.After(60 * time.Second)
	for {
		if shim.APIServerReachable(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return context.DeadlineExceeded
		case <-ticker.C:
		}
	}
}
