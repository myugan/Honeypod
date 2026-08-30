package kubeletshim

import (
	"crypto/tls"
	"net/http"
)

// NewServer builds the HTTPS server kubelet-shim exposes as the
// kubelet-endpoint side of exec/attach/logs: this is what the real
// kube-apiserver's kubelet-client proxy dials (using each seeded Node's
// status.daemonEndpoints.kubeletEndpoint.Port and InternalIP) when a
// client calls the pods/exec, pods/attach, or pods/log subresources
// against a Pod scheduled on one of these fake nodes. Route paths mirror
// the real kubelet HTTP API exactly (see
// k8s.io/kubelet/pkg/apis... server.go InstallDefaultHandlers): container
// name is a path segment here, unlike the client-facing apiserver
// subresource API where it's a query parameter.
//
// No authentication is performed on incoming requests -- this endpoint is
// reachable only from inside this Decoy's own inner cluster boundary
// (the real kube-apiserver's own kubelet-client proxy dials it directly,
// not through its own RBAC authorizer). The isolation boundary for this
// whole decoy is network/credential separation from the real cluster, not
// anything RBAC would add inside a fully decoy, zero-real-data inner
// cluster.
func (sh *Shim) NewServer(certFile, keyFile string) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /containerLogs/{ns}/{pod}/{container}", sh.handleLogs)
	mux.HandleFunc("GET /exec/{ns}/{pod}/{container}", sh.handleExec)
	mux.HandleFunc("POST /exec/{ns}/{pod}/{container}", sh.handleExec)
	mux.HandleFunc("GET /attach/{ns}/{pod}/{container}", sh.handleAttach)
	mux.HandleFunc("POST /attach/{ns}/{pod}/{container}", sh.handleAttach)
	// port-forward is deliberately not implemented, mirroring the
	// pre-nested-control-plane decoy's behavior -- a synthetic session
	// can't meaningfully fake a bound port.
	mux.HandleFunc("GET /portForward/{ns}/{pod}", handlePortForward)
	mux.HandleFunc("POST /portForward/{ns}/{pod}", handlePortForward)
	// The kubelet stats API -- served for real (synthesized values, real wire
	// shape) so a real metrics-server can scrape this decoy's kubelet and
	// `kubectl top` works, and `.../proxy/pods` resolves. See stats.go.
	mux.HandleFunc("GET /stats/summary", sh.handleStatsSummary)
	mux.HandleFunc("POST /stats/summary", sh.handleStatsSummary)
	mux.HandleFunc("GET /metrics/resource", sh.handleResourceMetrics)
	mux.HandleFunc("GET /pods", sh.handlePodsEndpoint)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	return &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}, nil
}

// handlePortForward refuses port-forward with the same error a
// real kubelet gives when its port-forward helper binary is missing from
// the target container's network namespace -- authentic-looking, unlike a
// message that names this as a decoy.
func handlePortForward(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	writeStatus(w, http.StatusNotImplemented, "MethodNotAllowed", "unable to do port forwarding: socat not found")
}
