// Command manager runs the Honeypod operator: it watches Decoy custom
// resources and reconciles each into an isolated decoy environment (fake
// API server + supporting Secrets/ConfigMaps/NetworkPolicy).
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/activity"
	"honeypod.io/honeypod/internal/auditwebhook"
	"honeypod.io/honeypod/internal/controller"
	"honeypod.io/honeypod/internal/metrics"
	"honeypod.io/honeypod/internal/notifier"
)

// webhookCertNamespace/webhookCertSecretName locate the Secret that
// persists the join-webhook's TLS cert across restarts -- matches
// config/manager/manager.yaml's own namespace.
const (
	webhookCertNamespace  = "honeypod"
	webhookCertSecretName = "honeypod-webhook-tls"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(honeypodv1alpha1.AddToScheme(scheme))
}

func main() {
	metricsAddr := flag.String("metrics-bind-address", ":8080", "address the Prometheus /metrics endpoint listens on -- serves both controller-runtime's built-in metrics and the honeypod_* families (see docs/metrics.md); set \"0\" to disable")
	auditWebhookAddr := flag.String("audit-webhook-bind-address", ":9880", "address the audit-webhook receiver listens on -- every Decoy's inner apiserver is configured to POST its real audit.k8s.io/v1 events here")
	managerAuditWebhookURL := flag.String("manager-audit-webhook-url", "", "base URL (scheme://host:port, no path) other Decoy inner apiservers use to reach this manager's audit-webhook receiver; defaults to matching config/manager's own Service (honeypod-controller-manager.honeypod.svc:9880)")
	joinWebhookAddr := flag.String("join-webhook-bind-address", ":9443", "address the honeypod.io/join MutatingWebhookConfiguration's HTTPS admission-review receiver listens on (see internal/controller/join_webhook.go and config/manager/webhook.yaml)")
	joinWebhookDNSNames := flag.String("join-webhook-dns-names", "honeypod-webhook.honeypod.svc,honeypod-webhook.honeypod.svc.cluster.local", "comma-separated DNS names the join-webhook's self-signed serving cert is issued for; must match config/manager/webhook.yaml's Service DNS name for the apiserver to trust it once its CA is patched into the MutatingWebhookConfiguration")
	joinWebhookConfigName := flag.String("join-webhook-config-name", "honeypod-pod-join", "name of the MutatingWebhookConfiguration object (config/manager/webhook.yaml) whose clientConfig.caBundle this manager keeps patched with its own webhook CA")
	logAuditEvents := flag.Bool("log-audit-events", true, "print notable audit events received from a Decoy's inner apiserver to this manager's own log (same notability heuristic as Alert: drops system: identities, status writes, lease renewals -- kube-apiserver's own startup burst and kubelet-shim's heartbeats); set false to keep the log quiet and rely on an AuditSink for the full unfiltered stream")
	logAllAuditEvents := flag.Bool("log-all-audit-events", false, "with -log-audit-events, also print the events the notability heuristic would drop -- kube-apiserver's startup housekeeping and kubelet-shim's own heartbeats, both under a system: identity")
	auditLogFormat := flag.String("audit-log-format", "text", "format for the audit lines -log-audit-events prints: \"text\" (the key=value line) or \"json\" (one JSON object per line, for a log shipper that expects structured input)")

	// Standard controller-runtime logging flags: --zap-log-level
	// (debug/info/error or a number for higher verbosity), --zap-encoder
	// (console/json), --zap-devel, --zap-stacktrace-level,
	// --zap-time-encoding. Defaults below keep the previous behaviour,
	// human-readable console output at debug level.
	logOpts := zap.Options{Development: true}
	logOpts.BindFlags(flag.CommandLine)

	flag.Parse()

	if *auditLogFormat != "text" && *auditLogFormat != "json" {
		log.Fatalf("-audit-log-format must be \"text\" or \"json\", got %q", *auditLogFormat)
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOpts)))
	setupLog := ctrl.Log.WithName("setup")

	// A direct (non-cached) client: notifier.Dispatcher's Lists/Gets are
	// triggered by discrete events, not a reconcile loop, so there's no
	// benefit to a cache -- and using one here would mean waiting for it to
	// sync before the very first audit event or Pod-join change could
	// be dispatched. Also reused for the CA-bundle-patch retry loop below.
	restConfig := ctrl.GetConfigOrDie()
	directClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to build direct API client")
		os.Exit(1)
	}
	notify := notifier.New(directClient)
	activityTracker := activity.New(directClient)

	// Each Decoy's inner kube-apiserver POSTs its audit events here
	// (via --audit-webhook-config-file, see internal/controller/render.go).
	// The /audit/{namespace}/{name} path says which Decoy they came
	// from. Every event is logged to stdout; matching Alerts and AuditSinks
	// (see internal/notifier) also get notified or shipped.
	go func() {
		setupLog.Info("starting audit-webhook receiver", "addr", *auditWebhookAddr)
		handler := auditwebhook.NewHandler(func(ns, name string, events []auditwebhook.Event) {
			metrics.AuditEvents.WithLabelValues(ns, name).Add(float64(len(events)))
			if *logAuditEvents {
				for _, ev := range events {
					if !*logAllAuditEvents && !notifier.IsNotableAuditEvent(ev, notifier.AuditFilter{}) {
						continue
					}
					if *auditLogFormat == "json" {
						auditwebhook.LogEventJSON(ns, name, ev)
					} else {
						auditwebhook.LogEvent(ns, name, ev)
					}
				}
			}
			// Record attacker traffic (notable events only) for the
			// status summary shown by `kubectl get decoys`.
			for _, ev := range events {
				if notifier.IsNotableAuditEvent(ev, notifier.AuditFilter{}) {
					srcIP := ""
					if len(ev.SourceIPs) > 0 {
						srcIP = ev.SourceIPs[0]
					}
					activityTracker.Record(ns, name, srcIP, time.Now())
				}
			}

			kt := notifier.DecoyRef{Namespace: ns, Name: name}
			ctx := context.Background()
			notify.NotifyAuditActivity(ctx, kt, events)
			notify.ShipAuditLog(ctx, kt, events)
		})
		if err := http.ListenAndServe(*auditWebhookAddr, handler); err != nil {
			setupLog.Error(err, "audit-webhook receiver stopped")
		}
	}()

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                server.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress: ":8081",
		LeaderElection:         false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&controller.DecoyReconciler{Client: mgr.GetClient(), ManagerAuditWebhookURL: *managerAuditWebhookURL, Notifier: notify}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Decoy")
		os.Exit(1)
	}

	// The honeypod.io/join MutatingWebhookConfiguration's HTTPS receiver
	// (see internal/controller/join_webhook.go and
	// config/manager/webhook.yaml). mgr.GetClient() is safe to hand to the
	// mutator here even though the manager hasn't Start()ed yet: the
	// client only performs Gets when an actual admission request arrives,
	// which can't happen before the apiserver can even reach this HTTPS
	// listener, by which point mgr.Start() below has long since brought
	// the cache up.
	//
	// The cert itself is fetched/stored via a short retry loop -- on a
	// fresh cluster the honeypod namespace this Secret lives in may
	// not exist yet the instant this process starts.
	dnsNames := append(strings.Split(*joinWebhookDNSNames, ","), "localhost", "127.0.0.1")
	var webhookCert tls.Certificate
	var webhookCAPEM []byte
	certBackoff := wait.Backoff{Duration: time.Second, Factor: 2, Steps: 8, Cap: time.Minute}
	if err := wait.ExponentialBackoff(certBackoff, func() (bool, error) {
		var err error
		webhookCert, webhookCAPEM, err = controller.EnsureWebhookServingCert(context.Background(), directClient, webhookCertNamespace, webhookCertSecretName, dnsNames)
		if err != nil {
			setupLog.Info("join-webhook serving cert not ready yet, retrying", "error", err.Error())
			return false, nil
		}
		return true, nil
	}); err != nil {
		setupLog.Error(err, "giving up ensuring join-webhook serving certificate")
		os.Exit(1)
	}
	// Keep the join webhook's caBundle correct for the manager's whole
	// lifetime. config/manager/webhook.yaml ships an empty placeholder --
	// the real CA doesn't exist until first generated -- so this reconciler
	// both fills it in on its first pass and re-patches it whenever the
	// MutatingWebhookConfiguration is later recreated or its caBundle
	// cleared (a manifest re-apply, a Helm upgrade), which would otherwise
	// silently disable every join until a restart. It watches that one
	// object, so a webhook.yaml applied minutes after this manager starts
	// is picked up too, with no startup-only patch to miss it.
	if err := (&controller.WebhookCABundleReconciler{
		Client:     mgr.GetClient(),
		ConfigName: *joinWebhookConfigName,
		CABundle:   webhookCAPEM,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WebhookCABundle")
		os.Exit(1)
	}

	mutator := &controller.PodJoinMutator{Client: mgr.GetClient()}
	go func() {
		setupLog.Info("starting honeypod.io/join admission webhook", "addr", *joinWebhookAddr)
		srv := &http.Server{
			Addr:      *joinWebhookAddr,
			Handler:   controller.NewPodMutationHandler(mutator),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{webhookCert}},
		}
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			setupLog.Error(err, "join-webhook receiver stopped")
		}
	}()

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// One signal handler shared by the manager and the activity flush loop
	// (SetupSignalHandler panics if called twice).
	signalCtx := ctrl.SetupSignalHandler()

	// Flush attacker-activity counters to Decoy status periodically.
	// Batched rather than per-request so a decoy under active attack does
	// not trigger a status write per API call.
	go activityTracker.Run(signalCtx, 15*time.Second)

	setupLog.Info("starting Honeypod operator")
	if err := mgr.Start(signalCtx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
