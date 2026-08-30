// Package auditwebhook implements the operator's --audit-webhook-config-file
// receiver: an HTTP endpoint each Decoy's inner kube-apiserver is
// configured to POST its real audit.k8s.io/v1 events to. Events arriving
// here are produced by a real kube-apiserver, not synthesized by our own
// request-handling code.
//
// This is deliberately simple: log what arrived, attributed to which
// Decoy it came from, to stdout (verifiable via `kubectl logs` on the
// operator). It is not a database or an external shipping pipeline -- "for
// monitoring and analysis" here means "an operator watching the manager's
// logs can see it," not a full observability stack.
package auditwebhook

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// ObjectRef identifies the object an audit event acted on. Named rather
// than inlined so callers can pass one around, which the notability filter
// in internal/notifier needs to do.
type ObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	Subresource string `json:"subresource"`
}

// Event is the subset of the audit.k8s.io/v1 Event schema this handler
// cares about. A minimal local type is used here (rather than importing
// k8s.io/apiserver's audit types) to keep this package's only dependency on
// the wire format, not a heavy apiserver-internals package.
type Event struct {
	Stage      string `json:"stage"`
	Verb       string `json:"verb"`
	RequestURI string `json:"requestURI"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	ObjectRef      *ObjectRef `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp string `json:"requestReceivedTimestamp"`

	// SourceIPs and UserAgent are the attacker's own network origin and
	// client string, kept because they are the most useful forensic fields
	// a honeypot can hand an operator: where the intruder connected from
	// and what tool they used. Both come straight from the real
	// kube-apiserver's RequestResponse-level audit event.
	SourceIPs []string `json:"sourceIPs,omitempty"`
	UserAgent string   `json:"userAgent,omitempty"`
}

type eventList struct {
	Items []Event `json:"items"`
}

// BatchFunc is called once per received audit-webhook HTTP request, with
// every ResponseComplete-stage event it carried, attributed to the Decoy
// (namespace, name) whose inner apiserver sent them. One call per request
// (rather than per event) lets a caller -- e.g. internal/notifier -- ship a
// batch as a single downstream request instead of one per k8s audit event.
type BatchFunc func(namespace, name string, events []Event)

// NewHandler builds the audit-webhook HTTP handler. Requests are expected
// at /audit/{namespace}/{name} -- the operator renders each Decoy's
// --audit-webhook-config-file kubeconfig with that Decoy's own
// namespace/name baked into the server URL (see
// internal/controller/render.go's renderAuditWebhookKubeconfig), so a
// single shared receiver in the manager process can attribute every event
// to the right Decoy with no extra correlation step.
func NewHandler(fn BatchFunc) http.Handler {
	if fn == nil {
		fn = logBatch
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /audit/{namespace}/{name}", func(w http.ResponseWriter, r *http.Request) {
		ns, name := r.PathValue("namespace"), r.PathValue("name")

		var list eventList
		if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
			http.Error(w, "invalid audit event payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Only ResponseComplete events carry a response status and are what
		// a real audit log ships by default at RequestResponse level's
		// terminal stage; RequestReceived duplicates are skipped to avoid
		// double-counting the same request.
		events := make([]Event, 0, len(list.Items))
		for _, ev := range list.Items {
			if ev.Stage != "" && ev.Stage != "ResponseComplete" {
				continue
			}
			events = append(events, ev)
		}
		if len(events) > 0 {
			fn(ns, name, events)
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func logBatch(namespace, name string, events []Event) {
	for _, ev := range events {
		LogEvent(namespace, name, ev)
	}
}

// LogEvent writes ev to stdout in the operator's standard audit-log line
// format.
func LogEvent(namespace, name string, ev Event) {
	log.Printf("[honeypod audit] honeypod=%s/%s %s", namespace, name, FormatLine(ev))
}

// LogEventJSON is LogEvent's --log-format=json counterpart: one line of
// JSON per event instead of the key=value form, for a log shipper that
// expects structured lines rather than a format it has to parse itself.
func LogEventJSON(namespace, name string, ev Event) {
	b, err := json.Marshal(jsonLine{
		DecoyNamespace: namespace,
		DecoyName:      name,
		Event:          ev,
	})
	if err != nil {
		// Never drop the event over a marshal failure -- fall back to the
		// same line LogEvent would have printed.
		log.Printf("[honeypod audit] honeypod=%s/%s %s", namespace, name, FormatLine(ev))
		return
	}
	log.Print(string(b))
}

type jsonLine struct {
	DecoyNamespace string `json:"honeypodNamespace"`
	DecoyName      string `json:"honeypodName"`
	Event          Event  `json:"event"`
}

// FormatLine renders ev as the single-line "key=value" form used for the
// operator's own stdout log, and reused by internal/notifier so a Loki
// AuditSink and a Discord AuditActivity alert describe an event identically.
func FormatLine(ev Event) string {
	resource := ""
	if ev.ObjectRef != nil {
		resource = ev.ObjectRef.Resource
		if ev.ObjectRef.Namespace != "" {
			resource += " " + ev.ObjectRef.Namespace + "/" + ev.ObjectRef.Name
		} else if ev.ObjectRef.Name != "" {
			resource += " " + ev.ObjectRef.Name
		}
		if ev.ObjectRef.Subresource != "" {
			resource += "/" + ev.ObjectRef.Subresource
		}
	}
	line := fmt.Sprintf("verb=%s user=%s resource=%q status=%d uri=%s",
		ev.Verb, ev.User.Username, strings.TrimSpace(resource), ev.ResponseStatus.Code, ev.RequestURI)
	if len(ev.SourceIPs) > 0 {
		line += " srcIP=" + strings.Join(ev.SourceIPs, ",")
	}
	if ev.UserAgent != "" {
		line += fmt.Sprintf(" userAgent=%q", ev.UserAgent)
	}
	return line + " ts=" + ev.RequestReceivedTimestamp
}
