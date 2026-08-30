package auditwebhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const samplePayload = `{
  "kind": "EventList",
  "apiVersion": "audit.k8s.io/v1",
  "items": [
    {
      "stage": "RequestReceived",
      "verb": "get",
      "requestURI": "/api/v1/namespaces/billing/secrets/checkout-api-db-credentials",
      "user": {"username": "honeypod:decoy"},
      "objectRef": {"resource": "secrets", "namespace": "billing", "name": "checkout-api-db-credentials"},
      "responseStatus": {"code": 0},
      "requestReceivedTimestamp": "2026-08-25T00:00:00Z"
    },
    {
      "stage": "ResponseComplete",
      "verb": "get",
      "requestURI": "/api/v1/namespaces/billing/secrets/checkout-api-db-credentials",
      "user": {"username": "honeypod:decoy"},
      "objectRef": {"resource": "secrets", "namespace": "billing", "name": "checkout-api-db-credentials"},
      "responseStatus": {"code": 200},
      "requestReceivedTimestamp": "2026-08-25T00:00:00Z"
    }
  ]
}`

// TestHandler_AttributesToDecoyFromURLPath verifies that events posted to
// /audit/{namespace}/{name} are attributed to that Decoy, and that only
// the ResponseComplete stage is forwarded to the BatchFunc -- a real
// kube-apiserver audit webhook running at RequestResponse level sends both
// the RequestReceived and ResponseComplete stage for the same request, and
// forwarding both would double-count every request.
func TestHandler_AttributesToDecoyFromURLPath(t *testing.T) {
	var got []Event
	var gotNS, gotName string
	h := NewHandler(func(namespace, name string, events []Event) {
		gotNS, gotName = namespace, name
		got = events
	})

	req := httptest.NewRequest(http.MethodPost, "/audit/honeypod-decoy/checkout-api-decoy", bytes.NewBufferString(samplePayload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotNS != "honeypod-decoy" || gotName != "checkout-api-decoy" {
		t.Fatalf("expected attribution honeypod-decoy/checkout-api-decoy, got %s/%s", gotNS, gotName)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 ResponseComplete Event forwarded, got %d", len(got))
	}
	if got[0].Verb != "get" || got[0].ResponseStatus.Code != 200 {
		t.Fatalf("unexpected Event: %+v", got[0])
	}
	if got[0].ObjectRef == nil || got[0].ObjectRef.Name != "checkout-api-db-credentials" {
		t.Fatalf("expected objectRef to be preserved, got %+v", got[0].ObjectRef)
	}
}

func TestHandler_RejectsInvalidPayload(t *testing.T) {
	h := NewHandler(func(string, string, []Event) { t.Fatal("fn should not be called for an invalid payload") })
	req := httptest.NewRequest(http.MethodPost, "/audit/ns/name", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

// TestLogEventJSON_ProducesParseableStructuredLine covers the
// --audit-log-format=json path: a log shipper expecting one JSON object
// per line must be able to parse it, and the Decoy attribution has to
// survive alongside the event, not just be prefixed as text.
func TestLogEventJSON_ProducesParseableStructuredLine(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer log.SetOutput(orig)

	ev := Event{
		Stage:      "ResponseComplete",
		Verb:       "get",
		RequestURI: "/api/v1/namespaces/billing/pods/checkout-api",
		ObjectRef:  &ObjectRef{Resource: "pods", Namespace: "billing", Name: "checkout-api"},
	}
	ev.User.Username = "kubernetes-admin"
	ev.ResponseStatus.Code = 200

	LogEventJSON("honeypod-decoy", "checkout-api-decoy", ev)

	var decoded struct {
		DecoyNamespace string `json:"honeypodNamespace"`
		DecoyName      string `json:"honeypodName"`
		Event          Event  `json:"event"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("LogEventJSON's line did not parse as JSON: %v\nline: %s", err, buf.String())
	}
	if decoded.DecoyNamespace != "honeypod-decoy" || decoded.DecoyName != "checkout-api-decoy" {
		t.Fatalf("expected Decoy attribution in the JSON, got %+v", decoded)
	}
	if decoded.Event.User.Username != "kubernetes-admin" || decoded.Event.Verb != "get" {
		t.Fatalf("expected the event fields to survive, got %+v", decoded.Event)
	}
}

// TestFormatLine_IncludesSourceIPAndUserAgent covers the highest-value
// forensic fields a honeypot surfaces: where the attacker connected from
// and what client they used. Both are appended only when present, so an
// event without them (an internal call) stays clean.
func TestFormatLine_IncludesSourceIPAndUserAgent(t *testing.T) {
	ev := Event{Verb: "get", RequestURI: "/api/v1/secrets"}
	ev.User.Username = "kubernetes-admin"
	ev.SourceIPs = []string{"203.0.113.7"}
	ev.UserAgent = "kubectl/v1.35.0 (linux/amd64)"

	line := FormatLine(ev)
	if !strings.Contains(line, "srcIP=203.0.113.7") {
		t.Fatalf("expected the attacker source IP in the line, got: %s", line)
	}
	if !strings.Contains(line, `userAgent="kubectl/v1.35.0 (linux/amd64)"`) {
		t.Fatalf("expected the attacker user-agent in the line, got: %s", line)
	}

	// An internal call with neither must not grow empty fields.
	plain := FormatLine(Event{Verb: "get", RequestURI: "/healthz"})
	if strings.Contains(plain, "srcIP=") || strings.Contains(plain, "userAgent=") {
		t.Fatalf("no srcIP/userAgent fields when absent, got: %s", plain)
	}
}
