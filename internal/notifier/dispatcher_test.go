package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/auditwebhook"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := honeypodv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newDispatcher(t *testing.T, objs ...client.Object) *Dispatcher {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	return New(c)
}

func TestNotifyPodJoin_DiscordProvider(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "checkout-api-decoy"}},
		},
	}
	d := newDispatcher(t, provider, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "checkout-api-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if gotBody == nil {
		t.Fatal("expected discord webhook to receive a request")
	}
	var payload discordPayload
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("decoding discord payload: %v", err)
	}
	if len(payload.Embeds) != 1 || !strings.Contains(payload.Embeds[0].Title, "joined") {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestNotifyPodJoin_NonMatchingDecoyIsSkipped(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "some-other-decoy"}},
		},
	}
	d := newDispatcher(t, provider, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "checkout-api-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if called {
		t.Fatal("expected the non-matching alert's provider to never be called")
	}
}

func TestNotifyPodJoin_WildcardDecoyMatches(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, provider, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if !called {
		t.Fatal("expected a wildcard DecoyReference to match any Decoy in its namespace")
	}
}

// TestNotifyPodJoin_EmptyTargetsMatchesSoleDecoy proves an Alert with no
// Targets covers every Decoy -- the single-decoy shape, one Alert for the
// sole decoy without naming it (or its namespace).
func TestNotifyPodJoin_EmptyTargetsMatchesSoleDecoy(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			// no Targets
		},
	}
	d := newDispatcher(t, provider, alert)

	// A decoy in a different namespace than the Alert still matches.
	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "honeypod", Name: "the-decoy"},
		types.NamespacedName{Namespace: "team-a", Name: "bait"}, true)

	if !called {
		t.Fatal("an Alert with empty Targets must match the sole decoy in any namespace")
	}
}

func TestProviderSecretRef_ResolvesAddressFromSecret(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "discord-webhook", Namespace: "ns"},
		Data:       map[string][]byte{"address": []byte(srv.URL)},
	}
	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", SecretRef: &corev1.LocalObjectReference{Name: "discord-webhook"}},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, provider, secret, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if gotBody == nil {
		t.Fatal("expected the secretRef-resolved address to receive a request")
	}
}

// TestProviderRef_SecretRefOverridesProviderSecretRef covers reusing one
// Provider across Alerts that each need a different webhook: an Alert's own
// providerRef.secretRef wins over the Provider's own spec.secretRef.
func TestProviderRef_SecretRefOverridesProviderSecretRef(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wrongSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-webhook", Namespace: "ns"},
		Data:       map[string][]byte{"address": []byte("http://unused.invalid")},
	}
	rightSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "team-b-webhook", Namespace: "ns"},
		Data:       map[string][]byte{"address": []byte(srv.URL)},
	}
	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", SecretRef: &corev1.LocalObjectReference{Name: "team-a-webhook"}},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord", SecretRef: &corev1.LocalObjectReference{Name: "team-b-webhook"}},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, provider, wrongSecret, rightSecret, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if gotBody == nil {
		t.Fatal("expected providerRef.secretRef's address to receive the request, not the Provider's own secretRef")
	}
}

// TestProviderRef_AmbiguousTypeIsAnError covers the failure mode that
// lookup-by-type introduces: two Providers of the same type in one
// namespace can't be disambiguated by providerRef.type alone.
func TestProviderRef_AmbiguousTypeIsAnError(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	providerA := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord-a", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	providerB := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord-b", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, providerA, providerB, alert)

	d.NotifyPodJoin(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"},
		types.NamespacedName{Namespace: "payments", Name: "payments-worker"}, true)

	if called {
		t.Fatal("expected an ambiguous providerRef.type (two matching Providers) to send nothing, not guess")
	}
}

func TestNotifyAuditActivity_FiltersHousekeepingNoise(t *testing.T) {
	var requestCount int
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
			EventTypes:  []honeypodv1alpha1.AlertEventType{honeypodv1alpha1.AlertEventAuditActivity},
		},
	}
	d := newDispatcher(t, provider, alert)

	heartbeat := auditwebhook.Event{Verb: "update", User: struct {
		Username string `json:"username"`
	}{Username: "honeypod:decoy"}}
	heartbeat.ObjectRef = &auditwebhook.ObjectRef{Resource: "pods", Namespace: "billing", Name: "checkout-api", Subresource: "status"}

	execCall := auditwebhook.Event{Verb: "get", User: heartbeat.User}
	execCall.ObjectRef = &auditwebhook.ObjectRef{Resource: "pods", Namespace: "billing", Name: "checkout-api", Subresource: "exec"}

	d.NotifyAuditActivity(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"},
		[]auditwebhook.Event{heartbeat, execCall})

	if requestCount != 1 {
		t.Fatalf("expected exactly 1 discord request (the exec call, not the status heartbeat), got %d", requestCount)
	}
	var payload discordPayload
	if err := json.Unmarshal(lastBody, &payload); err != nil {
		t.Fatalf("decoding discord payload: %v", err)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected exactly 1 embed (the notable exec event), got %d", len(payload.Embeds))
	}
}

func TestNotifyAuditActivity_ExcludeVerbsOverridesBuiltIn(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef:  honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:      []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
			EventTypes:   []honeypodv1alpha1.AlertEventType{honeypodv1alpha1.AlertEventAuditActivity},
			ExcludeVerbs: []string{"get"},
		},
	}
	d := newDispatcher(t, provider, alert)

	execCall := auditwebhook.Event{Verb: "get", User: struct {
		Username string `json:"username"`
	}{Username: "honeypod:decoy"}}
	execCall.ObjectRef = &auditwebhook.ObjectRef{Resource: "pods", Namespace: "billing", Name: "checkout-api", Subresource: "exec"}

	d.NotifyAuditActivity(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"}, []auditwebhook.Event{execCall})

	if requestCount != 0 {
		t.Fatalf("expected ExcludeVerbs=[get] to suppress a normally-notable get/exec event, got %d requests", requestCount)
	}
}

func TestNotifyAuditActivity_IncludeAllSurfacesHeartbeat(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	alert := &honeypodv1alpha1.Alert{
		ObjectMeta: metav1.ObjectMeta{Name: "alert", Namespace: "ns"},
		Spec: honeypodv1alpha1.AlertSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
			EventTypes:  []honeypodv1alpha1.AlertEventType{honeypodv1alpha1.AlertEventAuditActivity},
			IncludeAll:  true,
		},
	}
	d := newDispatcher(t, provider, alert)

	heartbeat := auditwebhook.Event{Verb: "update", User: struct {
		Username string `json:"username"`
	}{Username: "honeypod:decoy"}}
	heartbeat.ObjectRef = &auditwebhook.ObjectRef{Resource: "pods", Namespace: "billing", Name: "checkout-api", Subresource: "status"}

	d.NotifyAuditActivity(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"}, []auditwebhook.Event{heartbeat})

	if requestCount != 1 {
		t.Fatalf("expected IncludeAll=true to surface a normally-suppressed status heartbeat, got %d requests", requestCount)
	}
}

func TestShipAuditLog_LokiProvider(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "loki", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "loki", Address: srv.URL},
	}
	sink := &honeypodv1alpha1.AuditSink{
		ObjectMeta: metav1.ObjectMeta{Name: "sink", Namespace: "ns"},
		Spec: honeypodv1alpha1.AuditSinkSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "loki"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, provider, sink)

	events := []auditwebhook.Event{{Verb: "get"}, {Verb: "update"}}
	d.ShipAuditLog(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"}, events)

	if gotBody == nil {
		t.Fatal("expected the loki push endpoint to receive a request")
	}
	var payload lokiPushRequest
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("decoding loki payload: %v", err)
	}
	if len(payload.Streams) != 1 || len(payload.Streams[0].Values) != 2 {
		t.Fatalf("expected 1 stream with 2 values (unfiltered), got %+v", payload)
	}
}

func TestShipAuditLog_DiscordProviderRejected(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := &honeypodv1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "discord", Namespace: "ns"},
		Spec:       honeypodv1alpha1.ProviderSpec{Type: "discord", Address: srv.URL},
	}
	sink := &honeypodv1alpha1.AuditSink{
		ObjectMeta: metav1.ObjectMeta{Name: "sink", Namespace: "ns"},
		Spec: honeypodv1alpha1.AuditSinkSpec{
			ProviderRef: honeypodv1alpha1.ProviderReference{Type: "discord"},
			Targets:     []honeypodv1alpha1.DecoyTarget{{Name: "*"}},
		},
	}
	d := newDispatcher(t, provider, sink)

	d.ShipAuditLog(context.Background(), DecoyRef{Namespace: "ns", Name: "any-decoy"}, []auditwebhook.Event{{Verb: "get"}})

	if called {
		t.Fatal("expected a discord Provider to be rejected for AuditSink, never called")
	}
}

// TestAuditEmbed_IsReadable covers the Discord audit embed shape: instead of
// one dense key=value line, it must be structured labeled fields, with the
// attacker's source IP and client surfaced as their own fields.
func TestAuditEmbed_IsReadable(t *testing.T) {
	ev := auditwebhook.Event{
		Verb:       "get",
		RequestURI: "/api/v1/namespaces/web/secrets/httpbin-basic-auth",
		ObjectRef:  &auditwebhook.ObjectRef{Resource: "secrets", Namespace: "web", Name: "httpbin-basic-auth"},
		SourceIPs:  []string{"203.0.113.7"},
		UserAgent:  "kubectl/v1.35.0 (linux/amd64)",
	}
	ev.User.Username = "kubernetes-admin"
	ev.ResponseStatus.Code = 200

	embed := auditEmbed(DecoyRef{Namespace: "honeypod-decoy", Name: "httpbin-decoy"}, ev, "2026-08-26T00:00:00Z")

	if !strings.Contains(embed.Title, "httpbin-decoy") {
		t.Fatalf("title should name the decoy, got %q", embed.Title)
	}
	got := map[string]string{}
	for _, f := range embed.Fields {
		if f.Value == "" {
			t.Fatalf("field %q has an empty value (Discord rejects those)", f.Name)
		}
		got[f.Name] = f.Value
	}
	for _, name := range []string{"Verb", "Status", "Identity", "Object", "Name", "Source IP", "Client"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("expected a %q field, got fields %+v", name, embed.Fields)
		}
	}
	if !strings.Contains(got["Source IP"], "203.0.113.7") {
		t.Fatalf("Source IP field must carry the attacker IP, got %q", got["Source IP"])
	}
	if got["Object"] != "`secrets`" {
		t.Fatalf("Object should be the resource type, got %q", got["Object"])
	}
	if !strings.Contains(got["Name"], "httpbin-basic-auth") {
		t.Fatalf("Name field should carry the object name, got %q", got["Name"])
	}
	if _, ok := got["Namespace"]; !ok {
		t.Fatalf("a namespaced event must carry a Namespace field, got %+v", embed.Fields)
	}
	if !strings.Contains(got["Namespace"], "web") {
		t.Fatalf("Namespace field must name the namespace, got %q", got["Namespace"])
	}

	// A cluster-scoped event (nodes) has no namespace, so no Namespace field.
	clusterEv := auditwebhook.Event{Verb: "list", ObjectRef: &auditwebhook.ObjectRef{Resource: "nodes"}}
	clusterEv.User.Username = "kubernetes-admin"
	clusterEmbed := auditEmbed(DecoyRef{Namespace: "kt", Name: "d"}, clusterEv, "2026-08-26T00:00:00Z")
	for _, f := range clusterEmbed.Fields {
		if f.Name == "Namespace" {
			t.Fatalf("a cluster-scoped event must have no Namespace field, got %+v", clusterEmbed.Fields)
		}
		if f.Name == "Name" {
			t.Fatalf("a nameless (list) event must have no Name field, got %+v", clusterEmbed.Fields)
		}
	}
}

// TestPodJoinEmbed_IsReadable covers the structured PodJoin embed: a clear
// title for join vs leave, and Pod/Namespace/Decoy as labeled fields rather
// than one flat sentence.
func TestPodJoinEmbed_IsReadable(t *testing.T) {
	pod := types.NamespacedName{Namespace: "default", Name: "payments-worker"}
	kt := DecoyRef{Namespace: "default", Name: "httpbin-decoy"}

	joined := podJoinEmbed(kt, pod, true, "2026-08-27T00:00:00Z")
	if !strings.Contains(joined.Title, "joined") {
		t.Fatalf("join embed title should say joined, got %q", joined.Title)
	}
	got := map[string]string{}
	for _, f := range joined.Fields {
		if f.Value == "" {
			t.Fatalf("field %q empty (Discord rejects those)", f.Name)
		}
		got[f.Name] = f.Value
	}
	for _, name := range []string{"Pod", "Namespace", "Decoy"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("expected a %q field, got %+v", name, joined.Fields)
		}
	}
	if !strings.Contains(got["Pod"], "payments-worker") || !strings.Contains(got["Decoy"], "httpbin-decoy") {
		t.Fatalf("fields should carry pod and decoy, got %+v", got)
	}

	left := podJoinEmbed(kt, pod, false, "2026-08-27T00:00:00Z")
	if !strings.Contains(left.Title, "left") || left.Color != colorLeft {
		t.Fatalf("leave embed should say left with the grey color, got %q / %d", left.Title, left.Color)
	}
}
