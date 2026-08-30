// Package notifier sends Decoy events -- a Pod joining/leaving via
// honeypod.io/join, notable audit activity, and (for AuditSink) the full
// raw audit stream -- to Providers (Discord, Loki, or a generic webhook)
// declared as Alert/AuditSink/Provider objects. Nothing here reconciles
// those objects; Dispatcher reads them fresh on every call.
package notifier

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	honeypodv1alpha1 "honeypod.io/honeypod/api/v1alpha1"
	"honeypod.io/honeypod/internal/auditwebhook"
)

// DecoyRef identifies which Decoy an event is about.
type DecoyRef struct {
	Namespace string
	Name      string
}

// Dispatcher looks up Alert/AuditSink/Provider objects and sends to them.
type Dispatcher struct {
	Client     client.Client
	HTTPClient *http.Client
}

// New builds a Dispatcher with a default HTTP client timeout.
func New(c client.Client) *Dispatcher {
	return &Dispatcher{Client: c, HTTPClient: &http.Client{Timeout: 10 * time.Second}}
}

// NotifyPodJoin notifies every matching Alert that pod joined (or left)
// kt via the honeypod.io/join annotation.
func (d *Dispatcher) NotifyPodJoin(ctx context.Context, kt DecoyRef, pod types.NamespacedName, joined bool) {
	var list honeypodv1alpha1.AlertList
	if err := d.Client.List(ctx, &list); err != nil {
		log.Printf("notifier: listing alerts: %v", err)
		return
	}
	action := "joined"
	if !joined {
		action = "left"
	}
	message := fmt.Sprintf("pod %s/%s %s Decoy %s/%s", pod.Namespace, pod.Name, action, kt.Namespace, kt.Name)

	for _, a := range list.Items {
		if !wantsEventType(a.Spec.EventTypes, honeypodv1alpha1.AlertEventPodJoin) {
			continue
		}
		if !anyDecoyMatches(a.Spec.Targets, a.Namespace, kt) {
			continue
		}
		if err := d.sendPodJoinAlert(ctx, a, kt, pod, joined, message); err != nil {
			log.Printf("notifier: alert %s/%s: %v", a.Namespace, a.Name, err)
		}
	}
}

// sendPodJoinAlert delivers a pod join/leave: a structured embed for
// Discord, and the flat message for a generic webhook.
func (d *Dispatcher) sendPodJoinAlert(ctx context.Context, a honeypodv1alpha1.Alert, kt DecoyRef, pod types.NamespacedName, joined bool, message string) error {
	p, address, err := d.resolveProvider(ctx, a.Namespace, a.Spec.ProviderRef)
	if err != nil {
		return err
	}
	switch p.Spec.Type {
	case "discord":
		ts := time.Now().UTC().Format(time.RFC3339)
		return d.sendDiscord(ctx, address, []discordEmbed{podJoinEmbed(kt, pod, joined, ts)})
	case "generic-webhook":
		return d.sendGenericMessage(ctx, address, kt, "PodJoin", message)
	default:
		return fmt.Errorf("provider type %q not supported for a PodJoin alert (use discord or generic-webhook)", p.Spec.Type)
	}
}

// NotifyAuditActivity notifies every matching Alert about the events in
// events that are notable under that Alert's own AuditFilter (see
// IsNotableAuditEvent) -- each Alert filters independently, since
// ExcludeVerbs/ExcludeResources/IncludeAll can differ per Alert.
func (d *Dispatcher) NotifyAuditActivity(ctx context.Context, kt DecoyRef, events []auditwebhook.Event) {
	var list honeypodv1alpha1.AlertList
	if err := d.Client.List(ctx, &list); err != nil {
		log.Printf("notifier: listing alerts: %v", err)
		return
	}
	for _, a := range list.Items {
		if !wantsEventType(a.Spec.EventTypes, honeypodv1alpha1.AlertEventAuditActivity) {
			continue
		}
		if !anyDecoyMatches(a.Spec.Targets, a.Namespace, kt) {
			continue
		}
		filter := FilterFromAlertSpec(a.Spec)
		var notable []auditwebhook.Event
		for _, ev := range events {
			if IsNotableAuditEvent(ev, filter) {
				notable = append(notable, ev)
			}
		}
		if len(notable) == 0 {
			continue
		}
		if err := d.sendAlertAudit(ctx, a, kt, notable); err != nil {
			log.Printf("notifier: alert %s/%s: %v", a.Namespace, a.Name, err)
		}
	}
}

// ShipAuditLog ships every event in events, unfiltered, to every matching
// AuditSink.
func (d *Dispatcher) ShipAuditLog(ctx context.Context, kt DecoyRef, events []auditwebhook.Event) {
	if len(events) == 0 {
		return
	}
	var list honeypodv1alpha1.AuditSinkList
	if err := d.Client.List(ctx, &list); err != nil {
		log.Printf("notifier: listing auditsinks: %v", err)
		return
	}
	for _, s := range list.Items {
		if !anyDecoyMatches(s.Spec.Targets, s.Namespace, kt) {
			continue
		}
		if err := d.shipToSink(ctx, s, kt, events); err != nil {
			log.Printf("notifier: auditsink %s/%s: %v", s.Namespace, s.Name, err)
		}
	}
}

func (d *Dispatcher) sendAlertAudit(ctx context.Context, a honeypodv1alpha1.Alert, kt DecoyRef, events []auditwebhook.Event) error {
	p, address, err := d.resolveProvider(ctx, a.Namespace, a.Spec.ProviderRef)
	if err != nil {
		return err
	}
	switch p.Spec.Type {
	case "discord":
		embeds := make([]discordEmbed, len(events))
		ts := time.Now().UTC().Format(time.RFC3339)
		for i, ev := range events {
			embeds[i] = auditEmbed(kt, ev, ts)
		}
		return d.sendDiscord(ctx, address, embeds)
	case "generic-webhook":
		return d.sendGenericAudit(ctx, address, kt, events)
	default:
		return fmt.Errorf("provider type %q not supported for an AuditActivity alert (use discord or generic-webhook)", p.Spec.Type)
	}
}

func (d *Dispatcher) shipToSink(ctx context.Context, s honeypodv1alpha1.AuditSink, kt DecoyRef, events []auditwebhook.Event) error {
	p, address, err := d.resolveProvider(ctx, s.Namespace, s.Spec.ProviderRef)
	if err != nil {
		return err
	}
	switch p.Spec.Type {
	case "loki":
		lines := make([]string, len(events))
		for i, ev := range events {
			lines[i] = auditwebhook.FormatLine(ev)
		}
		labels := map[string]string{
			"job":                "honeypod-audit",
			"honeypod_namespace": kt.Namespace,
			"honeypod_name":      kt.Name,
		}
		return d.sendLoki(ctx, address, labels, lines)
	case "generic-webhook":
		return d.sendGenericAudit(ctx, address, kt, events)
	default:
		return fmt.Errorf("provider type %q not supported for AuditSink (use loki or generic-webhook)", p.Spec.Type)
	}
}

// resolveProvider finds the one Provider of ref.Type in namespace (the same
// namespace as the Alert/AuditSink referencing it) and its destination
// address. ref.SecretRef, if set, overrides the Provider's own
// spec.secretRef -- lets one Provider be reused with a different Secret
// per Alert/AuditSink.
func (d *Dispatcher) resolveProvider(ctx context.Context, namespace string, ref honeypodv1alpha1.ProviderReference) (provider *honeypodv1alpha1.Provider, address string, err error) {
	var list honeypodv1alpha1.ProviderList
	if err := d.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, "", fmt.Errorf("listing providers in %s: %w", namespace, err)
	}
	var matches []honeypodv1alpha1.Provider
	for _, p := range list.Items {
		if p.Spec.Type == ref.Type {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("no provider of type %q found in namespace %s", ref.Type, namespace)
	}
	if len(matches) > 1 {
		return nil, "", fmt.Errorf("multiple providers of type %q found in namespace %s, expected exactly one", ref.Type, namespace)
	}
	p := matches[0]

	secretRef := ref.SecretRef
	if secretRef == nil {
		secretRef = p.Spec.SecretRef
	}
	if secretRef != nil {
		var sec corev1.Secret
		if err := d.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretRef.Name}, &sec); err != nil {
			return nil, "", fmt.Errorf("getting provider %s/%s secret %q: %w", namespace, p.Name, secretRef.Name, err)
		}
		return &p, string(sec.Data["address"]), nil
	}
	if p.Spec.Address != "" {
		return &p, p.Spec.Address, nil
	}
	return nil, "", fmt.Errorf("provider %s/%s has no address: set providerRef.secretRef, spec.secretRef, or spec.address", namespace, p.Name)
}

func anyDecoyMatches(targets []honeypodv1alpha1.DecoyTarget, ownerNamespace string, kt DecoyRef) bool {
	// No targets means "every Decoy" -- one Alert/AuditSink covers the sole
	// decoy in a single-decoy deployment without naming it.
	if len(targets) == 0 {
		return true
	}
	for _, t := range targets {
		ns := t.Namespace
		if ns == "" {
			ns = ownerNamespace
		}
		if ns != kt.Namespace {
			continue
		}
		if t.Name == "*" || t.Name == kt.Name {
			return true
		}
	}
	return false
}

func wantsEventType(eventTypes []honeypodv1alpha1.AlertEventType, want honeypodv1alpha1.AlertEventType) bool {
	if len(eventTypes) == 0 {
		return true // no explicit list -- default to every event type
	}
	for _, t := range eventTypes {
		if t == want {
			return true
		}
	}
	return false
}
