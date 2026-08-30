package notifier

import (
	"context"
	"encoding/json"
	"time"

	"honeypod.io/honeypod/internal/auditwebhook"
)

// genericMessage is the envelope posted to a "generic-webhook" Provider for
// a discrete Alert notification (PodJoin, or a formatted AuditActivity
// line).
type genericMessage struct {
	DecoyNamespace string `json:"honeypodNamespace"`
	DecoyName      string `json:"honeypodName"`
	EventType      string `json:"eventType"`
	Message        string `json:"message"`
	Timestamp      string `json:"timestamp"`
}

func (d *Dispatcher) sendGenericMessage(ctx context.Context, address string, kt DecoyRef, eventType, message string) error {
	body, err := json.Marshal(genericMessage{
		DecoyNamespace: kt.Namespace,
		DecoyName:      kt.Name,
		EventType:      eventType,
		Message:        message,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	return d.postJSON(ctx, address, body)
}

// genericAuditBatch is the envelope posted to a "generic-webhook" Provider
// for a batch of raw audit events, from either an AuditActivity Alert or an
// AuditSink -- full structured fidelity, for a custom receiver to interpret.
type genericAuditBatch struct {
	DecoyNamespace string               `json:"honeypodNamespace"`
	DecoyName      string               `json:"honeypodName"`
	Events         []auditwebhook.Event `json:"events"`
}

func (d *Dispatcher) sendGenericAudit(ctx context.Context, address string, kt DecoyRef, events []auditwebhook.Event) error {
	body, err := json.Marshal(genericAuditBatch{
		DecoyNamespace: kt.Namespace,
		DecoyName:      kt.Name,
		Events:         events,
	})
	if err != nil {
		return err
	}
	return d.postJSON(ctx, address, body)
}
