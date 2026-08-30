package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	"honeypod.io/honeypod/internal/auditwebhook"
)

const discordEmbedsPerMessage = 10 // Discord's own limit per message

const (
	colorJoined = 0x2ecc71 // green
	colorLeft   = 0x95a5a6 // grey
	colorAudit  = 0xe67e22 // amber
)

type discordEmbed struct {
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
	Fields      []discordField `json:"fields,omitempty"`
}

// discordField is one labeled row in an embed. inline=true packs several
// side by side, which reads far better than one dense key=value line.
type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds,omitempty"`
}

// podJoinEmbed renders a pod join/leave as a readable Discord embed: a
// clear title saying what happened, and labeled fields for the pod, its
// namespace, the decoy it joined, and whether its own traffic is actually
// redirected (the join annotation mirrors a pod immediately, but only
// redirects it at pod creation -- see status.joinedPods[].redirected).
func podJoinEmbed(kt DecoyRef, pod types.NamespacedName, joined bool, ts string) discordEmbed {
	title, color := "🪤 Pod joined a decoy", colorJoined
	if !joined {
		title, color = "🔌 Pod left a decoy", colorLeft
	}
	return discordEmbed{
		Title:     title,
		Color:     color,
		Timestamp: ts,
		Fields: []discordField{
			{Name: "Pod", Value: codeOrDash(pod.Name), Inline: true},
			{Name: "Namespace", Value: codeOrDash(pod.Namespace), Inline: true},
			{Name: "Decoy", Value: codeOrDash(kt.Namespace + "/" + kt.Name), Inline: false},
		},
	}
}

// auditEmbed renders one audit event as a readable Discord embed: a title
// naming the decoy and the action, and labeled fields for verb, identity,
// resource, status, and -- the reason a honeypot exists -- where the
// attacker connected from and what client they used.
func auditEmbed(kt DecoyRef, ev auditwebhook.Event, ts string) discordEmbed {
	// Object is the resource type (plus subresource, e.g. "pods/exec");
	// Name and Namespace get their own fields, each shown only when the
	// event actually has one. A cluster-scoped action (get nodes) has no
	// namespace; a collection request (list secrets) has no single name.
	namespace, name := "", ""
	object := ev.RequestURI
	if ev.ObjectRef != nil {
		namespace = ev.ObjectRef.Namespace
		name = ev.ObjectRef.Name
		object = strings.TrimSpace(ev.ObjectRef.Resource)
		if ev.ObjectRef.Subresource != "" {
			object += "/" + ev.ObjectRef.Subresource
		}
	}

	fields := []discordField{
		{Name: "Verb", Value: codeOrDash(ev.Verb), Inline: true},
		{Name: "Status", Value: codeOrDash(fmt.Sprintf("%d", ev.ResponseStatus.Code)), Inline: true},
		{Name: "Identity", Value: codeOrDash(ev.User.Username), Inline: true},
	}
	if namespace != "" {
		fields = append(fields, discordField{Name: "Namespace", Value: codeOrDash(namespace), Inline: true})
	}
	fields = append(fields, discordField{Name: "Object", Value: codeOrDash(object), Inline: true})
	if name != "" {
		fields = append(fields, discordField{Name: "Name", Value: codeOrDash(name), Inline: true})
	}
	if len(ev.SourceIPs) > 0 {
		fields = append(fields, discordField{Name: "Source IP", Value: codeOrDash(strings.Join(ev.SourceIPs, ", ")), Inline: true})
	}
	if ev.UserAgent != "" {
		fields = append(fields, discordField{Name: "Client", Value: codeOrDash(ev.UserAgent), Inline: true})
	}

	return discordEmbed{
		Title:     fmt.Sprintf("🚨 Attacker activity · %s/%s", kt.Namespace, kt.Name),
		Color:     colorAudit,
		Timestamp: ts,
		Fields:    fields,
	}
}

// codeOrDash wraps v in Discord inline-code backticks, or returns an em dash
// for an empty value so a field never renders blank (Discord rejects an
// empty field value).
func codeOrDash(v string) string {
	if v == "" {
		return "—"
	}
	if len(v) > 1000 {
		v = v[:1000] + "…"
	}
	return "`" + v + "`"
}

// sendDiscord posts embeds to a Discord webhook address, chunked to
// discordEmbedsPerMessage per request.
func (d *Dispatcher) sendDiscord(ctx context.Context, address string, embeds []discordEmbed) error {
	for i := 0; i < len(embeds); i += discordEmbedsPerMessage {
		end := i + discordEmbedsPerMessage
		if end > len(embeds) {
			end = len(embeds)
		}
		body, err := json.Marshal(discordPayload{Embeds: embeds[i:end]})
		if err != nil {
			return err
		}
		if err := d.postJSON(ctx, address, body); err != nil {
			return err
		}
	}
	return nil
}
