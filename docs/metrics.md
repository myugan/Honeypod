# Metrics

The manager serves Prometheus metrics on `:8080` at `/metrics` (change with
`-metrics-bind-address`, disable with `-metrics-bind-address=0`). The port is
named `metrics` on both the controller-manager Deployment and its Service, so
a `ServiceMonitor`/`PodMonitor` or plain scrape config can target it by name.

One endpoint serves two families of metrics: controller-runtime's built-ins
and Honeypod's own `honeypod_*` metrics, registered on the same registry
(`internal/metrics`).

## Honeypod metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `honeypod_phase` | gauge | `namespace`, `name`, `phase` | One-hot phase per Honeypod: the row matching `status.phase` (`Pending`/`Ready`/`Failed`) is 1, the others 0. `sum by (phase)` counts decoys per phase. |
| `honeypod_joined_pods` | gauge | `namespace`, `name` | Real Pods currently mirrored into the decoy via the `honeypod.io/join` annotation. |
| `honeypod_reconcile_errors_total` | counter | `namespace`, `name` | Failed reconciles per Honeypod. The built-in `controller_runtime_reconcile_errors_total` counts the same failures but only per controller; this says *which* decoy is failing. |
| `honeypod_audit_events_received_total` | counter | `namespace`, `name` | Every audit event the manager's audit-webhook receiver got from that Honeypod's inner apiserver, including the decoy's own housekeeping traffic. |
| `honeypod_attacker_requests_total` | counter | `namespace`, `name` | Only notable events: requests under a non-system identity, i.e. someone holding the decoy token. Matches `status.intrusionActivity.requestCount`'s growth. **This is the one to alert on** — any increase means a trap was touched. |
| `honeypod_activity_flush_errors_total` | counter | — | Failed writes of attacker-activity counters to Honeypod status. Retried on the next flush interval, so a nonzero rate means `status.intrusionActivity` is lagging, not lost. |

Series labelled with a Honeypod's `namespace`/`name` are removed when that
Honeypod is deleted, so the endpoint never advertises decoys that no longer
exist.

Note on restarts: `honeypod_attacker_requests_total` is an in-process
counter and resets to zero when the manager restarts (use `rate()`/
`increase()` as usual). The durable running total lives in
`status.intrusionActivity.requestCount`, which survives restarts.

## Useful queries

Alert when any decoy is touched:

```promql
increase(honeypod_attacker_requests_total[5m]) > 0
```

Decoys not Ready:

```promql
honeypod_phase{phase="Ready"} == 0 and ignoring(phase) honeypod_phase{phase="Pending"} == 1
```

Reconcile failures by decoy:

```promql
rate(honeypod_reconcile_errors_total[15m]) > 0
```

## Grafana dashboard

A ready-made dashboard lives at [`docs/grafana-dashboard.json`](grafana-dashboard.json)
(uid `honeypod-operator`). It has an overview row (decoy counts by phase,
attacker requests, joined pods), an attacker-activity row (attacker vs. total
audit rates), an operator-health row (per-decoy reconcile errors, reconcile
latency p50/p90/p99, activity-flush errors), and a per-decoy state table.
`Namespace` and `Honeypod` template variables filter every panel.

Import it:

- **UI** — Dashboards → New → Import → upload the JSON, then pick your
  Prometheus data source when prompted (`DS_PROMETHEUS`).
- **API** —

  ```bash
  curl -sS -H "Authorization: Bearer $GRAFANA_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"dashboard\": $(cat docs/grafana-dashboard.json), \"overwrite\": true}" \
    "$GRAFANA_URL/api/dashboards/db"
  ```

The panels read `honeypod_*` (and `controller_runtime_reconcile_time_seconds`
for the latency panel), so they populate once the manager's `metrics` port is
scraped.

## Controller-runtime built-ins

The same endpoint also serves, among others:

- `controller_runtime_reconcile_total{controller,result}` — reconciles by outcome
- `controller_runtime_reconcile_errors_total{controller}` — reconcile errors per controller
- `controller_runtime_reconcile_time_seconds{controller}` — reconcile latency histogram
- `workqueue_depth{name}` / `workqueue_queue_duration_seconds{name}` — queue backlog and wait time
- standard Go process metrics (`go_*`, `process_*`)
