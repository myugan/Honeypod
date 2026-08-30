# Architecture: one rich decoy, not many

## Decision

Honeypod is deployed as a **single, high-interaction decoy** — one nested
Kubernetes control plane made as deep and convincing as possible — rather than
many small decoys. This is the default and recommended shape.

The operator still supports multiple `Honeypod` custom resources, but running a
fleet of them is intentionally *not* the target design; see "When to revisit".

## Why single

- **An attacker judges one cluster at a time.** They find a leaked
  token/kubeconfig and probe *a* cluster. One deep, believable cluster is
  exactly what they expect; they never see a "fleet".
- **The value is depth, not count.** Everything that makes a decoy convincing
  is per-cluster realism: the real kube-apiserver (backed by kine), the real
  kube-controller-manager and kube-scheduler, seeded kube-system pods, CRDs,
  the kubelet stats API, exec profiles, node leases, audit + alerts. Invest
  there.
- **Cheapest and simplest.** One control plane is ~0.5 GiB RSS and needs no
  scaling machinery — no sharding, no activator, no cross-tenant isolation
  layer.

## Resource cost of one decoy

One decoy pod runs five containers:

| container | approx idle RSS |
|---|---|
| kube-apiserver | 200–400 MiB |
| kube-controller-manager | 50–100 MiB |
| kube-scheduler | 30–50 MiB |
| kine | 20–40 MiB |
| kubelet-shim | 20–40 MiB |
| **total** | **~0.4–0.6 GiB idle** |

This is a fixed, one-time cost regardless of how much bait points at it.

## Many baits, one decoy

You do not need many decoys to plant bait in many places. Run **one** Honeypod
and scatter its kubeconfig/token wherever a decoy should be discovered (fake
apps, repos, object storage, environment variables, CI logs). Every bait leads
to the same decoy.

When exactly one Honeypod exists, the operator relays to it automatically, no
naming required:

- `honeypod.io/join: "true"` on a pod in **any** namespace redirects that pod
  to the sole decoy (with cross-namespace credentials mirrored for you); only
  when more than one Honeypod exists does `"true"` fall back to "the single
  Honeypod in the pod's own namespace".
- an `Alert` or `AuditSink` with **no `targets`** covers the sole decoy in any
  namespace; list explicit `targets` only when you run more than one.

You still get **per-source attribution** for free:

- the audit stream and `status.intrusionActivity` record source IP, user agent,
  and the identity used;
- `Alert` / `AuditSink` fan those out to Discord / Loki / a webhook;
- pods redirected via the `honeypod.io/join` annotation are tracked
  individually in `status.joinedPods`.

So "which bait was taken" is answerable by source/identity, not by needing a
separate cluster per bait.

## Why not centralize many decoys into one shared apiserver

Collapsing many logical decoys into a single shared apiserver (a
vcluster/kcp-style multi-tenant model) is explicitly rejected:

- If every attacker gets `system:masters` (as a real decoy token does), they
  all see every other tenant's namespaces and secrets — engagements
  cross-contaminate, and `kubectl get ns -A` reveals a multi-tenant fake.
- If each attacker instead gets a namespace-scoped, RBAC-limited token, then
  `kubectl auth whoami` / `can-i --list` / `get nodes` expose a restricted
  viewer — which destroys the "I found an admin token, I own a cluster" lure
  and reads as a shared namespace, not a cluster.
- Single-apiserver RBAC is not a hard isolation boundary between adversarial
  tenants anyway (cluster-scoped discovery, CRDs, node names, event leakage,
  escalation paths).

Shared-apiserver isolation is both weaker and less convincing, so it is not a
supported model.

## When to revisit (many independent decoys)

Only build multi-decoy scaling if you have a concrete need for **per-engagement
isolation** — distinct operations where one attacker must be sandboxed from
another's bait and data. In that case the right approach is **scale-to-zero**,
not a shared apiserver:

- keep each `Honeypod` CR + Service + credentials always present, but do not run
  the decoy pod until an attacker first connects;
- spin the Deployment up on the first connection and scale it back down after
  an idle period.

This keeps every active decoy fully isolated (its own real apiserver + token)
while idle decoys cost ~0, so the memory scales with *active* decoys, not
*total* decoys. The audit-webhook and activity signals already provide the
"this decoy is being touched" trigger. Until that need is real, prefer one
rich decoy.
