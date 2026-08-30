# Honeypod: Turn Your Pod into a Kubernetes Decoy

Honeypod is a Kubernetes operator that runs a decoy control plane inside your real cluster and redirects workloads into it. The decoy is a real nested control plane, a genuine `kube-apiserver`, `kube-controller-manager`, and `kube-scheduler` backed by `kine`, seeded with fake Nodes, Pods, and Secrets and reachable only by a token that has zero access to anything real. Anyone who steals a token from a redirected workload gets a fully working `kubectl` against the fake cluster, and every request is recorded in real Kubernetes audit format.

Use it to catch an attacker after a workload is compromised. A stolen ServiceAccount token or a pod breakout lands the attacker in the decoy instead of your cluster, where their every move is attributed and logged. Because the control plane is real, their own `kubectl create deployment` schedules and runs, so nothing about the responses gives the decoy away.

The operator is named Honeypod. The custom resource it manages is the **`Decoy`** (`decoys.honeypod.io`). You typically run one Decoy as a shared trap and redirect many workloads into it.

## Demo

A stolen ServiceAccount token drops an attacker into the decoy. From there they pull cluster-admin, list what look like production secrets, and exec into a pod, and every request is recorded in real Kubernetes audit format. Click the preview to play.

[![An attacker gets caught in the decoy](https://asciinema.org/a/1264214.svg)](https://asciinema.org/a/1264214)

## Quick Start

**Prerequisites:** a Kubernetes cluster whose nodes can pull the `honeypod/*` images, and `kubectl` access. The operator runs in the `honeypod` namespace.

Five steps take you from nothing to a working decoy that records everything an intruder does. Each step is one block you can copy as is.

Prefer to watch first? This is the whole install, end to end, in about a minute. Click the preview to play.

[![Honeypod install walkthrough](https://asciinema.org/a/1264218.svg)](https://asciinema.org/a/1264218)

**1. Install the operator and a ready to use Decoy.** A single manifest installs the controller into the `honeypod` namespace and creates a Decoy named `demo`.

```bash
kubectl apply -f manifests/quickstart.yaml
```

**2. Wait for the controller to come up.**

```bash
kubectl -n honeypod rollout status deploy/honeypod-controller-manager
```

**3. Wait for the Decoy to report `Ready`.** Ready means the decoy control plane is running and reachable.

```bash
kubectl -n honeypod get decoy demo -w
# NAME   PHASE   HITS   LAST-SEEN   AGE
# demo   Ready                      30s
```

**4. Use the decoy the way a compromised workload would.** The endpoint is an in-cluster address, so open a port-forward to reach it from your machine. Then pull the kubeconfig, point its server at the forward, and keep the in-cluster name as the TLS server name.

```bash
kubectl -n honeypod port-forward svc/demo 6443:6443 >/dev/null 2>&1 &

SECRET=$(kubectl -n honeypod get decoy demo -o jsonpath='{.status.credentialsSecret}')
kubectl -n honeypod get secret "$SECRET" -o jsonpath='{.data.kubeconfig}' | base64 -d \
  | sed 's#server: https://demo.honeypod.svc:6443#server: https://127.0.0.1:6443\n    tls-server-name: demo.honeypod.svc#' > decoy.kubeconfig

kubectl --kubeconfig=decoy.kubeconfig auth whoami
kubectl --kubeconfig=decoy.kubeconfig get pods -A
kubectl --kubeconfig=decoy.kubeconfig -n billing exec checkout-api -- id
```

**5. Confirm every call was recorded.** The Decoy's own status shows the hit count, and the controller log carries the full audit trail.

```bash
kubectl -n honeypod get decoy demo
kubectl -n honeypod logs deploy/honeypod-controller-manager | grep audit
```

To tear it all down again, delete the same manifest.

```bash
kubectl delete -f manifests/quickstart.yaml
```

## Usage

### The minimum manifest

Every spec field has a default, so the smallest useful Decoy is one namespace, a name, and a single node for pods to schedule on. With `seedSystemComponents` on by default, `kubectl get pods -A` inside it already looks like a real cluster.

```yaml
apiVersion: honeypod.io/v1alpha1
kind: Decoy
metadata:
  name: demo
  namespace: honeypod
spec:
  fakeNodes:
  - name: node-1
```

### Two ways to populate the decoy

- **Hand author** the inventory with `spec.fakePods` and `spec.fakeSecrets` for objects that exist nowhere real, and `spec.fakeCRDs` for the CRDs a real cluster would run.
- **Join a real workload** by annotating a Pod with `honeypod.io/join`. At creation an admission webhook swaps the pod API address and mounted token for the decoy, so its in-cluster client talks to the honeypot with no code change. The pod is also mirrored into the decoy inventory.

### Redirecting workloads

When you run a single Decoy, `honeypod.io/join: "true"` on a Pod in any namespace relays to it automatically, with credentials mirrored per namespace. With more than one Decoy, give the full target as `"<namespace>/<decoy name>"`, and `"true"` resolves to the sole Decoy in the Pod own namespace. On a Deployment, put the annotation on `spec.template.metadata.annotations` so new pods pick it up.

The redirect only takes effect at pod creation, because a pod environment and volumes are immutable afterward. Annotating a pod that is already running mirrors it into the decoy but leaves its real traffic in place until it is recreated. The `status.joinedPods[].redirected` field tells you which half applied.

### What is real and what is fabricated

- **Real:** `get`, `list`, `create`, `delete`, RBAC, `auth can-i`, `auth whoami`, and `exec`. The real controller-manager and scheduler mean an attacker own Deployment or Job reconciles and its pods schedule and run. The `exec` shell is a genuine sandboxed process, non-root with no capabilities and seccomp on.
- **Fabricated:** `logs` and `attach` come from `spec.fakePods[].logLines`. `port-forward` is not implemented.

## Status and verification

The Decoy status is the fastest way to see whether a trap is up and whether it has been touched.

| Status field | Meaning |
|---|---|
| `phase` | `Pending`, `Ready`, or `Failed`. Becomes `Ready` once the decoy pod has a ready replica. |
| `endpoint` | In-cluster address, `https://<name>.<namespace>.svc:<port>`. |
| `credentialsSecret` | Secret holding the decoy token, CA, TLS keypair, and a ready kubeconfig. |
| `joinedPods[]` | Real pods mirrored in. `redirected: true` means the pod traffic actually goes to the decoy. |
| `intrusionActivity` | `requestCount`, `firstSeen`, `lastSeen`, and `lastSourceIP`, counting only requests made with the decoy token, not the operator housekeeping. |
| `conditions[]` | A `Ready` condition whose reason is the phase, or `ReconcileFailed` on error. |

`kubectl get decoy` surfaces the important bits as columns. Add `-o wide` for the endpoint and secret.

```bash
kubectl -n honeypod get decoy
# NAME   PHASE   HITS   LAST-SEEN   AGE

kubectl -n honeypod get decoy demo -o jsonpath='{.status.intrusionActivity}' | jq .
kubectl -n honeypod describe decoy demo
```

**What happens after you apply a Decoy:** the operator creates one Deployment, Service, ConfigMap, Secret, and NetworkPolicy, all owned by the Decoy. The pod runs `kube-apiserver`, `kine`, the controller-manager and scheduler, and `kubelet-shim`. The NetworkPolicy denies egress except DNS and the audit receiver. When the pod is ready the phase flips to `Ready` and `status.credentialsSecret` is populated. Deleting the Decoy garbage collects everything it created.

## Examples

Hand authored decoy with a bait pod and secret:

```yaml
apiVersion: honeypod.io/v1alpha1
kind: Decoy
metadata:
  name: demo
  namespace: honeypod
spec:
  fakeNodes:
  - name: node-1
  fakePods:
  - name: checkout-api
    namespace: billing
    containers:
    - name: app
      image: internal-registry.example.com/checkout-api:1.4.2
  fakeSecrets:
  - name: checkout-api-db-credentials
    namespace: billing
    data:
      username: checkout_svc
      password: not-a-real-password
```

Redirect a real Deployment into the single decoy:

```yaml
spec:
  template:
    metadata:
      annotations:
        honeypod.io/join: "true"
```

Make the decoy look like it runs cert-manager:

```yaml
spec:
  fakeCRDs:
  - group: cert-manager.io
    kind: Certificate
    plural: certificates
    shortNames: ["cert", "certs"]
```

Durable storage for a long engagement, and a sandboxed exec:

```yaml
spec:
  persistence:
    size: 5Gi
  runtimeClassName: gvisor
  execIsolation: true
```

## Troubleshooting

Common issues and fixes are on their own page: [`docs/troubleshooting.md`](docs/troubleshooting.md).

## Cleanup

```bash
kubectl delete decoy demo -n honeypod
kubectl delete -f manifests/quickstart.yaml
```

Deleting a Decoy removes everything it created. Mirrored credential Secrets in other namespaces are cleaned up by a finalizer.

## More

- [`docs/testing-guide.md`](docs/testing-guide.md) walks the full attacker trapped flow with real command output.
- Alerts and audit shipping use the `Provider`, `Alert`, and `AuditSink` resources. See [`config/samples/`](config/samples/).
- Helm install and values are documented in [`charts/honeypod/README.md`](charts/honeypod/README.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
