# Testing Honeypod end-to-end

This walks through the full loop: install the operator, stand up a decoy,
act as an attacker who got hold of the decoy token, and confirm every move
is captured. The commands use generic `<name>`/`<pod>` placeholders so they
read the same whichever namespace you test in.

## 1. Install the operator

```bash
kubectl apply -f manifests/install.yaml
kubectl get pods -n honeypod        # wait for the manager to be Running
```

One file installs the four CRDs, RBAC, the manager `Deployment` and its
`Service`, and the `honeypod-pod-join` admission webhook. The manager
patches that webhook's CA bundle at startup, so give the pod a moment to be
Running before joining pods. Your cluster nodes need to be able to pull the
`honeypod/*` images from your registry.

## 2. Stand up a decoy

```bash
kubectl apply -f config/samples/honeypod.yaml
kubectl get decoys -A             # wait for PHASE=Ready
```

A `Decoy` describes what an attacker will see: `spec.fakeNodes`,
`fakePods`, and `fakeSecrets`. Only `fakeNodes` is required (a pod needs a
node to be "scheduled" on). Images and port default. When it reports
`Ready`, the operator has brought up that decoy's own pod. Inside it are a real
`kube-apiserver` backed by `kine` (SQLite, no real etcd) and a `kubelet-shim`,
seeded with the fake objects and reachable only by a decoy token. The
standard `kube-system` control-plane pods are seeded automatically too, so
`kubectl get pods -A` inside the decoy looks like a real cluster. Set
`spec.seedSystemComponents: false` to shape `kube-system` yourself.

## 3. (Optional) Trap a real pod

```bash
kubectl apply -f config/samples/honeypod_joined_pod.yaml
```

Annotating a Pod with `honeypod.io/join: "<Decoy namespace>/<name>"` (or
`"true"` when they share a namespace) does two things. At pod **creation**
the webhook swaps `KUBERNETES_SERVICE_HOST`/`PORT` and the mounted
ServiceAccount token for the decoy's, so anything in the pod using the
standard in-cluster config talks to the honeypot with no code change and no
network redirect. Separately, the pod is mirrored into the decoy's inventory
so an attacker sees it there. `status.joinedPods[]` lists it, with
`redirected` telling which half applied. The redirect needs the pod created
with the annotation (env and volumes are immutable afterward), while
annotating a running pod only mirrors it. On a Deployment, put the
annotation in `spec.template.metadata.annotations` so new pods get both.

## 4. Act as the attacker

The decoy's kubeconfig, which holds the token, CA, and server URL an attacker
would find, lives in the Secret named by `status.credentialsSecret`:

```bash
SECRET=$(kubectl get decoy <name> -o jsonpath='{.status.credentialsSecret}')
kubectl get secret "$SECRET" -o jsonpath='{.data.kubeconfig}' | base64 -d > decoy.kubeconfig

kubectl --kubeconfig=decoy.kubeconfig get pods -A
kubectl --kubeconfig=decoy.kubeconfig auth whoami        # kubernetes-admin / system:masters
kubectl --kubeconfig=decoy.kubeconfig get secret <bait> -o yaml
kubectl --kubeconfig=decoy.kubeconfig exec <pod> -- id   # a real, sandboxed shell
```

Everything here is answered for real by a real `kube-apiserver`, so nothing
about the responses gives the decoy away: `get`/`create`/`delete` are genuine
CRUD against `kine`'s store, RBAC and `auth can-i`/`auth whoami` behave like
a real cluster, and `exec` runs an actual sandboxed shell (non-root, no
capabilities, seccomp, no egress). Only `logs`/`attach` are fabricated, since
a fake pod's image never really runs. There is no path back to the real
cluster from any of it.

## 5. Read the audit trail

```bash
kubectl logs -n honeypod deploy/honeypod-controller-manager | grep audit
```

Every call above appears here, attributed to the exact decoy, produced by
`kube-apiserver`'s own native audit webhook (not a custom sniffer) so it
captures every verb including subresources like `/exec` and `/log`. Each line
carries the attacker's `srcIP` and `userAgent`. Interactive `exec` keystrokes,
meaning what the attacker typed inside a shell and not just the command, are
recorded to the decoy pod's own log:

```bash
kubectl logs <decoy-pod> -n <decoy-ns> -c kubelet-shim | grep '\[honeypod exec\]'
```

For an at-a-glance view of which decoys have been touched, `kubectl get
decoys` shows `HITS` and `LAST-SEEN` columns, and `status.intrusionActivity`
carries the count, first/last seen, and last source IP. To ship alerts or the
full stream elsewhere, see the `Provider`/`Alert`/`AuditSink` samples in
[`config/samples/`](../config/samples/).

## 6. Cleanup

```bash
kubectl delete decoys --all -A            # takes each decoy's resources with it
kubectl delete -f manifests/install.yaml    # only to remove the operator itself
```

Deleting a `Decoy` garbage-collects everything it owns. Mirrored
credential Secrets in other namespaces are cleaned up by a finalizer.
