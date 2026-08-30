# Decoy spec reference

Only the fields most users set are listed. See `kubectl explain decoy.spec` for the rest.

| Field | Type | Default | Description |
|---|---|---|---|
| `fakeNodes[]` | list | none | Nodes an attacker sees. A fake pod needs one to schedule on. |
| `fakePods[]` | list | none | Pods an attacker sees, for objects that exist nowhere real. |
| `fakeSecrets[]` | list | none | Bait Secrets. Use believable but worthless values, never real credentials. |
| `fakeCRDs[]` | list | none | Extra CustomResourceDefinitions to install, so `kubectl get crds` lists the operators a real cluster would run. |
| `seedSystemComponents` | bool | `true` | Auto add the standard kube-system pods, Services, and ConfigMaps so the decoy looks like a real cluster. Set `false` to declare kube-system yourself. |
| `execProfile` | enum | `shell` | Environment a `kubectl exec` presents: `shell` (full /bin/sh), `minimal` (busybox), or `distroless` (no shell, exec fails like a distroless image). |
| `execIsolation` | bool | `false` | Give each exec session its own PID, mount, and UTS namespace. Needs `CAP_SYS_ADMIN`, so pair it with `runtimeClassName`. |
| `runtimeClassName` | string | none | Run the decoy pod under a sandboxed runtime such as `gvisor`. Must already exist in the cluster. |
| `persistence` | object | ephemeral | Back the decoy storage with a PersistentVolumeClaim so its state survives a pod reschedule. |
| `kubernetesVersion` | string | `v1.35.0` | Version the decoy claims. Picks the control-plane images and the node versions. |
| `sans[]` | list | none | Extra DNS names or IPs on the decoy TLS certificate, for example `kubernetes.default.svc`. |
| `resources` | object | small | Resource requests and limits for the decoy pod. |
| `port` | int | `6443` | Port the Service exposes to decoy clients. |
| `kubeAPIServerImage`, `kineImage`, `kubeletShimImage` | string | upstream | Image overrides for a private registry or a custom build. |

**`fakeNodes[]`** takes `name` (required), and optional `internalIP` and `kubeletVersion`. Give one node a lower `kubeletVersion` to mimic a cluster mid upgrade.

**`fakePods[]`** takes `name`, `namespace`, and `containers[]` (each with `name` and `image`). Optional `replicas` (default 1), `nodeName` (must match a `fakeNodes` entry, defaults to the first), `logLines`, and `labels`.

**`fakeSecrets[]`** takes `name`, `namespace`, and a `data` map of string values.

**`fakeCRDs[]`** takes `group`, `kind`, and `plural`, with optional `singular`, `shortNames`, `versions` (default `["v1"]`), and `scope` (`Namespaced` or `Cluster`).

