# Honeypod Helm chart

Installs the Honeypod operator: the CRDs, RBAC, the manager Deployment, its
Services, and the pod-join admission webhook.

```bash
helm install honeypod ./charts/honeypod -n honeypod --create-namespace
```

## Namespace

The operator is pinned to the `honeypod` namespace. The decoy
NetworkPolicy egress and audit routing derive from it at the operator's build
time, so installing elsewhere silently breaks audit delivery. Always install
into `honeypod`.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `honeypod/manager` | Manager image. |
| `image.tag` | chart `appVersion` | Image tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | For a private registry. |
| `replicaCount` | `1` | |
| `resources` | 50m/64Mi .. 500m/256Mi | Manager container resources. |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | Defaults to the release fullname. |
| `podSecurityContext` | non-root, uid 65532 | |
| `securityContext` | no caps, no privilege escalation | |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Scheduling. |
| `podAnnotations` | `{}` | |
| `logging.auditEvents` | `true` | Print notable audit events to the operator log. `false` is silent (rely on an AuditSink). |
| `logging.allAuditEvents` | `false` | Also print the events the notability filter drops. Debug only. |
| `logging.auditFormat` | `text` | `text` or `json` for the audit lines. |
| `logging.encoder` | `console` | Operational log encoding: `console` or `json`. |
| `logging.level` | `debug` | Operational log level: `debug`, `info`, `error`, or an integer. |
| `extraArgs` | `[]` | Extra flags passed verbatim to the manager. |
| `createNamespace` | `false` | Prefer `--create-namespace`. |

The manager's own Service/webhook names and audit URL are derived from the
release and passed to it as flags automatically. They are not values.

## Keeping the CRDs in sync

`crds/` is a copy of `config/crd/bases/`. `./hack/update-manifests.sh`
refreshes it after any change to the Go API types, alongside the plain
manifests.
