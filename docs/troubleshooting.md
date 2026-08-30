# Troubleshooting

Common issues when running Honeypod and how to resolve them. Start by reading the Decoy status, which is where the operator records what happened.

```bash
kubectl -n honeypod get decoy <name>
kubectl -n honeypod describe decoy <name>
```

`describe` shows the `Ready` condition (with the failure reason when it failed) and an Events section for the Ready, ReconcileFailed, and PodJoined transitions. The operator log carries the same detail:

```bash
kubectl -n honeypod logs deploy/honeypod-controller-manager
```

## Common issues

| Symptom | Cause and fix |
|---|---|
| `error: the server doesn't have a resource type "decoys"` | The CRD is not installed. Apply `manifests/quickstart.yaml` or `manifests/install.yaml` first. |
| Phase stays `Pending` | The decoy pod is not ready. Check it with `kubectl -n honeypod get pods` and `kubectl -n honeypod describe pod <pod>`. The usual cause is nodes that cannot pull the `honeypod/*` images. |
| Phase is `Failed` | Read the reason. `kubectl -n honeypod describe decoy <name>` shows the `Ready` condition message and a `ReconcileFailed` Event. |
| A joined pod shows `redirected: false` | The annotation was added after the pod was created. The redirect only applies at pod creation, so recreate the pod. The pod still appears in the inventory. |
| Audit events never arrive | The operator must run in the `honeypod` namespace. It derives its audit routing from that name at build time, so installing elsewhere silently breaks delivery. |
| A namespace will not finish deleting | A Decoy in it still holds a finalizer. Delete the Decoy first, or clear the finalizer with `kubectl patch decoy <name> -p '{"metadata":{"finalizers":null}}' --type=merge`. |
| A `"true"` join annotation does nothing | `"true"` relays to the single Decoy in the cluster, or to the sole Decoy in the pod own namespace. With several Decoys and none in the pod namespace, use the explicit `"<namespace>/<decoy name>"` form instead. |
