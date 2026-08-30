#!/usr/bin/env bash
#
# Regenerates the CRDs from the Go types and rebuilds the two bundles in
# manifests/ from the pieces in config/.
#
# manifests/install.yaml and manifests/quickstart.yaml used to be edited by
# hand, which meant a CRD change had to be copied into both by hand and
# nothing noticed when that was forgotten. Run this after touching anything
# under api/ or config/, and commit whatever it changes.
#
#   ./hack/update-manifests.sh
#
# CI runs it with --check, which rebuilds and fails if the result differs
# from what is committed.

set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned: controller-gen writes its version into every CRD it generates, so
# an unpinned one shows up as noise in the diff.
CONTROLLER_GEN_VERSION="v0.21.0"

check_only=false
if [[ "${1:-}" == "--check" ]]; then
  check_only=true
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

controller_gen="$(go env GOPATH)/bin/controller-gen"
if [[ ! -x "$controller_gen" ]] || ! "$controller_gen" --version | grep -q "$CONTROLLER_GEN_VERSION"; then
  echo "installing controller-gen $CONTROLLER_GEN_VERSION"
  # go install occasionally fails fetching checksum-db tiles from
  # sum.golang.org with a transient stream error; retry a few times before
  # giving up so CI doesn't flake on infrastructure hiccups.
  installed=false
  for attempt in 1 2 3; do
    if go install "sigs.k8s.io/controller-tools/cmd/controller-gen@$CONTROLLER_GEN_VERSION"; then
      installed=true
      break
    fi
    echo "controller-gen install attempt $attempt failed, retrying..."
    sleep 5
  done
  if [[ "$installed" != true ]]; then
    echo "could not install controller-gen after retries" >&2
    exit 1
  fi
fi

# sync_chart_rbac rewrites the rules of the chart's ClusterRole from the
# generated config/rbac/role.yaml, keeping the chart's own templated header
# (name/labels) and its ClusterRoleBinding intact.
sync_chart_rbac() {
  local chart="charts/honeypod/templates/rbac.yaml"
  # The generated role's rules: everything from its own "rules:" line on.
  local rules
  rules="$(awk 'f{print} /^rules:/{f=1}' config/rbac/role.yaml)"
  # The chart header: up to and including its "rules:" line.
  local header
  header="$(awk '{print} /^rules:/{exit}' "$chart")"
  # The chart's ClusterRoleBinding: from the first "---" separator on.
  local binding
  binding="$(awk 'f{print} /^---$/{f=1}' "$chart")"
  {
    printf '%s\n' "$header"
    printf '%s\n' "$rules"
    printf -- '---\n'
    printf '%s\n' "$binding"
  } > "$chart"
}

"$controller_gen" object paths=./api/...
"$controller_gen" crd paths=./api/... output:crd:artifacts:config=config/crd/bases
"$controller_gen" rbac:roleName=honeypod-manager-role paths=./internal/controller/... output:rbac:artifacts:config=config/rbac

# The Helm chart ships its own copy of the CRDs (Helm installs crds/
# untouched, before templates). Keep it identical to the generated set.
cp config/crd/bases/*.yaml charts/honeypod/crds/

# Sync the Helm chart's ClusterRole rules from the generated role, so the
# chart's RBAC can't drift from the manager's actual +kubebuilder:rbac
# markers (both come from config/rbac/role.yaml).
sync_chart_rbac

# Order matters: the namespace has to exist before anything lands in it, and
# the CRDs before any custom resource that uses them.
install_parts=(
  config/manager/namespace.yaml
  config/crd/bases/honeypod.io_decoys.yaml
  config/crd/bases/honeypod.io_providers.yaml
  config/crd/bases/honeypod.io_alerts.yaml
  config/crd/bases/honeypod.io_auditsinks.yaml
  config/rbac/role.yaml
  config/rbac/role_binding.yaml
  config/manager/manager.yaml
  config/manager/service.yaml
  config/manager/webhook.yaml
)

# quickstart is install plus a ready-to-use decoy.
quickstart_parts=("${install_parts[@]}" config/quickstart/decoy.yaml)

# Joins files into one multi-document stream with a single "---" between
# each. Only a part's leading and trailing separators are trimmed, so a file
# holding more than one document (manager.yaml, webhook.yaml) keeps the
# separators between its own documents.

assemble() {
  local out="$1"
  shift
  : >"$out"
  local first=true part body
  for part in "$@"; do
    body="$(awk '
      { line[NR] = $0 }
      END {
        s = 1; while (s <= NR && (line[s] == "---" || line[s] == "")) s++
        e = NR; while (e >= s && (line[e] == "---" || line[e] == "")) e--
        for (i = s; i <= e; i++) print line[i]
      }' "$part")"
    if [[ "$first" == true ]]; then
      first=false
    else
      printf -- '---\n' >>"$out"
    fi
    printf '%s\n' "$body" >>"$out"
  done
}

if [[ "$check_only" == true ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  assemble "$tmp/install.yaml" "${install_parts[@]}"
  assemble "$tmp/quickstart.yaml" "${quickstart_parts[@]}"
  status=0
  for f in install quickstart; do
    if ! diff -u "manifests/$f.yaml" "$tmp/$f.yaml"; then
      echo "manifests/$f.yaml is out of date, run ./hack/update-manifests.sh" >&2
      status=1
    fi
  done
  # Only the generated artifacts, so a work-in-progress edit to a
  # hand-written file here doesn't read as drift.
  generated=(api/v1alpha1/zz_generated.deepcopy.go config/crd/bases config/rbac charts/honeypod/crds charts/honeypod/templates/rbac.yaml)
  if ! git diff --quiet -- "${generated[@]}"; then
    echo "generated files are out of date, run ./hack/update-manifests.sh" >&2
    git diff --stat -- "${generated[@]}" >&2
    status=1
  fi
  exit "$status"
fi

assemble manifests/install.yaml "${install_parts[@]}"
assemble manifests/quickstart.yaml "${quickstart_parts[@]}"

echo "wrote manifests/install.yaml and manifests/quickstart.yaml"
