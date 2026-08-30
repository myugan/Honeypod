{{/* Chart name, overridable via nameOverride. */}}
{{- define "honeypod.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified app name. */}}
{{- define "honeypod.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The operator's own namespace. The decoy NetworkPolicy that lets each inner
apiserver reach the audit receiver, and the audit URL other decoys POST to,
both derive from this at the operator's compile time as "honeypod". Installing
elsewhere silently breaks audit egress, so this is pinned rather than following
.Release.Namespace. Install with: helm install ... -n honeypod --create-namespace
*/}}
{{- define "honeypod.namespace" -}}
honeypod
{{- end -}}

{{- define "honeypod.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "honeypod.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Common labels. */}}
{{- define "honeypod.labels" -}}
app.kubernetes.io/name: honeypod-operator
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/*
Selector labels. The operator hardcodes app.kubernetes.io/name=honeypod-operator
in its own Deployment/Service selectors and the join webhook's Service selector,
so this must stay exactly that -- do not add the instance label here or the
webhook Service will fail to find the manager pod.
*/}}
{{- define "honeypod.selectorLabels" -}}
app.kubernetes.io/name: honeypod-operator
{{- end -}}
