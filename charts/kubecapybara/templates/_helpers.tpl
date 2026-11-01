{{- define "capybara.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "capybara.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "capybara.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/part-of: kubecapybara
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/* The CLI finds agents with app.kubernetes.io/name=capybara-agent: keep it fixed. */}}
{{- define "capybara.agentSelector" -}}
app.kubernetes.io/name: capybara-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "capybara.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s-agent" (include "capybara.fullname" .)) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "capybara.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{- define "capybara.subjects" -}}
{{- range .groups }}
- kind: Group
  apiGroup: rbac.authorization.k8s.io
  name: {{ . }}
{{- end }}
{{- range .users }}
- kind: User
  apiGroup: rbac.authorization.k8s.io
  name: {{ . }}
{{- end }}
{{- range .serviceAccounts }}
- kind: ServiceAccount
  name: {{ .name }}
  namespace: {{ .namespace }}
{{- end }}
{{- end }}
