{{/*
Expand the name of the chart.
*/}}
{{- define "s3proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "s3proxy.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "s3proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "s3proxy.labels" -}}
helm.sh/chart: {{ include "s3proxy.chart" . }}
{{ include "s3proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "s3proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "s3proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "isCertConfigValid" -}}
{{- .Values.cert.enable -}}
{{- end -}}

{{/*
Check if a specific value is provided; if it exists, return that value.
Parameters:
- .HasValue: The value to check, often passed from .Values in Helm.
- .Context: The Helm context (.), used to access release-specific details like namespace.
If .HasValue exists, it will be returned. If not, a default fully qualified service name
is returned in the format "<release fullname>.<namespace>.svc.cluster.local".
*/}}
{{- define "checkCertDefaultValue" -}}
{{- if .HasValue -}}
{{- .HasValue | quote -}}
{{- else -}}
{{- include "s3proxy.fullname" .Context -}}.{{- .Context.Release.Namespace -}}.svc.cluster.local
{{- end -}}
{{- end }}