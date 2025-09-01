{{- define "octovault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "octovault.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "octovault.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "octovault.serviceaccount" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- printf "octovault-controller-manager" }}
{{- end }}
{{- end }}}}


{{- define "octovault.labels" -}}
app.kubernetes.io/name: {{ include "octovault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Return the image tag.
If .Values.image.tag is set, use it.
Otherwise, fall back to .Chart.AppVersion.
*/}}
{{- define "octovault.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag -}}
{{- end }}
