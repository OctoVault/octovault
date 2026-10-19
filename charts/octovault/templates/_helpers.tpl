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

{{/*
octovault.intEnv renders an integer setting as a quoted env value.
Numbers go through int64, so an unquoted large number does not render as 2e+06.
Strings are passed through untouched, so an invalid value reaches the controller as written
and is reported there, instead of being turned into "0".
*/}}
{{- define "octovault.intEnv" -}}
{{- if kindIs "string" . -}}
{{- quote . -}}
{{- else -}}
{{- int64 . | quote -}}
{{- end -}}
{{- end }}
