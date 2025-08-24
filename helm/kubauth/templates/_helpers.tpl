
{{/*
Create a default fully qualified app name, to use as base bame for all ressources.
Use the release name by default
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "kubauth.baseName" -}}
{{- if .Values.baseNameOverride }}
{{- .Values.baseNameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubauth.chartName" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}


{{/*
Common labels
*/}}
{{- define "kubauth.labels" -}}
helm.sh/chart: {{ include "kubauth.chartName" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}


{{/*
Controller Selector labels
*/}}
{{- define "kubauth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubauth.baseName" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the deployment to use
*/}}
{{- define "kubauth.deploymentName" -}}
{{- default (printf "%s" (include "kubauth.baseName" .)) .Values.deploymentName }}
{{- end }}


{{/*
Create the name of the service account to use
*/}}
{{- define "kubauth.serviceAccountName" -}}
{{- default (printf "%s" (include "kubauth.baseName" .)) .Values.serviceAccountName }}
{{- end }}

{{/*
Create the name of the associated role
*/}}
{{- define "kubauth.roleName" -}}
{{- default (printf "%s" (include "kubauth.baseName" .)) .Values.roleName }}
{{- end }}



{{/*
Create the name of the netpol to allow communication in the deployment namespace
*/}}
{{- define "kubauth.allowIntraNamespacePolicyName" -}}
{{- default (printf "%s-allow-intra-namespace" (include "kubauth.baseName" .)) .Values.networkPolicies.allowIntraNamespacePolicyName }}
{{- end }}

{{/*
Create the name of the netpol to allow to outside
*/}}
{{- define "kubauth.allowAllEgressPolicyName" -}}
{{- default (printf "%s-allow-all-egress" (include "kubauth.baseName" .)) .Values.networkPolicies.allowAllEgressPolicyName }}
{{- end }}
