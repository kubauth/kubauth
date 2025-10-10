
{{/* --------------------------------------------------------------------- Identity server server */}}


{{/*
Create the name of the logger server certificate
*/}}
{{- define "kubauth.logger.server.certificateName" -}}
{{- default (printf "%s-logger-server" (include "kubauth.baseName" .)) .Values.logger.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the logger server certificate
*/}}
{{- define "kubauth.logger.server.certificateSecretName" -}}
{{- default (printf "%s-logger-server-cert" (include "kubauth.baseName" .)) .Values.logger.server.certificateSecretName }}
{{- end }}

{{/*
Create the name of the logger service
*/}}
{{- define "kubauth.logger.server.serviceName" -}}
{{- default (printf "%s-logger-server" (include "kubauth.baseName" .)) .Values.logger.server.serviceName }}
{{- end }}

{{/*
Create the name of the ingress
*/}}
{{- define "kubauth.logger.ingressName" -}}
{{- default (printf "%s-logger" (include "kubauth.baseName" .)) .Values.logger.ingressName }}
{{- end }}

{{/*
Create the name of the netpol to allow ingress => service
*/}}
{{- define "kubauth.logger.ingressNetworkPolicyName" -}}
{{- default (printf "%s-logger-ingress" (include "kubauth.baseName" .)) .Values.logger.ingressNetworkPolicyName }}
{{- end }}


{{/* --------------------------------------------------------------------- RBAC */}}

{{/*
Create the name of the role for kubauth server access
*/}}
{{- define "kubauth.logger.systemRoleName" -}}
{{- default (printf "%s-logger-system" (include "kubauth.baseName" .)) .Values.logger.systemRoleName }}
{{- end }}

{{/*
Create the name of the role for kubauth administrator (Manage users and group)
*/}}
{{- define "kubauth.logger.adminRoleName" -}}
{{- default (printf "%s-logger-admin" (include "kubauth.baseName" .)) .Values.logger.adminRoleName }}
{{- end }}

