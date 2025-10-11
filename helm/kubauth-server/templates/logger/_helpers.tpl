
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

