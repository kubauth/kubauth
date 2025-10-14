
{{/* --------------------------------------------------------------------- Identity server server */}}


{{/*
Create the name of the audit server certificate
*/}}
{{- define "kubauth.audit.server.certificateName" -}}
{{- default (printf "%s-audit-server" (include "kubauth.baseName" .)) .Values.audit.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the audit server certificate
*/}}
{{- define "kubauth.audit.server.certificateSecretName" -}}
{{- default (printf "%s-audit-server-cert" (include "kubauth.baseName" .)) .Values.audit.server.certificateSecretName }}
{{- end }}


{{/* --------------------------------------------------------------------- RBAC */}}

{{/*
Create the name of the role for kubauth server access
*/}}
{{- define "kubauth.audit.systemRoleName" -}}
{{- default (printf "%s-audit-system" (include "kubauth.baseName" .)) .Values.audit.systemRoleName }}
{{- end }}

{{/*
Create the name of the role for kubauth administrator (Manage users and group)
*/}}
{{- define "kubauth.audit.adminRoleName" -}}
{{- default (printf "%s-audit-admin" (include "kubauth.baseName" .)) .Values.audit.adminRoleName }}
{{- end }}

