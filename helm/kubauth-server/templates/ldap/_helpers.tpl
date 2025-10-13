
{{/* --------------------------------------------------------------------- Identity server */}}


{{/*
Create the name of the configMap
*/}}
{{- define "kubauth.ldap.configMapName" -}}
{{- default (printf "%s-ldap" (include "kubauth.baseName" .)) .Values.ldap.configMapName }}
{{- end }}


{{/*
Create the name of the ldap server certificate
*/}}
{{- define "kubauth.ldap.server.certificateName" -}}
{{- default (printf "%s-ldap-server" (include "kubauth.baseName" .)) .Values.ldap.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the ldap server certificate
*/}}
{{- define "kubauth.ldap.server.certificateSecretName" -}}
{{- default (printf "%s-ldap-server-cert" (include "kubauth.baseName" .)) .Values.ldap.server.certificateSecretName }}
{{- end }}

