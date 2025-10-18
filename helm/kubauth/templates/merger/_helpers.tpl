
{{/* --------------------------------------------------------------------- Identity server */}}


{{/*
Create the name of the configMap
*/}}
{{- define "kubauth.merger.configMapName" -}}
{{- default (printf "%s-merger" (include "kubauth.baseName" .)) .Values.merger.configMapName }}
{{- end }}


{{/*
Create the name of the merger server certificate
*/}}
{{- define "kubauth.merger.server.certificateName" -}}
{{- default (printf "%s-merger-server" (include "kubauth.baseName" .)) .Values.merger.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the merger server certificate
*/}}
{{- define "kubauth.merger.server.certificateSecretName" -}}
{{- default (printf "%s-merger-server-cert" (include "kubauth.baseName" .)) .Values.merger.server.certificateSecretName }}
{{- end }}

