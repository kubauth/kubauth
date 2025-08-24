
{{/* --------------------------------------------------------------------- Identity server server */}}


{{/*
Create the name of the userdb server certificate
*/}}
{{- define "kubauth.userdb.server.certificateName" -}}
{{- default (printf "%s-userdb-server" (include "kubauth.baseName" .)) .Values.userdb.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the userdb server certificate
*/}}
{{- define "kubauth.userdb.server.certificateSecretName" -}}
{{- default (printf "%s-userdb-server-cert" (include "kubauth.baseName" .)) .Values.userdb.server.certificateSecretName }}
{{- end }}

{{/*
Create the name of the userdb service
*/}}
{{- define "kubauth.userdb.server.serviceName" -}}
{{- default (printf "%s-userdb-server" (include "kubauth.baseName" .)) .Values.userdb.server.serviceName }}
{{- end }}

{{/*
Create the name of the ingress
*/}}
{{- define "kubauth.userdb.ingressName" -}}
{{- default (printf "%s-userdb" (include "kubauth.baseName" .)) .Values.userdb.ingressName }}
{{- end }}

{{/*
Create the name of the netpol to allow ingress => service
*/}}
{{- define "kubauth.userdb.ingressNetworkPolicyName" -}}
{{- default (printf "%s-userdb-ingress" (include "kubauth.baseName" .)) .Values.userdb.ingressNetworkPolicyName }}
{{- end }}



{{/* --------------------------------------------------------------------- metrics */}}

{{/*
Create the name of the metrics serviceMonitor
*/}}
{{- define "kubauth.userdb.metrics.serviceMonitor.name" -}}
{{- default (printf "%s-userdb" (include "kubauth.baseName" .)) .Values.userdb.metrics.serviceMonitor.name }}
{{- end }}


{{/*
Create the name of the metrics services
*/}}
{{- define "kubauth.userdb.metrics.serviceName" -}}
{{- default (printf "%s-userdb-metrics" (include "kubauth.baseName" .)) .Values.userdb.metrics.serviceName }}
{{- end }}

{{/*
Create the name of the metrics tls certificate
*/}}
{{- define "kubauth.userdb.metrics.certificateName" -}}
{{- default (printf "%s-userdb-metrics" (include "kubauth.baseName" .)) .Values.userdb.metrics.certificateName }}
{{- end }}

{{/*
Create the name of the metrics tls secret
*/}}
{{- define "kubauth.userdb.metrics.secretName" -}}
{{- default (printf "%s-userdb-metrics" (include "kubauth.baseName" .)) .Values.userdb.metrics.secretName }}
{{- end }}

{{/*
Create the name of the self-signed issuer for metrics certficate
*/}}
{{- define "kubauth.userdb.metrics.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-userdb-metrics" (include "kubauth.baseName" .)) .Values.userdb.metrics.certificateSelfSignedIssuerName }}
{{- end }}

{{/* --------------------------------------------------------------------- webhook */}}

{{/*
Create the name of the self-signed issuer for webhook certficate
*/}}
{{- define "kubauth.userdb.webhooks.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-userdb-webhooks" (include "kubauth.baseName" .)) .Values.userdb.webhooks.certificateSelfSignedIssuerName }}
{{- end }}

{{/*
Create the name of the webhook services
*/}}
{{- define "kubauth.userdb.webhooks.serviceName" -}}
{{- default (printf "%s-userdb-webhook" (include "kubauth.baseName" .)) .Values.userdb.webhooks.serviceName }}
{{- end }}

{{/*
Create the name of the webhook tls certificate
*/}}
{{- define "kubauth.userdb.webhooks.certificateName" -}}
{{- default (printf "%s-userdb-webhooks" (include "kubauth.baseName" .)) .Values.userdb.webhooks.certificateName }}
{{- end }}

{{/*
Create the name of the webhook tls secret
*/}}
{{- define "kubauth.userdb.webhooks.secretName" -}}
{{- default (printf "%s-userdb-webhooks" (include "kubauth.baseName" .)) .Values.userdb.webhooks.secretName }}
{{- end }}

{{/*
Create the name of the validating webhook configuration
*/}}
{{- define "kubauth.userdb.webhooks.validatingWebhookConfiguration" -}}
{{- default (printf "%s-userdb-validating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.userdb.webhooks.validatingWebhookConfiguration }}
{{- end }}

{{/*
Create the name of the mutating webhook configuration
*/}}
{{- define "kubauth.userdb.webhooks.mutatingWebhookConfiguration" -}}
{{- default (printf "%s-userdb-mutating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.userdb.webhooks.mutatingWebhookConfiguration }}
{{- end }}


{{/* --------------------------------------------------------------------- RBAC */}}

{{/*
Create the name of the userdb access role
*/}}
{{- define "kubauth.userdb.roleName" -}}
{{- default (printf "%s-userdb" (include "kubauth.baseName" .)) .Values.userdb.roleName }}
{{- end }}

