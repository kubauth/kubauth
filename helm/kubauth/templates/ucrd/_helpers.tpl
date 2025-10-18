
{{/* --------------------------------------------------------------------- Identity server server */}}

{{/*
Create the name of the ucrd server certificate
*/}}
{{- define "kubauth.ucrd.server.certificateName" -}}
{{- default (printf "%s-ucrd-server" (include "kubauth.baseName" .)) .Values.ucrd.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the ucrd server certificate
*/}}
{{- define "kubauth.ucrd.server.certificateSecretName" -}}
{{- default (printf "%s-ucrd-server-cert" (include "kubauth.baseName" .)) .Values.ucrd.server.certificateSecretName }}
{{- end }}


{{/* --------------------------------------------------------------------- metrics */}}

{{/*
Create the name of the metrics serviceMonitor
*/}}
{{- define "kubauth.ucrd.metrics.serviceMonitor.name" -}}
{{- default (printf "%s-ucrd" (include "kubauth.baseName" .)) .Values.ucrd.metrics.serviceMonitor.name }}
{{- end }}


{{/*
Create the name of the metrics services
*/}}
{{- define "kubauth.ucrd.metrics.serviceName" -}}
{{- default (printf "%s-ucrd-metrics" (include "kubauth.baseName" .)) .Values.ucrd.metrics.serviceName }}
{{- end }}

{{/*
Create the name of the metrics tls certificate
*/}}
{{- define "kubauth.ucrd.metrics.certificateName" -}}
{{- default (printf "%s-ucrd-metrics" (include "kubauth.baseName" .)) .Values.ucrd.metrics.certificateName }}
{{- end }}

{{/*
Create the name of the metrics tls secret
*/}}
{{- define "kubauth.ucrd.metrics.secretName" -}}
{{- default (printf "%s-ucrd-metrics" (include "kubauth.baseName" .)) .Values.ucrd.metrics.secretName }}
{{- end }}

{{/*
Create the name of the self-signed issuer for metrics certficate
*/}}
{{- define "kubauth.ucrd.metrics.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-ucrd-metrics" (include "kubauth.baseName" .)) .Values.ucrd.metrics.certificateSelfSignedIssuerName }}
{{- end }}

{{/* --------------------------------------------------------------------- webhook */}}

{{/*
Create the name of the self-signed issuer for webhook certficate
*/}}
{{- define "kubauth.ucrd.webhooks.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-ucrd-webhooks" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.certificateSelfSignedIssuerName }}
{{- end }}

{{/*
Create the name of the webhook services
*/}}
{{- define "kubauth.ucrd.webhooks.serviceName" -}}
{{- default (printf "%s-ucrd-webhook" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.serviceName }}
{{- end }}

{{/*
Create the name of the webhook tls certificate
*/}}
{{- define "kubauth.ucrd.webhooks.certificateName" -}}
{{- default (printf "%s-ucrd-webhooks" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.certificateName }}
{{- end }}

{{/*
Create the name of the webhook tls secret
*/}}
{{- define "kubauth.ucrd.webhooks.secretName" -}}
{{- default (printf "%s-ucrd-webhooks" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.secretName }}
{{- end }}

{{/*
Create the name of the validating webhook configuration
*/}}
{{- define "kubauth.ucrd.webhooks.validatingWebhookConfiguration" -}}
{{- default (printf "%s-ucrd-validating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.validatingWebhookConfiguration }}
{{- end }}

{{/*
Create the name of the mutating webhook configuration
*/}}
{{- define "kubauth.ucrd.webhooks.mutatingWebhookConfiguration" -}}
{{- default (printf "%s-ucrd-mutating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.mutatingWebhookConfiguration }}
{{- end }}

{{/*
Create the name of the webhook network policy
*/}}
{{- define "kubauth.ucrd.webhooks.networkPolicyName" -}}
{{- default (printf "%s-ucrd-webhooks" (include "kubauth.baseName" .)) .Values.ucrd.webhooks.networkPolicyName }}
{{- end }}


{{/* --------------------------------------------------------------------- RBAC */}}

{{/*
Create the name of the role for kubauth server access
*/}}
{{- define "kubauth.ucrd.systemRoleName" -}}
{{- default (printf "%s-ucrd-system" (include "kubauth.baseName" .)) .Values.ucrd.systemRoleName }}
{{- end }}

{{/*
Create the name of the role for kubauth administrator (Manage users and group)
*/}}
{{- define "kubauth.ucrd.adminRoleName" -}}
{{- default (printf "%s-ucrd-admin" (include "kubauth.baseName" .)) .Values.ucrd.adminRoleName }}
{{- end }}

