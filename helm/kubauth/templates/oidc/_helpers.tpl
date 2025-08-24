
{{/* --------------------------------------------------------------------- OIDC server */}}


{{/*
Create the name of the oidc server certificate
*/}}
{{- define "kubauth.oidc.server.certificateName" -}}
{{- default (printf "%s-oidc-server" (include "kubauth.baseName" .)) .Values.oidc.server.certificateName }}
{{- end }}

{{/*
Create the name of the secret hosting the oidc server certificate
*/}}
{{- define "kubauth.oidc.server.certificateSecretName" -}}
{{- default (printf "%s-oidc-server-cert" (include "kubauth.baseName" .)) .Values.oidc.server.certificateSecretName }}
{{- end }}

{{/*
Create the name of the oidc service
*/}}
{{- define "kubauth.oidc.server.serviceName" -}}
{{- default (printf "%s-oidc-server" (include "kubauth.baseName" .)) .Values.oidc.server.serviceName }}
{{- end }}

{{/*
Create the name of the ingress
*/}}
{{- define "kubauth.oidc.ingressName" -}}
{{- default (printf "%s-oidc" (include "kubauth.baseName" .)) .Values.oidc.ingressName }}
{{- end }}

{{/*
Create the name of the netpol to allow access ingrss => service
*/}}
{{- define "kubauth.oidc.ingressNetworkPolicyName" -}}
{{- default (printf "%s-oidc-ingress" (include "kubauth.baseName" .)) .Values.oidc.ingressNetworkPolicyName }}
{{- end }}



{{/* --------------------------------------------------------------------- metrics */}}

{{/*
Create the name of the metrics serviceMonitor
*/}}
{{- define "kubauth.oidc.metrics.serviceMonitor.name" -}}
{{- default (printf "%s-oidc" (include "kubauth.baseName" .)) .Values.oidc.metrics.serviceMonitor.name }}
{{- end }}


{{/*
Create the name of the metrics services
*/}}
{{- define "kubauth.oidc.metrics.serviceName" -}}
{{- default (printf "%s-oidc-metrics" (include "kubauth.baseName" .)) .Values.oidc.metrics.serviceName }}
{{- end }}

{{/*
Create the name of the metrics tls certificate
*/}}
{{- define "kubauth.oidc.metrics.certificateName" -}}
{{- default (printf "%s-oidc-metrics" (include "kubauth.baseName" .)) .Values.oidc.metrics.certificateName }}
{{- end }}

{{/*
Create the name of the metrics tls secret
*/}}
{{- define "kubauth.oidc.metrics.secretName" -}}
{{- default (printf "%s-oidc-metrics" (include "kubauth.baseName" .)) .Values.oidc.metrics.secretName }}
{{- end }}

{{/*
Create the name of the self-signed issuer for metrics certficate
*/}}
{{- define "kubauth.oidc.metrics.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-oidc-metrics" (include "kubauth.baseName" .)) .Values.oidc.metrics.certificateSelfSignedIssuerName }}
{{- end }}

{{/* --------------------------------------------------------------------- webhook */}}

{{/*
Create the name of the self-signed issuer for webhook certficate
*/}}
{{- define "kubauth.oidc.webhooks.certificateSelfSignedIssuerName" -}}
{{- default (printf "%s-oidc-webhooks" (include "kubauth.baseName" .)) .Values.oidc.webhooks.certificateSelfSignedIssuerName }}
{{- end }}

{{/*
Create the name of the webhook services
*/}}
{{- define "kubauth.oidc.webhooks.serviceName" -}}
{{- default (printf "%s-oidc-webhook" (include "kubauth.baseName" .)) .Values.oidc.webhooks.serviceName }}
{{- end }}

{{/*
Create the name of the webhook tls certificate
*/}}
{{- define "kubauth.oidc.webhooks.certificateName" -}}
{{- default (printf "%s-oidc-webhooks" (include "kubauth.baseName" .)) .Values.oidc.webhooks.certificateName }}
{{- end }}

{{/*
Create the name of the webhook tls secret
*/}}
{{- define "kubauth.oidc.webhooks.secretName" -}}
{{- default (printf "%s-oidc-webhooks" (include "kubauth.baseName" .)) .Values.oidc.webhooks.secretName }}
{{- end }}

{{/*
Create the name of the validating webhook configuration
*/}}
{{- define "kubauth.oidc.webhooks.validatingWebhookConfiguration" -}}
{{- default (printf "%s-oidc-validating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.oidc.webhooks.validatingWebhookConfiguration }}
{{- end }}

{{/*
Create the name of the mutating webhook configuration
*/}}
{{- define "kubauth.oidc.webhooks.mutatingWebhookConfiguration" -}}
{{- default (printf "%s-oidc-mutating-webhooks-configuration" (include "kubauth.baseName" .)) .Values.oidc.webhooks.mutatingWebhookConfiguration }}
{{- end }}


{{/* --------------------------------------------------------------------- RBAC */}}

{{/*
Create the name of the OidcClient access role
*/}}
{{- define "kubauth.oidc.clientRoleName" -}}
{{- default (printf "%s-oidc-client" (include "kubauth.baseName" .)) .Values.oidc.clients.roleName }}
{{- end }}

{{/*
Create the name of the SsoSession access role
*/}}
{{- define "kubauth.oidc.ssoRoleName" -}}
{{- default (printf "%s-oidc-sso" (include "kubauth.baseName" .)) .Values.oidc.sso.roleName }}
{{- end }}
