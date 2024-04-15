# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0
---
{{/*
Expand the name of the chart.
*/}}
{{- define "oidc-apps-extension.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "oidc-apps-extension.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "oidc-apps-extension.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "oidc-apps-extension.labels" -}}
helm.sh/chart: {{ include "oidc-apps-extension.chart" . }}
{{ include "oidc-apps-extension.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "oidc-apps-extension.selectorLabels" -}}
app.kubernetes.io/name: {{ include "oidc-apps-extension.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Certificate labels
*/}}
{{- define "oidc-apps-extension.certificateLabels" -}}
{{ include "oidc-apps-extension.labels" . }}
app.kubernetes.io/component: certificate
{{- end }}

{{/*
Create the name of the certificate secret to use
*/}}
{{- define "oidc-apps-extension.certificateSecretName" -}}
{{- if .Values.certificate.create }}
{{- $defaultSecretName :=  printf "%s-%s" (include "oidc-apps-extension.fullname" .) "webhook-tls-cert" -}}
{{- default $defaultSecretName .Values.certificate.secretName }}
{{- else }}
{{- default "default" "" }}
{{- end }}
{{- end }}

{{/*
Create the certificate reference for the ca-injector
*/}}
{{- define "oidc-apps-extension.certificateRef" -}}
{{- printf "%s/%s" .Release.Namespace (include "oidc-apps-extension.clusterRoleName" .) -}}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "oidc-apps-extension.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "oidc-apps-extension.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cluster role to use
*/}}
{{- define "oidc-apps-extension.clusterRoleName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "oidc-apps-extension.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Returns a clientId by seed name
*/}}
{{- define "oidc-apps-extension.fetchClientIdBySeedIdentifier" }}
  {{- $clientName := get .Values.gardener.seed.annotations "oidc-apps.extensions.gardener.cloud/client-name" }}
  {{- $clientID := "" }}
  {{- range .Values.clients }}
    {{- if eq .name $clientName }}
      {{- $clientID = .clientId -}}
      {{- break -}}
    {{- end }}
  {{- end }}
  {{- required (print "found no clientID for seed: " .Values.gardener.seed.name ) $clientID -}}
{{- end }}

{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
{{- end }}