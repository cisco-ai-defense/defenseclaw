{{/*
Resource names are fixed ("defenseclaw-<part>"): rendered egress policies
name the actor Service as defenseclaw-actor.<namespace>.svc, so one release
per namespace.
*/}}
{{- define "dc.name" -}}defenseclaw-{{ . }}{{- end -}}

{{- define "dc.labels" -}}
app.kubernetes.io/name: defenseclaw-substrate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: defenseclaw
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/* Selector labels of one component: (dict "ctx" $ "component" "gateway"). */}}
{{- define "dc.selector" -}}
app.kubernetes.io/name: defenseclaw-substrate
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "dc.componentLabels" -}}
{{ include "dc.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "dc.image" -}}
{{- $img := .Values.image -}}
{{- if $img.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $img.digest) -}}
{{- fail "image.digest must be sha256:<64 hex>" -}}
{{- end -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ $img.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/* The ServiceAccount of a component and its ate-api principal. */}}
{{- define "dc.sa" -}}defenseclaw-{{ . }}{{- end -}}
{{- define "dc.principal" -}}system:serviceaccount:{{ .ctx.Release.Namespace }}:defenseclaw-{{ .component }}{{- end -}}

{{/* Service DNS names. */}}
{{- define "dc.actorHost" -}}defenseclaw-actor.{{ .Release.Namespace }}.svc{{- end -}}
{{- define "dc.adminHost" -}}defenseclaw-admin.{{ .Release.Namespace }}.svc{{- end -}}
{{- define "dc.calloutService" -}}{{ .Release.Namespace }}/defenseclaw-callout:{{ .Values.callout.port }}{{- end -}}

{{/*
The launcher atespaces as a sorted, de-duplicated list, from
config.substrate.launcher_atespaces (profile -> [atespace]).
*/}}
{{- define "dc.launcherAtespaces" -}}
{{- $out := list -}}
{{- range $profile, $spaces := (.Values.config.substrate.launcher_atespaces | default dict) -}}
{{- range $spaces -}}{{- $out = append $out . -}}{{- end -}}
{{- end -}}
{{- toJson ($out | uniq | sortAlpha) -}}
{{- end -}}

{{/* Launcher and managed atespaces, sorted. */}}
{{- define "dc.writableAtespaces" -}}
{{- $out := include "dc.launcherAtespaces" . | fromJsonArray -}}
{{- range .Values.managedAtespaces -}}{{- $out = append $out . -}}{{- end -}}
{{- toJson ($out | uniq | sortAlpha) -}}
{{- end -}}

{{/*
The rendered config.yaml: config with the chart's defaults for the keys that
name this release's Services and the Substrate API filled in.
*/}}
{{- define "dc.config" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- $sub := get $cfg "substrate" | default dict -}}
{{- $_ := set $sub "enabled" (ternary true $sub.enabled (not (hasKey $sub "enabled"))) -}}
{{- if not (hasKey $sub "services") -}}
{{- $_ := set $sub "services" (dict "actor" (include "dc.actorHost" .) "admin" (include "dc.adminHost" .)) -}}
{{- end -}}
{{- if not (hasKey $sub "api") -}}
{{- $_ := set $sub "api" (dict "address" .Values.substrate.apiAddress "auth" "serviceaccount" "token_file" "/var/run/secrets/ate-api/token" "ca_file" "/run/servicedns.podcert.ate.dev/trust-bundle.pem") -}}
{{- end -}}
{{- $_ := set $cfg "substrate" $sub -}}
{{- toYaml $cfg -}}
{{- end -}}

{{/* Pod-level settings shared by every DefenseClaw pod. */}}
{{- define "dc.podSpecCommon" -}}
{{- with .ctx.Values.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
serviceAccountName: {{ include "dc.sa" .sa }}
automountServiceAccountToken: false
enableServiceLinks: false
securityContext:
{{- toYaml .ctx.Values.podSecurityContext | nindent 2 }}
{{- with .values.nodeSelector }}
nodeSelector:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Volumes every DefenseClaw pod mounts: (dict "ctx" $). */}}
{{- define "dc.volumes" -}}
- name: config
  configMap:
    name: defenseclaw-config
- name: tmp
  emptyDir: {}
- name: ate-api-token
  projected:
    sources:
    - serviceAccountToken:
        audience: {{ .ctx.Values.substrate.apiAudience }}
        expirationSeconds: {{ .ctx.Values.serviceAccounts.apiTokenExpirationSeconds }}
        path: token
{{- if .ctx.Values.podCertificates.enabled }}
- name: servicedns
  projected:
    sources:
    - podCertificate:
        signerName: servicedns.podcert.ate.dev/identity
        keyType: ECDSAP256
        credentialBundlePath: credential-bundle.pem
    - clusterTrustBundle:
        signerName: servicedns.podcert.ate.dev/identity
        labelSelector:
          matchLabels:
            podcert.ate.dev/canarying: live
        path: trust-bundle.pem
- name: podidentity
  projected:
    sources:
    - podCertificate:
        signerName: podidentity.podcert.ate.dev/identity
        keyType: ECDSAP256
        credentialBundlePath: credential-bundle.pem
    - clusterTrustBundle:
        signerName: podidentity.podcert.ate.dev/identity
        labelSelector:
          matchLabels:
            podcert.ate.dev/canarying: live
        path: trust-bundle.pem
{{- end }}
{{- end -}}

{{- define "dc.volumeMounts" -}}
- name: config
  mountPath: /etc/defenseclaw
  readOnly: true
- name: tmp
  mountPath: /tmp
- name: ate-api-token
  mountPath: /var/run/secrets/ate-api
  readOnly: true
{{- if .ctx.Values.podCertificates.enabled }}
- name: servicedns
  mountPath: /run/servicedns.podcert.ate.dev
  readOnly: true
- name: podidentity
  mountPath: /run/podidentity.podcert.ate.dev
  readOnly: true
{{- end }}
{{- end -}}

{{- define "dc.env" -}}
- name: DEFENSECLAW_CONFIG
  value: /etc/defenseclaw/config.yaml
- name: DEFENSECLAW_HOME
  value: /tmp/defenseclaw
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- end -}}

{{/* Annotations that roll pods when the config changes. */}}
{{- define "dc.podAnnotations" -}}
checksum/config: {{ include "dc.config" .ctx | sha256sum }}
{{- with .ctx.Values.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}
