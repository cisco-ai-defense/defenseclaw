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

{{/* The pod-identity SPIFFE ID of a component's ServiceAccount. */}}
{{- define "dc.spiffe" -}}spiffe://cluster.local/ns/{{ .ctx.Release.Namespace }}/sa/defenseclaw-{{ .component }}{{- end -}}

{{/* The ServiceAccount of a component and its ate-api principal. */}}
{{- define "dc.sa" -}}defenseclaw-{{ . }}{{- end -}}
{{- define "dc.principal" -}}system:serviceaccount:{{ .ctx.Release.Namespace }}:defenseclaw-{{ .component }}{{- end -}}

{{/*
Service DNS names, fully qualified: an actor's DNS goes through the egress
relay, which answers only the names in its policy, so the short
"<svc>.<ns>.svc" name (expanded by the search path) never resolves there
(GAP-0023). Rules and kit base URLs use these exact names.
*/}}
{{- define "dc.actorHost" -}}defenseclaw-actor.{{ .Release.Namespace }}.svc.cluster.local{{- end -}}
{{- define "dc.adminHost" -}}defenseclaw-admin.{{ .Release.Namespace }}.svc.cluster.local{{- end -}}
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
{{- $_ := set $sub "api" (dict "address" .Values.substrate.apiAddress "server_name" .Values.substrate.apiAudience "auth" "serviceaccount" "token_file" "/var/run/ate/token" "ca_file" "/var/run/ate/ca.crt") -}}
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

{{/*
Volumes every DefenseClaw pod mounts: (dict "ctx" $). /var/run/ate holds what
the ateapi client reads by default (internal/substrate/ateapi): the token for
ate-api-server, its serving CA, the pod's podidentity client certificate and
the podidentity CA the callout checks atenet-egress against.
/run/servicedns.podcert.ate.dev holds the serving certificate for the
Services that select the pod: only pods a Service selects ("serving" true),
since the signer issues no certificate without a Service DNS name and the pod
would never start.
*/}}
{{- define "dc.volumes" -}}
- name: config
  configMap:
    name: defenseclaw-config
- name: tmp
  emptyDir: {}
# DEFENSECLAW_HOME lives under a memory emptyDir: its root is root-owned and
# sticky (3777), which the audit store's directory trust check accepts; a
# disk emptyDir (2777) or a PVC root (0777 or 2775) is refused.
- name: run
  emptyDir:
    medium: Memory
    sizeLimit: {{ .ctx.Values.homeSizeLimit }}
- name: ate
  projected:
    sources:
    - serviceAccountToken:
        audience: {{ .ctx.Values.substrate.apiAudience }}
        expirationSeconds: {{ .ctx.Values.serviceAccounts.apiTokenExpirationSeconds }}
        path: token
    {{- if .ctx.Values.podCertificates.enabled }}
    - clusterTrustBundle:
        signerName: servicedns.podcert.ate.dev/identity
        labelSelector:
          matchLabels:
            podcert.ate.dev/canarying: live
        path: ca.crt
    - podCertificate:
        signerName: podidentity.podcert.ate.dev/identity
        keyType: ECDSAP256
        credentialBundlePath: credential-bundle.pem
    - clusterTrustBundle:
        signerName: podidentity.podcert.ate.dev/identity
        labelSelector:
          matchLabels:
            podcert.ate.dev/canarying: live
        path: podidentity-ca.crt
    {{- end }}
{{- if and .ctx.Values.podCertificates.enabled .serving }}
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
{{- end }}
{{- end -}}

{{- define "dc.volumeMounts" -}}
- name: config
  mountPath: /etc/defenseclaw
  readOnly: true
- name: tmp
  mountPath: /tmp
- name: run
  mountPath: /var/lib/defenseclaw/run
- name: ate
  mountPath: /var/run/ate
  readOnly: true
{{- if and .ctx.Values.podCertificates.enabled .serving }}
- name: servicedns
  mountPath: /run/servicedns.podcert.ate.dev
  readOnly: true
{{- end }}
{{- end -}}

{{- define "dc.env" -}}
- name: DEFENSECLAW_CONFIG
  value: /etc/defenseclaw/config.yaml
- name: DEFENSECLAW_HOME
  value: /var/lib/defenseclaw/run/home
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

{{/* Leader RPC mTLS: the pod-identity bundle and the SPIFFE IDs that may call the leader (A2 serve flags). */}}
{{- define "dc.peerFlags" -}}
- --peer-bundle=/var/run/ate/credential-bundle.pem
- --peer-trust=/var/run/ate/podidentity-ca.crt
- --peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "gateway") }}
- --peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "callout") }}
- --peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "controller") }}
{{- end -}}

{{/* Optional Secrets of the gateway and leader (absent ones are skipped). */}}
{{- define "dc.gatewaySecretMounts" -}}
- name: relay-session
  mountPath: /var/run/secrets/defenseclaw-relay-session
  readOnly: true
- name: llm-credentials
  mountPath: /var/run/secrets/defenseclaw-llm
  readOnly: true
{{- if .Values.callout.judge.tokenSecret }}
- name: callout-judge
  mountPath: /var/run/secrets/defenseclaw-callout-judge
  readOnly: true
{{- end }}
{{- end -}}

{{- define "dc.gatewaySecretVolumes" -}}
- name: relay-session
  secret:
    secretName: {{ .Values.gateway.relaySessionSecret }}
    optional: true
- name: llm-credentials
  secret:
    secretName: {{ .Values.gateway.llmCredentialsSecret }}
    optional: true
{{- with .Values.callout.judge.tokenSecret }}
- name: callout-judge
  secret:
    secretName: {{ . }}
    items:
    - {key: token, path: token}
{{- end }}
{{- end -}}

{{/* The Kubernetes API token for pods that call the Kubernetes API (the
service account automount stays off). */}}
{{- define "dc.kubeTokenMount" -}}
- name: kube-api-token
  mountPath: /var/run/secrets/kubernetes.io/serviceaccount
  readOnly: true
{{- end -}}
{{- define "dc.kubeTokenVolume" -}}
- name: kube-api-token
  projected:
    sources:
    - serviceAccountToken:
        expirationSeconds: 3600
        path: token
    - configMap:
        name: kube-root-ca.crt
        items:
        - {key: ca.crt, path: ca.crt}
    - downwardAPI:
        items:
        - path: namespace
          fieldRef: {fieldPath: metadata.namespace}
{{- end -}}
