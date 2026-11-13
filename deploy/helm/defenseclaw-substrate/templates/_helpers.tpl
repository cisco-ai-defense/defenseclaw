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
{{- /* The exposed actor_secrets values: the gateway's /llm exact-value DLP
reads them from the same directory as the callout (F3, fa2fb4c476). */ -}}
{{- if .Values.callout.actorSecrets.secretName -}}
{{- $x := get $sub "extproc" | default dict -}}
{{- if not (hasKey $x "actor_secrets_dir") }}{{ $_ := set $x "actor_secrets_dir" (include "dc.actorSecretsDir" .) }}{{ end -}}
{{- $_ := set $sub "extproc" $x -}}
{{- end -}}
{{- if and .Values.bundles.enabled (not (hasKey $sub "bundles")) -}}
{{- $_ := set $sub "bundles" (dict "enabled" true "anchors_file" "/etc/defenseclaw-substrate/bundle-anchors/bundle-anchors.json" "inbox" .Values.bundles.inbox) -}}
{{- end -}}
{{- $_ := set $cfg "substrate" $sub -}}
{{- with .Values.deploymentMode }}{{ $_ := set $cfg "deployment_mode" . }}{{ end -}}
{{- if and (include "dc.managed" .) (not (hasKey $cfg "data_dir")) -}}
{{- $_ := set $cfg "data_dir" (include "dc.managedDataDir" .) -}}
{{- end -}}
{{- if and (include "dc.managed" .) (not (hasKey $cfg "policy_dir")) -}}
{{- $_ := set $cfg "policy_dir" (include "dc.managedPolicyDir" .) -}}
{{- end -}}
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
{{/* "true" when the release runs in managed_enterprise (GAP-0135). */}}
{{/* The gateway's Kubernetes sign-in is on (internal/cli substrateKubeSignIn):
no substrate.identity.oidc.issuer, not a managed install, and not turned
off with --no-kube-sign-in in custom gateway args. The flag is a Go bool:
--no-kube-sign-in and --no-kube-sign-in=<true value> turn it off, =false
keeps it on, and the last one wins, as the gateway parses it. */}}
{{- define "dc.kubeSignIn" -}}
{{- $issuer := dig "substrate" "identity" "oidc" "issuer" "" (.Values.config | default dict) -}}
{{- $off := false -}}
{{- range (.Values.gateway.args | default list) -}}
{{- $a := toString . -}}
{{- if eq $a "--no-kube-sign-in" -}}
{{- $off = true -}}
{{- else if hasPrefix "--no-kube-sign-in=" $a -}}
{{- $off = has (trimPrefix "--no-kube-sign-in=" $a) (list "1" "t" "T" "TRUE" "true" "True") -}}
{{- end -}}
{{- end -}}
{{- if and (not $issuer) (not (include "dc.managed" .)) (not $off) }}true{{ end -}}
{{- end -}}

{{/* The auth-delegator ClusterRoleBinding's name: gateway.authDelegatorBinding,
else defenseclaw-auth-delegator-<namespace>-<release> (cluster-scoped, so
two releases never share one). */}}
{{- define "dc.authDelegatorBinding" -}}
{{- .Values.gateway.authDelegatorBinding | default (printf "defenseclaw-auth-delegator-%s-%s" .Release.Namespace .Release.Name) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dc.managed" -}}
{{- $m := lower (toString (.Values.deploymentMode | default (.Values.config.deployment_mode | default ""))) -}}
{{- if has $m (list "managed" "managed_enterprise" "managed-enterprise") }}true{{ end -}}
{{- end -}}

{{/* The managed data dir: its own volume, owned by the gateway account,
0700 (the managed data_dir trust check refuses a 0777 volume root). */}}
{{- define "dc.managedDataDir" -}}/var/lib/defenseclaw/data{{- end -}}
{{/* The managed policy_dir: the root-owned vendor folder of the Linux
layout, seeded by the init container and read-only to the gateway. */}}
{{- define "dc.managedPolicyDir" -}}/opt/defenseclaw/share/policies{{- end -}}

{{/* Init containers of a DefenseClaw pod: in managed mode one gives the
data volume to the gateway account (the gateway image has no shell, so
its own hidden substrate-datadir step does it; it needs CHOWN and FOWNER
as root, nothing else). */}}
{{- define "dc.initContainers" -}}
{{- if include "dc.managed" . }}
initContainers:
- name: data-dir
  image: {{ include "dc.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
  - substrate-datadir
  - --path={{ include "dc.managedDataDir" . }}
  - --uid={{ .Values.podSecurityContext.runAsUser }}
  - --gid={{ .Values.podSecurityContext.runAsGroup }}
  - --mode=0700
  - --policies={{ include "dc.managedPolicyDir" . }}
  resources:
    requests: {cpu: 10m, memory: 16Mi}
    limits: {memory: 64Mi}
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: [ALL]
      add: [CHOWN, FOWNER]
  volumeMounts:
  - name: data
    mountPath: {{ include "dc.managedDataDir" . }}
  - name: policies
    mountPath: {{ include "dc.managedPolicyDir" . }}
{{- end }}
{{- end -}}

{{- define "dc.volumes" -}}
- name: config
  configMap:
    name: defenseclaw-config
    # Read-only for everyone (managed: the config trust check wants an
    # admin-owned file nobody else can write).
    defaultMode: 0444
{{- if include "dc.managed" .ctx }}
- name: data
  emptyDir:
    sizeLimit: {{ .ctx.Values.managed.dataSizeLimit }}
- name: policies
  emptyDir:
    sizeLimit: 64Mi
{{- end }}
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
{{- if and .ctx.Values.bundles.enabled (has .component (list "controller" "gateway")) }}
- name: bundle-anchors
  secret:
    secretName: {{ .ctx.Values.bundles.anchorsSecret }}
    defaultMode: 0444
{{- end }}
{{- end -}}

{{- define "dc.volumeMounts" -}}
{{- if include "dc.managed" .ctx }}
# Managed: one file, not the ConfigMap directory, whose ..data symlinks the
# managed config trust check refuses (GAP-0135). The pods roll on a config
# change (checksum annotation), as a subPath mount is not updated in place.
- name: config
  mountPath: /etc/defenseclaw/config.yaml
  subPath: config.yaml
  readOnly: true
- name: data
  mountPath: {{ include "dc.managedDataDir" .ctx }}
- name: policies
  mountPath: {{ include "dc.managedPolicyDir" .ctx }}
  readOnly: true
{{- else }}
- name: config
  mountPath: /etc/defenseclaw
  readOnly: true
{{- end }}
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
{{- if and .ctx.Values.bundles.enabled (has .component (list "controller" "gateway")) }}
- name: bundle-anchors
  mountPath: /etc/defenseclaw-substrate/bundle-anchors
  readOnly: true
{{- end }}
{{- end -}}

{{- define "dc.env" -}}
- name: DEFENSECLAW_CONFIG
  value: /etc/defenseclaw/config.yaml
{{- if include "dc.managed" . }}
- name: DEFENSECLAW_HOME
  value: {{ include "dc.managedDataDir" . }}
# The gateway account the managed trust checks accept (distroless "nonroot").
- name: DEFENSECLAW_UNIX_SERVICE_ACCOUNT
  value: {{ .Values.managed.serviceAccountName | quote }}
{{- else }}
- name: DEFENSECLAW_HOME
  value: /var/lib/defenseclaw/run/home
{{- end }}
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
{{/* Leader peers: gateway replicas may call every method; the callout
 only the egress chain check and the controller only registrations,
 lifecycle and activity (leader.Permissions, GAP-0094). */}}
{{- define "dc.peerFlags" -}}
- --peer-bundle=/var/run/ate/credential-bundle.pem
- --peer-trust=/var/run/ate/podidentity-ca.crt
- --peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "gateway") }}
- --callout-peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "callout") }}
- --controller-peer-id={{ include "dc.spiffe" (dict "ctx" . "component" "controller") }}
{{- end -}}

{{/* Where the exposed actor_secrets values are mounted, in the callout and
the gateway: config.substrate.extproc.actor_secrets_dir when set. */}}
{{- define "dc.actorSecretsDir" -}}
{{- dig "substrate" "extproc" "actor_secrets_dir" "/run/defenseclaw/actor-secrets" (.Values.config | default dict) -}}
{{- end -}}

{{/* The exposed actor_secrets Secret, read-only, for exact-value DLP in
the callout (egress) and the gateway (/llm). Never mounted into actors or
the leader. */}}
{{- define "dc.actorSecretsMount" -}}
- name: actor-secrets
  mountPath: {{ include "dc.actorSecretsDir" . }}
  readOnly: true
{{- end -}}
{{- define "dc.actorSecretsVolume" -}}
- name: actor-secrets
  secret:
    secretName: {{ .Values.callout.actorSecrets.secretName }}
    defaultMode: 0440
{{- end -}}

{{/* Optional Secrets of the gateway and leader (absent ones are skipped). */}}
{{- define "dc.gatewaySecretMounts" -}}
# The value-lineage key every replica shares (the chain-key hook creates it).
- name: chain-key
  mountPath: /var/run/secrets/defenseclaw-chain-key
  readOnly: true
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
- name: chain-key
  secret:
    secretName: defenseclaw-chain-key
    optional: true
    defaultMode: 0440
    items:
    - {key: key, path: key}
- name: relay-session
  secret:
    secretName: {{ .Values.gateway.relaySessionSecret }}
    optional: true
    defaultMode: 0440
- name: llm-credentials
  secret:
    secretName: {{ .Values.gateway.llmCredentialsSecret }}
    optional: true
    defaultMode: 0440
{{- with .Values.callout.judge.tokenSecret }}
- name: callout-judge
  secret:
    secretName: {{ . }}
    defaultMode: 0440
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

{{/*
The template trust anchors (admin-only Secret, key anchors.pem), mounted
read-only at the directory of substrate.templates.trust_anchors' default
(config.DefaultSubstrateTemplateAnchors). Both the controller and the
gateway's create path admit templates with them (GAP-0154). A Secret update
reaches the file in about a minute and both re-read it.
*/}}
{{- define "dc.templateAnchorsMount" -}}
{{- if .Values.controller.templateAnchorsSecret -}}
- name: template-anchors
  mountPath: /etc/defenseclaw/substrate/template-anchors
  readOnly: true
{{- end }}
{{- end -}}

{{- define "dc.templateAnchorsVolume" -}}
{{- if .Values.controller.templateAnchorsSecret -}}
- name: template-anchors
  secret:
    secretName: {{ .Values.controller.templateAnchorsSecret }}
    optional: true
    defaultMode: 0440
    items:
    - {key: anchors.pem, path: anchors.pem}
{{- end }}
{{- end -}}

{{/*
The gateway's attach route reaches actor relays through the atenet router
(GAP-0157). It needs the pod identity certificate, so it is on only with pod
certificates.
*/}}
{{- define "dc.routerFlags" -}}
{{- $r := .Values.substrate.router -}}
{{- if and $r.enabled .Values.podCertificates.enabled -}}
- --router-address={{ $r.address | default (printf "atenet-router.%s.svc:8444" .Values.substrate.namespace) }}
{{- with $r.serverName }}
- --router-server-name={{ . }}
{{- end }}
{{- with $r.caFile }}
- --router-ca-file={{ . }}
{{- end }}
- --relay-port={{ $r.relayPort }}
{{- end -}}
{{- end -}}
