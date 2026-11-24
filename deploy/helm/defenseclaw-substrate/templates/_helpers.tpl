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

{{/* The skill scanner sidecar's image (gateway.skillScanner.image). */}}
{{- define "dc.scannerImage" -}}
{{- $img := .Values.gateway.skillScanner.image -}}
{{- if $img.digest -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" $img.digest) -}}
{{- fail "gateway.skillScanner.image.digest must be sha256:<64 hex>" -}}
{{- end -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else -}}
{{ $img.repository }}:{{ $img.tag | default .Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/*
The skill scanner sidecar's uid and gid: the gateway's, from
podSecurityContext (GAP-0876). The jobs folder (0700) and the worker's
socket (0600) belong to the one user both containers run as; a sidecar of
another user could not read the gateway's jobs, and scanning would be off.
*/}}
{{- define "dc.scannerUser" -}}
{{- $id := index .Values.podSecurityContext .field -}}
{{- if or (not $id) (eq (int64 $id) 0) -}}
{{- fail (printf "gateway.skillScanner needs podSecurityContext.%s set to a non-root id: the scanner sidecar runs as the gateway's user" .field) -}}
{{- end -}}
{{ int64 $id }}
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
{{/*
The admin listener's TLS name for clients inside the cluster. Its serving
certificate is the Substrate servicedns pod certificate, which names each
Service as "<svc>.<ns>.svc" only, never ".svc.cluster.local" (GAP-0186).
Every client that verifies that certificate uses this name: the callout's
judge and ask client, and the launcher endpoint's in-cluster default. Pods
resolve it through the search path; actors never reach the admin Service,
so the fully qualified rule above does not apply to it.
*/}}
{{- define "dc.adminTLSHost" -}}defenseclaw-admin.{{ .Release.Namespace }}.svc{{- end -}}
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
{{- /* No scanner sidecar: the gateway does not scan skills (B5.4), so the
fail mode decides (managed installs refuse new skills). */ -}}
{{- if not .Values.gateway.skillScanner.enabled -}}
{{- $sk := get $sub "skills" | default dict -}}
{{- $sc := get $sk "scan" | default dict -}}
{{- $_ := set $sc "enabled" false -}}
{{- $_ := set $sk "scan" $sc -}}
{{- $_ := set $sub "skills" $sk -}}
{{- end -}}
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
{{- /* Template registry logins (GAP-0190) point at the chart's mount
unless config names a file. */ -}}
{{- if .Values.controller.templateRegistrySecret -}}
{{- $t := get $sub "templates" | default dict -}}
{{- $ra := get $t "registry_auth" | default dict -}}
{{- if not (hasKey $ra "docker_config") }}{{ $_ := set $ra "docker_config" (include "dc.templateRegistryFile" .) }}{{ end -}}
{{- $_ := set $t "registry_auth" $ra -}}
{{- $_ := set $sub "templates" $t -}}
{{- end -}}
{{- if and .Values.bundles.enabled (not (hasKey $sub "bundles")) -}}
{{- $_ := set $sub "bundles" (dict "enabled" true "anchors_file" "/etc/defenseclaw-substrate/bundle-anchors/bundle-anchors.json" "inbox" .Values.bundles.inbox) -}}
{{- end -}}
{{- /* OCI bundle source (GAP-0437, Preview): the chart values render
substrate.bundles.oci unless config sets it. The mounts below give the
credentials and CA paths. */ -}}
{{- if and .Values.bundles.enabled .Values.bundles.oci.enabled -}}
{{- $b := get $sub "bundles" | default dict -}}
{{- if not (hasKey $b "oci") -}}
{{- $o := dict "enabled" true "stages" .Values.bundles.oci.stages -}}
{{- if .Values.bundles.oci.timeout }}{{ $_ := set $o "timeout" .Values.bundles.oci.timeout }}{{ end -}}
{{- if .Values.bundles.oci.authHosts }}{{ $_ := set $o "auth_hosts" .Values.bundles.oci.authHosts }}{{ end -}}
{{- if .Values.bundles.oci.credentialsSecret }}{{ $_ := set $o "credentials_file" (include "dc.bundleOCIAuthFile" .) }}{{ end -}}
{{- if or .Values.bundles.oci.ca.configMap .Values.bundles.oci.ca.secret }}{{ $_ := set $o "ca_file" (include "dc.bundleOCICAFile" .) }}{{ end -}}
{{- $_ := set $b "oci" $o -}}
{{- $_ := set $sub "bundles" $b -}}
{{- end -}}
{{- end -}}
{{- /* The actor token key set (GAP-0194): chart values fill
identity.keys_url and keys_ca_file unless config sets them. */ -}}
{{- $keys := .Values.substrate.actorKeys | default dict -}}
{{- if or $keys.url $keys.caConfigMap -}}
{{- $id := get $sub "identity" | default dict -}}
{{- if and $keys.url (not (hasKey $id "keys_url")) }}{{ $_ := set $id "keys_url" $keys.url }}{{ end -}}
{{- if and $keys.caConfigMap (not (hasKey $id "keys_ca_file")) }}{{ $_ := set $id "keys_ca_file" "/etc/defenseclaw-substrate/actor-keys-ca/ca.crt" }}{{ end -}}
{{- $_ := set $sub "identity" $id -}}
{{- end -}}
{{- /* Dedicated values for substrate.launcher, files and git. Each fills
its config key unless config.substrate sets it: config stays the single
source and wins. An unset value adds nothing; false is a value. */ -}}
{{- $cv := .Values.substrate -}}
{{- range $sect, $keys := dict "launcher" (dict "keyReplay" "key_replay") "files" (dict "push" "push" "sync" "sync") "git" (dict "httpsRewrite" "https_rewrite" "submodules" "submodules" "lfs" "lfs" "pushBranch" "push_branch") -}}
{{- $have := get $cv $sect | default dict -}}
{{- $target := get $sub $sect | default dict -}}
{{- range $v, $k := $keys -}}
{{- if and (hasKey $have $v) (not (hasKey $target $k)) }}{{ $_ := set $target $k (get $have $v) }}{{ end -}}
{{- end -}}
{{- if $target }}{{ $_ := set $sub $sect $target }}{{ end -}}
{{- end -}}
{{- $_ := set $cfg "substrate" $sub -}}
{{- /* GAP-0426: redact before the gateway keeps or sends a record. The
chart's profile is the observability default unless config names one. */ -}}
{{- $obsDefaults := get (get $cfg "observability" | default dict) "defaults" | default dict -}}
{{- if not (hasKey $obsDefaults "redaction_profile") -}}
{{- $obs := get $cfg "observability" | default dict -}}
{{- $_ := set $obsDefaults "redaction_profile" .Values.observability.redactionProfile -}}
{{- $_ := set $obs "defaults" $obsDefaults -}}
{{- $_ := set $cfg "observability" $obs -}}
{{- end -}}
{{- /* Cost for budgets and usage: the gateway prices a call from
observability.pricing and counts nothing without tokenomics, so the chart turns
tokenomics on and seeds the reviewed price table unless config sets them. */ -}}
{{- if .Values.observability.tokenomics.enabled -}}
{{- $obs := get $cfg "observability" | default dict -}}
{{- $tok := get $obs "tokenomics" | default dict -}}
{{- if not (hasKey $tok "enabled") }}{{ $_ := set $tok "enabled" true }}{{ end -}}
{{- $_ := set $obs "tokenomics" $tok -}}
{{- if and .Values.observability.tokenomics.defaultPricing (not (hasKey $obs "pricing")) -}}
{{- $_ := set $obs "pricing" (omit (.Files.Get "files/default-pricing.json" | fromJson) "_comment" "_sources") -}}
{{- end -}}
{{- $_ := set $cfg "observability" $obs -}}
{{- end -}}
{{- /* The local collector (observability.local.enabled) is the try-out
target: export to it unless config names a destination chart-collector
(GAP-0272). Its Service address is private, so the destination allows
private networks, and plain http needs tls.insecure. */ -}}
{{- if .Values.observability.local.enabled -}}
{{- $obs := get $cfg "observability" | default dict -}}
{{- $dests := get $obs "destinations" | default list -}}
{{- $named := false -}}
{{- range $dests }}{{ if eq (toString (get . "name")) "chart-collector" }}{{ $named = true }}{{ end }}{{ end -}}
{{- if not $named -}}
{{- $dest := dict "name" "chart-collector" "kind" "otlp" "protocol" "http/protobuf" "endpoint" (printf "http://defenseclaw-otel-collector.%s.svc:4318" .Release.Namespace) "tls" (dict "insecure" true) "network_safety" (dict "allow_private_networks" true) -}}
{{- $_ := set $obs "destinations" (append $dests $dest) -}}
{{- $_ := set $cfg "observability" $obs -}}
{{- end -}}
{{- end -}}
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
no substrate.identity.oidc.issuer, not a managed install, not turned off by
substrate.identity.kube_sign_in false, and not turned off with
--no-kube-sign-in in custom gateway args. The flag is a Go bool:
--no-kube-sign-in and --no-kube-sign-in=<true value> turn it off, =false
keeps it on, and the last one wins, as the gateway parses it. */}}
{{- define "dc.kubeSignIn" -}}
{{- $issuer := dig "substrate" "identity" "oidc" "issuer" "" (.Values.config | default dict) -}}
{{- $off := eq (toString (dig "substrate" "identity" "kube_sign_in" "" (.Values.config | default dict))) "false" -}}
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

{{/* DEFENSECLAW_HOME outside managed mode: the volume root that holds the
local audit database (audit.db and its write-ahead log) and local state. */}}
{{- define "dc.homeDir" -}}/var/lib/defenseclaw/run{{- end -}}

{{/* A Kubernetes memory quantity in MiB, as an integer: (list quantity key
round), round "up" or "down". It reads a number with an optional exponent
and Ki, Mi, Gi, Ti, k, M, G, T or no unit (bytes), and fails naming key on
anything else (validate.yaml, GAP-0402 and GAP-0537). */}}
{{- define "dc.mib" -}}
{{- $q := toString (index . 0) -}}
{{- $num := regexFind "^[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?" $q -}}
{{- $unit := trimPrefix $num $q -}}
{{- $bytes := dict "" 1 "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 "k" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 -}}
{{- if or (not $num) (not (hasKey $bytes $unit)) -}}
{{- fail (printf "%s %q is not a memory quantity (a number with Ki, Mi, Gi, Ti, k, M, G, T or no unit)" (index . 1) $q) -}}
{{- end -}}
{{- $mib := divf (mulf (float64 $num) (index $bytes $unit)) 1048576 -}}
{{- if eq (index . 2) "up" }}{{ ceil $mib | int }}{{ else }}{{ floor $mib | int }}{{ end -}}
{{- end -}}

{{/* "true" when DEFENSECLAW_HOME is on a disk emptyDir that the init
container gives to the gateway account: every install outside managed mode
unless homeMedium is Memory (GAP-0402). */}}
{{- define "dc.homeOnDisk" -}}
{{- if and (not (include "dc.managed" .)) (ne (toString .Values.homeMedium) "Memory") }}true{{ end -}}
{{- end -}}

{{/* Init containers of a DefenseClaw pod: one gives the volume that holds
the audit store (the managed data volume, or the disk home volume) to the
gateway account with 0700, which the audit store's directory trust check
needs: an emptyDir root is root-owned and world-writable. The gateway image
has no shell, so its own hidden substrate-datadir step does it; it needs
CHOWN and FOWNER as root, nothing else. In managed mode it also writes the
policy volume. */}}
{{- define "dc.initContainers" -}}
{{- $managed := include "dc.managed" . -}}
{{- if or $managed (include "dc.homeOnDisk" .) }}
initContainers:
- name: {{ ternary "data-dir" "home-dir" (not (empty $managed)) }}
  image: {{ include "dc.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  args:
  - substrate-datadir
  - --path={{ ternary (include "dc.managedDataDir" .) (include "dc.homeDir" .) (not (empty $managed)) }}
  - --uid={{ .Values.podSecurityContext.runAsUser }}
  - --gid={{ .Values.podSecurityContext.runAsGroup }}
  - --mode=0700
  {{- if $managed }}
  - --policies={{ include "dc.managedPolicyDir" . }}
  {{- end }}
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
  {{- if $managed }}
  - name: data
    mountPath: {{ include "dc.managedDataDir" . }}
  - name: policies
    mountPath: {{ include "dc.managedPolicyDir" . }}
  {{- else }}
  - name: run
    mountPath: {{ include "dc.homeDir" . }}
  {{- end }}
{{- end }}
{{- end -}}

{{- define "dc.volumes" -}}
- name: config
  configMap:
    name: defenseclaw-config
    # Read-only for everyone (managed: the config trust check wants an
    # admin-owned file nobody else can write).
    defaultMode: 0444
# The audit store's volume is a disk emptyDir that the init container gives
# to the gateway account (0700): the managed data volume, or the home volume
# outside managed mode. A memory home volume (homeMedium Memory) needs no init
# container, as its root is root-owned and sticky (3777), which the trust
# check accepts; it counts against the pod's memory (GAP-0402).
{{- if include "dc.managed" .ctx }}
- name: data
  emptyDir:
    sizeLimit: {{ .ctx.Values.managed.dataSizeLimit }}
- name: policies
  emptyDir:
    sizeLimit: 64Mi
{{- else }}
- name: run
  emptyDir:
    {{- if not (include "dc.homeOnDisk" .ctx) }}
    medium: Memory
    {{- end }}
    sizeLimit: {{ .ctx.Values.homeSizeLimit }}
{{- end }}
- name: tmp
  emptyDir: {}
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
{{- if and .ctx.Values.substrate.actorKeys.caConfigMap (eq .component "gateway") }}
- name: actor-keys-ca
  configMap:
    name: {{ .ctx.Values.substrate.actorKeys.caConfigMap }}
    items:
    - key: ca.crt
      path: ca.crt
    defaultMode: 0444
{{- end }}
{{- if and .ctx.Values.bundles.enabled (has .component (list "controller" "gateway")) }}
- name: bundle-anchors
  secret:
    secretName: {{ .ctx.Values.bundles.anchorsSecret }}
    defaultMode: 0444
{{- end }}
{{- if and .ctx.Values.bundles.enabled (eq .component "controller") }}
{{- if .ctx.Values.bundles.oci.credentialsSecret }}
- name: bundle-oci-auth
  secret:
    secretName: {{ .ctx.Values.bundles.oci.credentialsSecret }}
    defaultMode: 0440
    items:
    - {key: .dockerconfigjson, path: config.json}
{{- end }}
{{- if .ctx.Values.bundles.oci.ca.configMap }}
- name: bundle-oci-ca
  configMap:
    name: {{ .ctx.Values.bundles.oci.ca.configMap }}
    defaultMode: 0444
    items:
    - {key: {{ .ctx.Values.bundles.oci.ca.key | quote }}, path: ca.crt}
{{- else if .ctx.Values.bundles.oci.ca.secret }}
- name: bundle-oci-ca
  secret:
    secretName: {{ .ctx.Values.bundles.oci.ca.secret }}
    defaultMode: 0444
    items:
    - {key: {{ .ctx.Values.bundles.oci.ca.key | quote }}, path: ca.crt}
{{- end }}
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
- name: run
  mountPath: {{ include "dc.homeDir" .ctx }}
{{- end }}
- name: tmp
  mountPath: /tmp
- name: ate
  mountPath: /var/run/ate
  readOnly: true
{{- if and .ctx.Values.podCertificates.enabled .serving }}
- name: servicedns
  mountPath: /run/servicedns.podcert.ate.dev
  readOnly: true
{{- end }}
{{- if and .ctx.Values.substrate.actorKeys.caConfigMap (eq .component "gateway") }}
- name: actor-keys-ca
  mountPath: /etc/defenseclaw-substrate/actor-keys-ca
  readOnly: true
{{- end }}
{{- if and .ctx.Values.bundles.enabled (has .component (list "controller" "gateway")) }}
- name: bundle-anchors
  mountPath: /etc/defenseclaw-substrate/bundle-anchors
  readOnly: true
{{- end }}
{{- if and .ctx.Values.bundles.enabled (eq .component "controller") }}
{{- if .ctx.Values.bundles.oci.credentialsSecret }}
- name: bundle-oci-auth
  mountPath: /etc/defenseclaw-substrate/bundle-oci-auth
  readOnly: true
{{- end }}
{{- if or .ctx.Values.bundles.oci.ca.configMap .ctx.Values.bundles.oci.ca.secret }}
- name: bundle-oci-ca
  mountPath: /etc/defenseclaw-substrate/bundle-oci-ca
  readOnly: true
{{- end }}
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
  value: {{ include "dc.homeDir" . }}/home
{{- end }}
- name: POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- with .Values.clusterName }}
# The k8s.cluster.name resource attribute of the gateway's telemetry
# (Kubernetes has no API that names the cluster, GAP-0454).
- name: DEFENSECLAW_K8S_CLUSTER_NAME
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* Annotations that roll pods when the config changes. */}}
{{- define "dc.podAnnotations" -}}
checksum/config: {{ include "dc.config" .ctx | sha256sum }}
{{- with .ctx.Values.podAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Leader RPC mTLS: the pod-identity bundle and the SPIFFE IDs that may call the leader (A2 serve flags). */}}
{{/* Leader peers: gateway replicas may call every method but the
 controller's publish of its egress callout read (leader.NamedOnly,
 GAP-0553); the callout only the egress chain check, the name lookup of a
 registration and its egress decisions for the telemetry relay; the controller
 only registrations, lifecycle, activity and that publish
 (leader.Permissions, GAP-0094, GAP-0505). */}}
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
- name: relay-ca
  mountPath: /var/run/secrets/defenseclaw-relay-ca
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
- name: relay-ca
  secret:
    secretName: {{ .Values.gateway.relayCASecret }}
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

{{/*
The template registry logins (controller.templateRegistrySecret, a
kubernetes.io/dockerconfigjson Secret): mounted read-only in the controller
and the gateway, the two readers of attestations (GAP-0190). The file is
re-read when the Secret changes.
*/}}
{{/* The OCI bundle source's mounted files (bundles.oci), controller only. */}}
{{- define "dc.bundleOCIAuthFile" -}}/etc/defenseclaw-substrate/bundle-oci-auth/config.json{{- end -}}
{{- define "dc.bundleOCICAFile" -}}/etc/defenseclaw-substrate/bundle-oci-ca/ca.crt{{- end -}}

{{- define "dc.templateRegistryFile" -}}/etc/defenseclaw/substrate/registry-auth/config.json{{- end -}}

{{- define "dc.templateRegistryMount" -}}
- name: template-registry-auth
  mountPath: /etc/defenseclaw/substrate/registry-auth
  readOnly: true
{{- end -}}

{{- define "dc.templateRegistryVolume" -}}
- name: template-registry-auth
  secret:
    secretName: {{ .Values.controller.templateRegistrySecret }}
    optional: true
    defaultMode: 0440
    items:
    - {key: .dockerconfigjson, path: config.json}
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

{{/* The self-service secrets namespace (config.substrate.self_service_secrets.namespace),
or "" when self_service_secrets.mode is off. */}}
{{- define "dc.userSecretsNs" -}}
{{- $ss := dig "substrate" "self_service_secrets" dict (.Values.config | default dict) -}}
{{- if ne (toString (dig "mode" "bindings" $ss)) "off" -}}
{{- dig "namespace" "defenseclaw-user-secrets" $ss -}}
{{- end -}}
{{- end -}}

{{/* The self-service secrets namespace whatever the mode (the hooks revoke its grants when off). */}}
{{- define "dc.userSecretsNsName" -}}
{{- dig "substrate" "self_service_secrets" "namespace" "defenseclaw-user-secrets" (.Values.config | default dict) -}}
{{- end -}}
