{{/* The plan every chart hook Job reads (internal/substrate/setup.ChartPlan), in its env. */}}
{{- define "dc.hookPlan" -}}
{{- $launcher := include "dc.launcherAtespaces" . | fromJsonArray -}}
{{- $p := dict
  "schema" 1
  "release" .Release.Name
  "namespace" .Release.Namespace
  "chart_version" .Chart.Version
  "app_version" .Chart.AppVersion
  "store_schema" (index .Chart.Annotations "defenseclaw.cisco.com/store-schema" | atoi)
  "substrate_namespace" .Values.substrate.namespace
  "supported_versions" (index .Chart.Annotations "defenseclaw.cisco.com/substrate-versions")
  "api" (dict "address" .Values.substrate.apiAddress "audience" .Values.substrate.apiAudience)
  "actor_host" (include "dc.actorHost" .)
  "launcher_atespaces" $launcher
  "writable_atespaces" (include "dc.writableAtespaces" . | fromJsonArray)
  "editors" (list (include "dc.principal" (dict "ctx" . "component" "gateway")) (include "dc.principal" (dict "ctx" . "component" "controller")) (include "dc.principal" (dict "ctx" . "component" "hooks")))
  "global_viewers" (list (include "dc.principal" (dict "ctx" . "component" "gateway")) (include "dc.principal" (dict "ctx" . "component" "controller")) (include "dc.principal" (dict "ctx" . "component" "callout")) (include "dc.principal" (dict "ctx" . "component" "hooks")))
  "credential_provider" (dict "grant" .Values.substrate.credentialProvider.grant "config_map" .Values.substrate.credentialProvider.policyConfigMap "deployment" .Values.substrate.credentialProvider.deployment "secrets_namespace" .Values.substrate.credentialProvider.secretsNamespace)
  "store_state_config_map" "defenseclaw-store-state"
  "controller_deployment" "defenseclaw-controller"
  "owner_token_secret" .Values.bootstrap.ownerTokenSecret
  "delete_owner_token" .Values.bootstrap.deleteTokenAfterUse
  "auth_delegator_binding" (ternary (include "dc.authDelegatorBinding" .) "" (eq (include "dc.kubeSignIn" .) "true"))
-}}
{{- toPrettyJson $p -}}
{{- end -}}

{{/* Annotations of RBAC that exists only while its hooks run: created
before the Jobs (weight -10) and deleted once the hooks succeed. */}}
{{- define "dc.hookRBACAnnotations" -}}
helm.sh/hook: {{ .hooks }}
helm.sh/hook-weight: "-10"
helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
{{- end -}}

{{/* One hook Job: (dict "ctx" $ "name" "pre-upgrade" "hook" "pre-upgrade" "weight" "0" "step" "pre-upgrade" "owner" false). */}}
{{- define "dc.hookJob" -}}
{{- $ := .ctx -}}
apiVersion: batch/v1
kind: Job
metadata:
  name: defenseclaw-{{ .name }}
  labels:
    {{- include "dc.componentLabels" (dict "ctx" $ "component" "hooks") | nindent 4 }}
  annotations:
    helm.sh/hook: {{ .hook }}
    helm.sh/hook-weight: {{ .weight | quote }}
    helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
spec:
  backoffLimit: {{ ternary $.Values.bootstrap.backoffLimit $.Values.hooks.backoffLimit .owner }}
  activeDeadlineSeconds: {{ $.Values.hooks.activeDeadlineSeconds }}
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels:
        {{- include "dc.selector" (dict "ctx" $ "component" "hooks") | nindent 8 }}
    spec:
      restartPolicy: Never
      {{- include "dc.podSpecCommon" (dict "ctx" $ "sa" (.sa | default "hooks") "values" dict) | nindent 6 }}
      containers:
      - name: {{ .step }}
        image: {{ include "dc.image" $ }}
        imagePullPolicy: {{ $.Values.image.pullPolicy }}
        args:
        - substrate-chart
        - {{ .step }}
        - --plan=env:DEFENSECLAW_CHART_PLAN
        - --config=env:DEFENSECLAW_CHART_CONFIG
        {{- if .owner }}
        - --owner-token=/var/run/secrets/ate-owner/token
        {{- end }}
        env:
        # The plan and config ride in the Job itself: a hook ConfigMap would
        # outlive the release (Helm keeps hook resources), and each hook
        # must see its own release's plan (the target one in a rollback).
        - name: DEFENSECLAW_CHART_PLAN
          value: {{ include "dc.hookPlan" $ | quote }}
        - name: DEFENSECLAW_CHART_CONFIG
          value: {{ include "dc.config" $ | quote }}
        - name: DEFENSECLAW_HOME
          value: /tmp/defenseclaw
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        resources:
          {{- toYaml (ternary $.Values.bootstrap.resources $.Values.hooks.resources .owner) | nindent 10 }}
        securityContext:
          {{- toYaml $.Values.containerSecurityContext | nindent 10 }}
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: ate
          mountPath: /var/run/ate
          readOnly: true
        - name: kube-api-token
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
        {{- if .owner }}
        - name: owner-token
          mountPath: /var/run/secrets/ate-owner
          readOnly: true
        {{- end }}
      volumes:
      - name: tmp
        emptyDir: {}
      - name: ate
        projected:
          sources:
          - serviceAccountToken:
              audience: {{ $.Values.substrate.apiAudience }}
              expirationSeconds: 600
              path: token
          {{- if $.Values.podCertificates.enabled }}
          - clusterTrustBundle:
              signerName: servicedns.podcert.ate.dev/identity
              labelSelector:
                matchLabels:
                  podcert.ate.dev/canarying: live
              path: ca.crt
          {{- end }}
      # The Kubernetes API token for the configmap and rollout steps.
      - name: kube-api-token
        projected:
          sources:
          - serviceAccountToken:
              expirationSeconds: 600
              path: token
          - configMap:
              name: kube-root-ca.crt
              items:
              - {key: ca.crt, path: ca.crt}
          - downwardAPI:
              items:
              - path: namespace
                fieldRef: {fieldPath: metadata.namespace}
      {{- if .owner }}
      # Optional: the bootstrap deletes the Secret after use, so on a later
      # upgrade it is absent and the step leaves the grants as they are.
      - name: owner-token
        secret:
          secretName: {{ $.Values.bootstrap.ownerTokenSecret }}
          optional: true
          items:
          - {key: token, path: token}
      {{- end }}
{{- end -}}
