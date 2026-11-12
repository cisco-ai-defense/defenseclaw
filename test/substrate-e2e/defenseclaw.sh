# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# The DefenseClaw phase of the Substrate kind E2E. run.sh sources this file; it uses run.sh's helpers
# (check, retry, pass, fail, K, ATE, kctx, proxy_actor, stop_proxies, info) and its E2E_* settings.
#
#   dc_install       build the gateway image from this checkout (or take E2E_GATEWAY_IMAGE), install the chart
#   dc_actor_policy  an actor created in the managed atespace gets its egress policy written by the controller
#   dc_hook_deny     the stub agent posts hook events: a blocked command is denied by the real gateway, a
#                    harmless one is allowed
#   dc_uninstall     helm uninstall leaves no DefenseClaw policy and no open egress

DC_RELEASE=dc
DC_ACTOR=e2e-managed
DC_HOOK_ALLOW='{"hook_event_name":"PreToolUse","session_id":"dc-e2e","cwd":"/work","tool_name":"Bash","tool_input":{"command":"ls"}}'
# AWS instance metadata: refused by the default DefenseClaw rules (rule C2-METADATA-AWS).
DC_HOOK_DENY='{"hook_event_name":"PreToolUse","session_id":"dc-e2e","cwd":"/work","tool_name":"Bash","tool_input":{"command":"curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"}}'

dc_fqdn() { echo "defenseclaw-actor.$E2E_DC_NAMESPACE.svc.cluster.local"; }

# dc_image: print the gateway image reference (repo:tag@digest) the chart should run.
dc_image() {
  if [ -n "$E2E_GATEWAY_IMAGE" ]; then echo "$E2E_GATEWAY_IMAGE"; return 0; fi
  local arch ctx="$E2E_WORKDIR/gateway-ctx" ref="$E2E_REGISTRY/dc-e2e/defenseclaw-gateway:ci-$$"
  arch=$(go env GOARCH) || return 1
  rm -rf "$ctx"; mkdir -p "$ctx/linux-$arch"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$ctx/linux-$arch/defenseclaw-gateway" ./cmd/defenseclaw) >>"$E2E_ARTIFACTS/gateway-build.log" 2>&1 || return 1
  cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/THIRD_PARTY_LICENSES.txt" "$ctx/" || return 1
  docker build -q --build-arg VERSION=e2e -f "$ROOT/deploy/images/gateway/Dockerfile" -t "$ref" "$ctx" >>"$E2E_ARTIFACTS/gateway-build.log" 2>&1 || return 1
  docker push -q "$ref" >>"$E2E_ARTIFACTS/gateway-build.log" 2>&1 || return 1
  local digest
  digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null | sed 's/.*@//')
  [ -n "$digest" ] || return 1
  echo "$ref@$digest"
}

dc_install() {
  local chart="$ROOT/deploy/helm/defenseclaw-substrate" ns=$E2E_DC_NAMESPACE image repo tag digest
  log "DefenseClaw: gateway image and chart"
  if ! image=$(dc_image); then fail "build and push the DefenseClaw gateway image"; return 1; fi
  pass "the DefenseClaw gateway image is available ($(echo "$image" | sed 's/@.*//'))"
  digest=${image#*@}; repo=${image%@*}; tag=${repo##*:}; repo=${repo%:*}
  K create namespace "$ns" >/dev/null 2>&1 || true
  # ate-api-server admits clients only from namespaces with this label (its NetworkPolicy); the bootstrap Job and the
  # controller reach the API from here.
  K label namespace "$ns" ate.dev/api-access=true --overwrite >/dev/null || { fail "label the namespace ate.dev/api-access=true"; return 1; }
  K -n "$ns" delete secret dc-e2e-owner --ignore-not-found >/dev/null 2>&1
  # The one-time owner token the bootstrap Job uses to set up atespaces and access policies; the Job deletes it.
  local tok
  tok=$(K -n ate-system create token ate-client --audience api.ate-system.svc --duration 30m 2>>"$E2E_ARTIFACTS/check.log") || { fail "mint the bootstrap owner token"; return 1; }
  K -n "$ns" create secret generic dc-e2e-owner --from-literal=token="$tok" >/dev/null || { fail "store the bootstrap owner token"; return 1; }
  cat >"$E2E_WORKDIR/dc-values.yaml" <<YAML
image:
  repository: $repo
  tag: "$tag"
  digest: $digest
config:
  substrate:
    # The stub agent template is not attested (that is a separate journey); an unattested template gets no network.
    require_attested_templates: false
    launcher_atespaces:
      engineering: [$E2E_DC_LAUNCH_ATESPACE]
  # An actor in the managed atespace gets the policy of the profile whose match.substrate selects its atespace.
  guardrail:
    profiles:
      e2e:
        mode: action
        block_at: HIGH
    profile_assignments:
    - profile: e2e
      match: {substrate: {atespaces: [$E2E_ATESPACE]}}
managedAtespaces: [$E2E_ATESPACE]
substrate:
  credentialProvider:
    grant: false
bootstrap:
  ownerTokenSecret: dc-e2e-owner
gateway:
  hpa: {enabled: false}
callout:
  hpa: {enabled: false}
leader:
  store:
    size: 1Gi
YAML
  local rc=0
  # shellcheck disable=SC2046
  helm $( [ -n "$E2E_CONTEXT" ] && echo --kube-context "$E2E_CONTEXT" ) install "$DC_RELEASE" "$chart" -n "$ns" -f "$E2E_WORKDIR/dc-values.yaml" --timeout 8m >"$E2E_ARTIFACTS/helm-install.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then tail -n 20 "$E2E_ARTIFACTS/helm-install.log"; fail "helm install of the DefenseClaw chart"; return 1; fi
  pass "helm install of the DefenseClaw chart (the OpenFGA bootstrap Job ran)"
  check "the DefenseClaw deployments are available" K -n "$ns" wait --for=condition=Available deployment --all --timeout=300s
}

dc_actor_policy() {
  log "DefenseClaw: the controller writes the policy of a new actor"
  ATE delete actor "$DC_ACTOR" -a "$E2E_ATESPACE" >/dev/null 2>&1
  check "actor $DC_ACTOR created in the managed atespace" ATE create actor "$DC_ACTOR" -a "$E2E_ATESPACE" --template stub
  local fq; fq=$(dc_fqdn)
  if retry 120 3 bash -c "kubectl-ate $(kctx) get egress-policy $DC_ACTOR -a $E2E_ATESPACE -o yaml 2>/dev/null | grep -q '$fq'"; then
    pass "DefenseClaw wrote an egress policy for the actor that names $fq"
  else
    ATE get egress-policy "$DC_ACTOR" -a "$E2E_ATESPACE" -o yaml >"$E2E_ARTIFACTS/policy-after-wait.yaml" 2>&1
    fail "DefenseClaw wrote an egress policy for the actor that names $fq"
    return 1
  fi
}

# dc_post <body>: the gateway's answer to a hook event the stub agent posts; prints "<http code> <body>".
dc_post() {
  curl -s -m 70 -o "$E2E_WORKDIR/hook.out" -w '%{http_code}' -X POST --data "$1" "http://127.0.0.1:$E2E_PROXY_PORT/hook" | tr -d '\n'
  printf ' '; tr -d '\n' <"$E2E_WORKDIR/hook.out"; echo
}

dc_hook_deny() {
  log "DefenseClaw: a hook event reaches the real gateway"
  if ! proxy_actor "$DC_ACTOR" "$E2E_PROXY_PORT"; then fail "the stub agent answers through the actor proxy"; return 1; fi
  local got
  # The first posts can fail while the new policy and the actor's registration settle.
  if retry 90 4 bash -c "$(declare -f dc_post); E2E_PROXY_PORT=$E2E_PROXY_PORT E2E_WORKDIR=$E2E_WORKDIR; dc_post '$DC_HOOK_ALLOW' | grep -q '^200 '"; then
    got=$(dc_post "$DC_HOOK_ALLOW"); echo "$got" >"$E2E_ARTIFACTS/hook-allow.txt"
    if echo "$got" | grep -qi -E '"(action|verdict)" *: *"(deny|block)"|"decision" *: *"block"'; then
      fail "a harmless command is allowed by the gateway: $got"
    else
      pass "a harmless command (ls) is allowed by the real gateway"
    fi
  else
    fail "the real gateway answers a hook event from the stub agent through egress"
    return 1
  fi
  got=$(dc_post "$DC_HOOK_DENY"); echo "$got" >"$E2E_ARTIFACTS/hook-deny.txt"
  info "deny answer: $(echo "$got" | cut -c1-240)"
  if echo "$got" | grep -qi -E 'deny|block|C2-METADATA-AWS'; then
    pass "a command that reads instance metadata is denied by the real gateway"
  else
    fail "a command that reads instance metadata is denied by the real gateway"
  fi
  stop_proxies
}

dc_uninstall() {
  log "uninstall leaves nothing open"
  local ns=$E2E_DC_NAMESPACE fq rc=0
  fq=$(dc_fqdn)
  # shellcheck disable=SC2046
  helm $( [ -n "$E2E_CONTEXT" ] && echo --kube-context "$E2E_CONTEXT" ) uninstall "$DC_RELEASE" -n "$ns" --timeout 5m >"$E2E_ARTIFACTS/helm-uninstall.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then tail -n 15 "$E2E_ARTIFACTS/helm-uninstall.log"; fail "helm uninstall of the DefenseClaw chart"; return 1; fi
  pass "helm uninstall of the DefenseClaw chart"
  if retry 60 3 bash -c "! kubectl-ate $(kctx) get egress-policy $DC_ACTOR -a $E2E_ATESPACE -o yaml 2>/dev/null | grep -q '$fq'"; then
    pass "no DefenseClaw rule is left in the actor's egress policy"
  else
    ATE get egress-policy "$DC_ACTOR" -a "$E2E_ATESPACE" -o yaml >"$E2E_ARTIFACTS/policy-after-uninstall.yaml" 2>&1
    fail "no DefenseClaw rule is left in the actor's egress policy"
  fi
  if ! proxy_actor "$DC_ACTOR" "$E2E_PROXY_PORT"; then fail "the stub agent answers through the actor proxy after the uninstall"; return 1; fi
  local got
  got=$(fetch_code "$E2E_PROXY_PORT" "$E2E_EGRESS_PROBE_URL")
  case "$got" in 200*) fail "egress to $E2E_EGRESS_PROBE_HOST is closed after the uninstall (got $got)" ;; *) pass "egress to $E2E_EGRESS_PROBE_HOST is closed after the uninstall" ;; esac
  got=$(dc_post "$DC_HOOK_ALLOW")
  case "$got" in 200*) fail "the gateway is unreachable from the actor after the uninstall (got ${got:0:60})" ;; *) pass "the gateway is unreachable from the actor after the uninstall" ;; esac
  stop_proxies
  ATE delete actor "$DC_ACTOR" -a "$E2E_ATESPACE" >/dev/null 2>&1
  K delete namespace "$ns" --ignore-not-found --wait=false >/dev/null 2>&1
}
