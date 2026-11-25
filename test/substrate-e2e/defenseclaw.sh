# shellcheck shell=bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# The DefenseClaw phase of the Substrate kind E2E. run.sh sources this file; it uses run.sh's helpers
# (check, retry, pass, fail, K, ATE, kctx, proxy_actor, stop_proxies, info) and its E2E_* settings.
#
#   dc_install       build the gateway image from this checkout (or take E2E_GATEWAY_IMAGE), install the chart
#   dc_actor_policy  an actor created in the managed atespace gets its egress policy written by the controller
#   dc_attributed_hook  the stub agent of an actor made outside DefenseClaw posts a hook event: the real gateway
#                    reports its step (its unattested template names no connector) and does not block it
#   dc_launcher_hook an actor the launcher created: a harmless command is allowed, a metadata read is blocked
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

# dc_scanner_image: print the skill scanner sidecar image reference (repo:tag@digest) the chart should run
# (gateway.skillScanner; the chart default is off, GAP-1103, so dc_install turns it on). E2E_SCANNER_IMAGE=repo:tag@sha256:... uses an image that is already in a
# registry the cluster reads; empty builds one from this checkout like the release does
# (scripts/release/substrate-images.sh): deploy/images/scanner/Dockerfile around this checkout's gateway,
# defenseclaw-scanners and the scanner runtime of the managed Linux package (packaging/unix/build-scanner-runtime.sh,
# which needs uv, npm and network), so the smoke test runs the sidecar and checks it is ready (GAP-1071).
dc_scanner_image() {
  if [ -n "$E2E_SCANNER_IMAGE" ]; then echo "$E2E_SCANNER_IMAGE"; return 0; fi
  local arch ctx="$E2E_WORKDIR/scanner-ctx" ref="$E2E_REGISTRY/dc-e2e/defenseclaw-scanner:ci-$$" log="$E2E_ARTIFACTS/scanner-build.log"
  arch=$(go env GOARCH) || return 1
  rm -rf "$ctx"; mkdir -p "$ctx/linux-$arch"
  (cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$ctx/linux-$arch/defenseclaw-gateway" ./cmd/defenseclaw &&
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$ctx/linux-$arch/defenseclaw-scanners" ./cmd/defenseclaw-scanners) >>"$log" 2>&1 || return 1
  "$ROOT/packaging/unix/build-scanner-runtime.sh" --target "linux-$arch" --out-dir "$ctx/linux-$arch/scanner-runtime" >>"$log" 2>&1 || return 1
  cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/THIRD_PARTY_LICENSES.txt" "$ctx/" || return 1
  docker build -q --build-arg VERSION=e2e -f "$ROOT/deploy/images/scanner/Dockerfile" -t "$ref" "$ctx" >>"$log" 2>&1 || return 1
  docker push -q "$ref" >>"$log" 2>&1 || return 1
  local digest
  digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null | sed 's/.*@//')
  [ -n "$digest" ] || return 1
  echo "$ref@$digest"
}

dc_install() {
  local chart="$ROOT/deploy/helm/defenseclaw-substrate" ns=$E2E_DC_NAMESPACE image repo tag digest simage srepo stag sdigest
  log "DefenseClaw: gateway and skill scanner images and chart"
  if ! image=$(dc_image); then fail "build and push the DefenseClaw gateway image"; return 1; fi
  pass "the DefenseClaw gateway image is available (${image%%@*})"
  digest=${image#*@}; repo=${image%@*}; tag=${repo##*:}; repo=${repo%:*}
  if ! simage=$(dc_scanner_image); then tail -n 20 "$E2E_ARTIFACTS/scanner-build.log" 2>/dev/null; fail "build and push the DefenseClaw skill scanner image"; return 1; fi
  pass "the DefenseClaw skill scanner image is available (${simage%%@*})"
  sdigest=${simage#*@}; srepo=${simage%@*}; stag=${srepo##*:}; srepo=${srepo%:*}
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
      default: [$E2E_DC_LAUNCH_ATESPACE]
  # The default profile only observes; the smoke test needs a gateway that blocks.
  # An actor in the managed atespace gets the policy of the profile whose match.substrate selects its atespace.
  guardrail:
    mode: action
    block_at: HIGH
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
  skillScanner:
    enabled: true
    image:
      repository: $srepo
      tag: "$stag"
      digest: $sdigest
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
  # The gateway asks its skill scanner sidecar at start whether skill-scanner runs (up to a minute) and logs the answer.
  if retry 120 5 bash -c "kubectl $(kctx) -n $ns logs deploy/defenseclaw-gateway -c gateway 2>/dev/null | grep -q 'substrate: skill scanner ready'"; then
    pass "the gateway's skill scanner sidecar is ready"
  else
    K -n "$ns" logs deploy/defenseclaw-gateway -c skill-scanner --tail=40 >"$E2E_ARTIFACTS/skill-scanner.log" 2>&1
    fail "the gateway's skill scanner sidecar is ready"
  fi
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

dc_attributed_hook() {
  log "DefenseClaw: a hook event of an actor made outside DefenseClaw reaches the real gateway"
  if ! proxy_actor "$DC_ACTOR" "$E2E_PROXY_PORT"; then fail "the stub agent answers through the actor proxy"; return 1; fi
  local got
  # The first posts can fail while the new policy and the actor's registration settle.
  if retry 90 4 bash -c "$(declare -f dc_post); E2E_PROXY_PORT=$E2E_PROXY_PORT E2E_WORKDIR=$E2E_WORKDIR; dc_post '$DC_HOOK_ALLOW' | grep -q '^200 '"; then
    got=$(dc_post "$DC_HOOK_ALLOW"); echo "$got" >"$E2E_ARTIFACTS/hook-allow.txt"
    # The actor was made with kubectl ate, so its registration is attributed, and its stub template is not attested:
    # DefenseClaw knows no connector for it and can't put its tool steps in the chain window. The step is reported,
    # never skipped silently, and the alert does not block it (GAP-0339, GAP-0347). The gateway log names the reason.
    # The allow of the same command is proven for the launcher-created actor, whose registration names its connector.
    if echo "$got" | grep -q '^200 ' && echo "$got" | grep -q '"would_block":false' &&
      echo "$got" | grep -q 'SUBSTRATE-CHAIN-UNRECORDED' && ! echo "$got" | grep -q '"action":"block"'; then
      pass "a harmless command of an actor with no known connector is reported, not blocked (SUBSTRATE-CHAIN-UNRECORDED)"
    else
      fail "a harmless command of an actor with no known connector is reported, not blocked: $got"
    fi
  else
    fail "the real gateway answers a hook event from the stub agent through egress"
    return 1
  fi
  # The deny is proven for an actor the launcher created (dc_launcher_hook): only that registration carries the
  # connector the gateway inspects the hook for.
  stop_proxies
}

# dc_launcher_hook: the real launcher create flow. A person signs in with a Kubernetes bearer (E2E_KUBE_TOKEN, set by
# kube_user_setup in create mode; an existing cluster passes its own), POSTs to the admin listener to create an actor,
# and the registration carries the connector. The hook post of the stub agent is then inspected: the metadata read
# is blocked by the real gateway.
dc_launcher_hook() {
  log "DefenseClaw: an actor created through the launcher flow"
  if [ -z "${E2E_KUBE_TOKEN:-}" ]; then
    if [ "$E2E_REQUIRE_DEFENSECLAW" = 1 ]; then
      fail "a Kubernetes user token exists for the launcher create flow (E2E_KUBE_TOKEN; create mode adds one)"
    else
      skip "the launcher create flow: no Kubernetes user token (E2E_KUBE_TOKEN; create mode adds one)"
    fi
    return 0
  fi
  local ns=$E2E_DC_NAMESPACE la=$E2E_DC_LAUNCH_ATESPACE hdr="$E2E_WORKDIR/auth.hdr" tpl="$E2E_WORKDIR/launch-template.yaml" port=18443
  # The gateway checks the bearer with a TokenReview and needs the system:auth-delegator role for it. The chart
  # does not grant it (GAP-0153); the test adds the binding.
  check "the gateway may review tokens (test binding)" K create clusterrolebinding dc-e2e-auth-delegator --clusterrole=system:auth-delegator --serviceaccount="$ns:defenseclaw-gateway"
  # The launcher atespace (created by the bootstrap) needs workers and the stub template.
  ATE get atespace "$la" >/dev/null 2>&1 || ATE create atespace "$la" >>"$E2E_ARTIFACTS/check.log" 2>&1
  K apply -f - <<YAML >>"$E2E_ARTIFACTS/check.log" 2>&1
apiVersion: ate.dev/v1
kind: WorkerPool
metadata:
  name: lp
  namespace: $E2E_NAMESPACE
  labels:
    workload: $la
spec:
  replicas: $E2E_LAUNCH_POOL_REPLICAS
  sandboxClasses:
  - name: gvisor
  workerImage: ghcr.io/agent-substrate/substrate/ateworker-gvisor:$E2E_SUBSTRATE_VERSION
  template:
    resources:
      limits: {cpu: "2", memory: 2Gi}
      requests: {cpu: 250m, memory: 512Mi}
YAML
  sed -e "s/atespace: $E2E_ATESPACE/atespace: $la/" -e "s/workload: $E2E_ATESPACE/workload: $la/" "$E2E_WORKDIR/stub-template.yaml" >"$tpl"
  check "actor template stub created in the launcher atespace" ATE create actor-template -f "$tpl"
  if ! retry 300 5 bash -c "kubectl $(kctx) -n $E2E_NAMESPACE get workerpool lp -o jsonpath='{.status.readyReplicas}' | grep -qx $E2E_LAUNCH_POOL_REPLICAS"; then
    # A worker that never schedules is most often a node without the CPU or memory its request asks; say so.
    K -n "$E2E_NAMESPACE" get events --field-selector reason=FailedScheduling -o custom-columns=POD:.involvedObject.name,MESSAGE:.message --no-headers 2>/dev/null | grep '^lp-' | sort -u | head -n 5 | while IFS= read -r l; do info "$l"; done
    fail "launcher worker pool is ready ($E2E_LAUNCH_POOL_REPLICAS workers)"; return 1
  fi

  (umask 077; printf 'Authorization: Bearer %s\n' "$E2E_KUBE_TOKEN" >"$hdr")
  # shellcheck disable=SC2046
  setsid nohup kubectl $(kctx) -n "$ns" port-forward svc/defenseclaw-admin "$port:443" >"$E2E_ARTIFACTS/port-forward.log" 2>&1 </dev/null &
  PROXY_PIDS+=("$!")
  if ! retry 30 1 bash -c "curl -sk -m 3 -o /dev/null https://127.0.0.1:$port/"; then fail "the admin listener answers through a port-forward"; return 1; fi
  local code
  code=$(curl -sk -m 120 -o "$E2E_WORKDIR/create.out" -w '%{http_code}' -X POST -H @"$hdr" -H 'X-DefenseClaw-Client: substrate-e2e' \
    -H 'Content-Type: application/json' -d '{"template":"stub","connector":"claudecode"}' "https://127.0.0.1:$port/api/v1/substrate/actors")
  if [ "$code" != 201 ]; then
    info "create answered $code: $(head -c 300 "$E2E_WORKDIR/create.out")"
    fail "the launcher create flow creates an actor (HTTP $code)"; return 1
  fi
  pass "the launcher create flow creates an actor for a Kubernetes user"
  local name
  name=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("name",""))' "$E2E_WORKDIR/create.out")
  [ -n "$name" ] || { fail "the create answer names the actor"; return 1; }
  info "launcher actor $la/$name"
  if ! proxy_actor "$name" "$E2E_PROXY_PORT" "$la"; then fail "the launcher-created stub agent answers through the actor proxy"; return 1; fi
  local got
  retry 90 4 bash -c "$(declare -f dc_post); E2E_PROXY_PORT=$E2E_PROXY_PORT E2E_WORKDIR=$E2E_WORKDIR; dc_post '$DC_HOOK_ALLOW' | grep -q '^200 '"
  got=$(dc_post "$DC_HOOK_ALLOW"); echo "$got" >"$E2E_ARTIFACTS/launcher-hook-allow.txt"
  if echo "$got" | grep -q '"action":"allow"' && echo "$got" | grep -q '"would_block":false'; then pass "a harmless command (ls) is allowed for a launcher-created actor"; else fail "a harmless command is allowed for a launcher-created actor: $got"; fi
  got=$(dc_post "$DC_HOOK_DENY"); echo "$got" >"$E2E_ARTIFACTS/launcher-hook-deny.txt"
  info "deny answer: $(echo "$got" | cut -c1-240)"
  if echo "$got" | grep -q '^200 ' && echo "$got" | grep -q -E '"action":"block"|"permissionDecision":"deny"'; then
    pass "a command that reads instance metadata is blocked by the real gateway for a launcher-created actor"
  else
    fail "a command that reads instance metadata is blocked by the real gateway for a launcher-created actor: $got"
  fi
  stop_proxies
  ATE delete actor "$name" -a "$la" >/dev/null 2>&1
}

dc_uninstall() {
  log "uninstall leaves nothing open"
  K delete clusterrolebinding dc-e2e-auth-delegator --ignore-not-found >/dev/null 2>&1
  K -n "$E2E_NAMESPACE" delete workerpool lp --ignore-not-found >/dev/null 2>&1
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
