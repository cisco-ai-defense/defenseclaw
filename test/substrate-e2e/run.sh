#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Substrate kind E2E: a scripted smoke test of DefenseClaw on Agent Substrate.
#
# It brings up Agent Substrate (prebuilt release images, gVisor only: hosted runners
# have no KVM), installs the DefenseClaw chart, and checks the behaviour that must
# hold on every change to the Substrate integration:
#
#   substrate   Substrate installs and its control plane answers.
#   workers     A worker pool, an atespace and a template for the stub agent.
#   egress      An actor starts; its egress is denied until a policy allows it, and denied
#               again when the policy is removed (the baseline "uninstall leaves nothing open").
#   defenseclaw The chart installs; actor creation through DefenseClaw writes the policy;
#               a hook deny arrives through the real gateway from the stub agent.
#   uninstall   helm uninstall leaves no DefenseClaw policy and no open egress.
#
# Modes (E2E_CLUSTER_MODE):
#   create    (CI default) ate-setup creates a kind cluster and installs Substrate.
#   existing  use the current kubectl context, whose ate-system is already installed
#             (the dev cluster). Everything this script creates lives in $E2E_NAMESPACE
#             and the atespace $E2E_ATESPACE, and phase "cleanup" removes it again.
#
# Usage: test/substrate-e2e/run.sh [phase ...]    (default: every phase, then cleanup)
# Exit status 0 only when every check passed.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

: "${E2E_CLUSTER_MODE:=create}"
: "${E2E_NAMESPACE:=dc-e2e}"
: "${E2E_ATESPACE:=dc-e2e-gv}"
: "${E2E_ARTIFACTS:=$ROOT/_artifacts/substrate-e2e}"
: "${E2E_WORKDIR:=${RUNNER_TEMP:-/tmp}/substrate-e2e}"
: "${E2E_SUBSTRATE_VERSION:=v1.0.0}"
: "${E2E_SUBSTRATE_REPO:=https://github.com/agent-substrate/substrate.git}"
: "${E2E_SUBSTRATE_SRC:=$E2E_WORKDIR/substrate}"
: "${E2E_KIND_CLUSTER:=kind}"
: "${E2E_REGISTRY:=localhost:5001}"
: "${E2E_POOL_REPLICAS:=2}"
: "${E2E_PROXY_PORT:=18080}"
: "${E2E_EGRESS_PROBE_URL:=https://example.com/}"
: "${E2E_EGRESS_PROBE_HOST:=example.com}"
# 1 makes a missing chart a failure (CI); 0 skips the DefenseClaw phase with a notice.
: "${E2E_REQUIRE_DEFENSECLAW:=0}"
# Where the chart installs, and the gateway image it runs. E2E_GATEWAY_IMAGE=repo:tag@sha256:... uses an image
# that is already in a registry the cluster reads; empty builds one from this checkout.
: "${E2E_DC_NAMESPACE:=defenseclaw-system}"
: "${E2E_DC_LAUNCH_ATESPACE:=dc-e2e-launch}"
: "${E2E_GATEWAY_IMAGE:=}"
# Kubernetes context kubectl and kubectl-ate use. In create mode it is kind-<cluster>.
: "${E2E_CONTEXT:=}"

mkdir -p "$E2E_ARTIFACTS" "$E2E_WORKDIR/bin"
export PATH="$E2E_WORKDIR/bin:$PATH"

RESULTS="$E2E_ARTIFACTS/results.tsv"
: >"$RESULTS"
FAILED=0
PROXY_PIDS=()

log() { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; printf 'pass\t%s\n' "$*" >>"$RESULTS"; }
fail() { printf 'FAIL  %s\n' "$*"; printf 'fail\t%s\n' "$*" >>"$RESULTS"; FAILED=1; }
skip() { printf 'SKIP  %s\n' "$*"; printf 'skip\t%s\n' "$*" >>"$RESULTS"; }

# check "<name>" <command...>: pass when the command exits 0.
check() {
  local name=$1; shift
  if "$@" >>"$E2E_ARTIFACTS/check.log" 2>&1; then pass "$name"; else fail "$name"; fi
}

kctx() { if [ -n "$E2E_CONTEXT" ]; then echo "--context=$E2E_CONTEXT"; fi; }
# shellcheck disable=SC2046
K() { kubectl $(kctx) "$@"; }
# kubectl ate prints a token-file warning on every call.
# shellcheck disable=SC2046
ATE() { kubectl-ate $(kctx) "$@" 2> >(grep -v '^Warning: no --token-file' >&2); }

# retry <seconds> <interval> <command...>
retry() {
  local limit=$1 every=$2; shift 2
  local end=$((SECONDS + limit))
  while :; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    [ "$SECONDS" -ge "$end" ] && return 1
    sleep "$every"
  done
}

stop_proxies() {
  local p
  for p in "${PROXY_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  PROXY_PIDS=()
}

diagnostics() {
  local d="$E2E_ARTIFACTS/diagnostics"
  mkdir -p "$d"
  K get pods -A -o wide >"$d/pods.txt" 2>&1
  K get events -A --sort-by=.lastTimestamp >"$d/events.txt" 2>&1
  K get workerpool,pods -n "$E2E_NAMESPACE" -o yaml >"$d/lane-ns.yaml" 2>&1
  ATE get actor -a "$E2E_ATESPACE" -o yaml >"$d/actors.yaml" 2>&1
  local ns p
  for ns in ate-system "$E2E_NAMESPACE" "$E2E_DC_NAMESPACE"; do
    for p in $(K -n "$ns" get pods -o name 2>/dev/null); do
      K -n "$ns" logs --tail=200 --all-containers "$p" >"$d/log-${ns}-${p#pod/}.txt" 2>&1
    done
  done
}

on_exit() {
  local rc=$?
  stop_proxies
  if [ "$FAILED" -ne 0 ] || [ "$rc" -ne 0 ]; then
    FAILED=1
    log "diagnostics"
    diagnostics
  fi
  log "summary"
  awk -F'\t' '{n[$1]++} END {printf "pass=%d fail=%d skip=%d\n", n["pass"], n["fail"], n["skip"]}' "$RESULTS"
  exit "$FAILED"
}
trap on_exit EXIT

# ---- phase: tools ----
phase_tools() {
  log "tools"
  local t
  for t in docker kubectl helm git; do
    command -v "$t" >/dev/null 2>&1 || { fail "tool $t is installed"; return 1; }
  done
  # A client already on PATH (a dev box) is used as it is; a runner builds both from the release tag.
  # ate-setup reads its manifests from a checkout of the release it installs, so a new install
  # needs the clone even when the binaries exist.
  if [ ! -d "$E2E_SUBSTRATE_SRC/.git" ] && { [ "$E2E_CLUSTER_MODE" = create ] || ! command -v ate-setup >/dev/null 2>&1 || ! command -v kubectl-ate >/dev/null 2>&1; }; then
    git clone --quiet --depth 1 -c advice.detachedHead=false --branch "$E2E_SUBSTRATE_VERSION" "$E2E_SUBSTRATE_REPO" "$E2E_SUBSTRATE_SRC" || { fail "clone Substrate $E2E_SUBSTRATE_VERSION"; return 1; }
  fi
  if ! command -v ate-setup >/dev/null 2>&1 || ! command -v kubectl-ate >/dev/null 2>&1; then
    (cd "$E2E_SUBSTRATE_SRC" && go build -o "$E2E_WORKDIR/bin/ate-setup" ./cmd/ate-setup && go build -o "$E2E_WORKDIR/bin/kubectl-ate" ./cmd/kubectl-ate) || { fail "build ate-setup and kubectl-ate $E2E_SUBSTRATE_VERSION"; return 1; }
  fi
  # kubectl finds kubectl-ate on PATH as the plugin "kubectl ate".
  pass "tools present, Substrate $E2E_SUBSTRATE_VERSION client available"
}

# ---- phase: substrate ----
phase_substrate() {
  log "substrate"
  if [ "$E2E_CLUSTER_MODE" = create ]; then
    : "${E2E_CONTEXT:=kind-$E2E_KIND_CLUSTER}"
    cat >"$E2E_WORKDIR/substrate-install.yaml" <<YAML
apiVersion: install.ate.dev/v1alpha1
kind: SubstrateInstall
namespace: ate-system
kindCluster:
  enabled: true
  name: $E2E_KIND_CLUSTER
sandboxClasses: gvisor
atenet:
  dataplane: envoy
  egress:
    credentialProvider: '{"name":"k8s.io"}'
ingressAllowedSPIFFEIDs: spiffe://cluster.local/ns/ate-system/sa/atenet-client
images:
  repo: ghcr.io/agent-substrate/substrate
  tag: $E2E_SUBSTRATE_VERSION
storage:
  bucketName: ate-snapshots
rolloutTimeout: 5m0s
YAML
    export E2E_CONTEXT
    # ate-setup does not create the cluster. The release's own script creates it (and the local
    # registry on localhost:5001); it also probes /dev/kvm and mounts it when there is one.
    if (cd "$E2E_SUBSTRATE_SRC" && KIND_CLUSTER_NAME="$E2E_KIND_CLUSTER" hack/create-kind-cluster.sh) >"$E2E_ARTIFACTS/kind-create.log" 2>&1; then
      pass "kind cluster $E2E_KIND_CLUSTER created"
    else
      tail -n 30 "$E2E_ARTIFACTS/kind-create.log"
      fail "kind cluster $E2E_KIND_CLUSTER created"
      return 1
    fi
    if (cd "$E2E_SUBSTRATE_SRC" && ate-setup deploy ate-system --config "$E2E_WORKDIR/substrate-install.yaml") >"$E2E_ARTIFACTS/ate-setup.log" 2>&1; then
      pass "ate-setup installed Substrate $E2E_SUBSTRATE_VERSION on a new kind cluster"
    else
      tail -n 30 "$E2E_ARTIFACTS/ate-setup.log"
      fail "ate-setup installed Substrate $E2E_SUBSTRATE_VERSION on a new kind cluster"
      return 1
    fi
  else
    info "existing cluster: context ${E2E_CONTEXT:-<current>}"
  fi
  check "ate-system deployments are available" K -n ate-system wait --for=condition=Available deployment --all --timeout=300s
  check "the Substrate API answers" ATE get atespace
}

# ---- phase: workers ----
phase_workers() {
  log "workers"
  K create namespace "$E2E_NAMESPACE" >/dev/null 2>&1 || true
  ATE get atespace "$E2E_ATESPACE" >/dev/null 2>&1 || ATE create atespace "$E2E_ATESPACE" >>"$E2E_ARTIFACTS/check.log" 2>&1
  check "atespace $E2E_ATESPACE exists" ATE get atespace "$E2E_ATESPACE"
  K apply -f - <<YAML >>"$E2E_ARTIFACTS/check.log" 2>&1
apiVersion: ate.dev/v1
kind: WorkerPool
metadata:
  name: gv
  namespace: $E2E_NAMESPACE
  labels:
    workload: $E2E_ATESPACE
spec:
  replicas: $E2E_POOL_REPLICAS
  sandboxClasses:
  - name: gvisor
  workerImage: ghcr.io/agent-substrate/substrate/ateworker-gvisor:$E2E_SUBSTRATE_VERSION
  template:
    resources:
      limits: {cpu: "2", memory: 2Gi}
      requests: {cpu: 250m, memory: 512Mi}
YAML
  check "worker pool gv is ready" retry 300 5 bash -c "kubectl $(kctx) -n $E2E_NAMESPACE get workerpool gv -o jsonpath='{.status.readyReplicas}' | grep -qx $E2E_POOL_REPLICAS"
}

# ---- phase: stub (build and push the stub agent image, create its template) ----
stub_image=""
phase_stub() {
  log "stub agent image and template"
  local tag="dc-e2e-$$"
  if ! docker build -q -t "$E2E_REGISTRY/dc-e2e/stub:$tag" "$HERE/stub" >>"$E2E_ARTIFACTS/stub-build.log" 2>&1; then
    fail "build the stub agent image"; return 1
  fi
  if ! docker push -q "$E2E_REGISTRY/dc-e2e/stub:$tag" >>"$E2E_ARTIFACTS/stub-build.log" 2>&1; then
    fail "push the stub agent image to $E2E_REGISTRY"; return 1
  fi
  local digest
  digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$E2E_REGISTRY/dc-e2e/stub:$tag" 2>/dev/null | sed 's/.*@//')
  if [ -z "$digest" ]; then fail "read the stub image digest"; return 1; fi
  stub_image="$E2E_REGISTRY/dc-e2e/stub@$digest"
  info "stub image $stub_image"
  cat >"$E2E_WORKDIR/stub-template.yaml" <<YAML
metadata:
  atespace: $E2E_ATESPACE
  name: stub
workerSelector:
  matchLabels:
    workload: $E2E_ATESPACE
containers:
- name: agent
  image: $stub_image
  env:
  - {name: SSL_CERT_FILE, value: /run/ate/trust-bundle.pem}
  - {name: STUB_HOOK_URL, value: "http://defenseclaw-actor.$E2E_DC_NAMESPACE.svc.cluster.local/api/v1/substrate/hook/claudecode"}
  volumeMounts:
  - {name: system-info, mountPath: /run/ate}
  wakeupProbe:
    httpGet: {path: /readyz, port: 8080}
    timeoutSeconds: 120
volumes:
- name: system-info
  systemInfo:
    dataSources:
    - trustBundle:
        names: [egress-mitm.ate.dev, system-roots.ate.dev]
        path: trust-bundle.pem
resources:
  limits:
    cpuMillicores: 1000
    memoryBytes: 536870912
snapshotConfig:
  preferredFidelity: SNAPSHOT_FIDELITY_MEMORY
YAML
  ATE delete actor-template stub -a "$E2E_ATESPACE" >/dev/null 2>&1
  check "actor template stub created" ATE create actor-template -f "$E2E_WORKDIR/stub-template.yaml"
}

# proxy_actor <actor> <local-port>: forward the stub agent's port 8080.
proxy_actor() {
  setsid nohup kubectl-ate $(kctx) proxy actor "$1" "$2:8080" -a "$E2E_ATESPACE" >"$E2E_ARTIFACTS/proxy-$1.log" 2>&1 </dev/null &
  PROXY_PIDS+=("$!")
  retry 60 1 curl -sf -m 2 "http://127.0.0.1:$2/readyz"
}

# fetch_code <port> <url>: prints the HTTP status the stub agent got, or "error".
fetch_code() {
  curl -s -m 60 --get --data-urlencode "url=$2" "http://127.0.0.1:$1/fetch"
}

# ---- phase: egress ----
phase_egress() {
  log "actor egress is denied by default"
  local actor=e2e-egress port=$E2E_PROXY_PORT
  ATE delete actor "$actor" -a "$E2E_ATESPACE" >/dev/null 2>&1
  check "actor $actor created" ATE create actor "$actor" -a "$E2E_ATESPACE" --template stub
  # A new actor is suspended; the first request through the proxy resumes it.
  if ! proxy_actor "$actor" "$port"; then fail "the stub agent answers through the actor proxy"; return 1; fi
  pass "the stub agent answers through the actor proxy"
  check "actor $actor is running" retry 60 3 bash -c "kubectl-ate $(kctx) get actor $actor -a $E2E_ATESPACE 2>/dev/null | grep -q ACTOR_STATE_RUNNING"

  local got
  got=$(fetch_code "$port" "$E2E_EGRESS_PROBE_URL")
  info "no policy: $got"
  case "$got" in 200*) fail "egress to $E2E_EGRESS_PROBE_HOST is denied with no policy (got $got)" ;; *) pass "egress to $E2E_EGRESS_PROBE_HOST is denied with no policy" ;; esac

  cat >"$E2E_WORKDIR/allow.yaml" <<YAML
rules:
- https:
    hostnames: ["$E2E_EGRESS_PROBE_HOST"]
YAML
  check "egress policy created" ATE create egress-policy "$actor" -a "$E2E_ATESPACE" -f "$E2E_WORKDIR/allow.yaml"
  if retry 60 3 bash -c "[ \"\$(curl -s -m 30 --get --data-urlencode url=$E2E_EGRESS_PROBE_URL http://127.0.0.1:$port/fetch)\" = 200 ]"; then
    pass "egress to $E2E_EGRESS_PROBE_HOST is allowed once a policy names it (positive control)"
  else
    fail "egress to $E2E_EGRESS_PROBE_HOST is allowed once a policy names it (positive control)"
  fi

  check "egress policy deleted" ATE delete egress-policy "$actor" -a "$E2E_ATESPACE"
  if retry 60 3 bash -c "[ \"\$(curl -s -m 30 --get --data-urlencode url=$E2E_EGRESS_PROBE_URL http://127.0.0.1:$port/fetch)\" != 200 ]"; then
    pass "egress is denied again after the policy is removed"
  else
    fail "egress is denied again after the policy is removed"
  fi
  stop_proxies
  # The DefenseClaw controller manages this atespace once the chart is installed: leave no actor of the
  # plain-Substrate phase behind for it.
  ATE delete actor "$actor" -a "$E2E_ATESPACE" >/dev/null 2>&1
}

# ---- phase: defenseclaw ----
phase_defenseclaw() {
  log "DefenseClaw on Substrate"
  local chart="$ROOT/deploy/helm/defenseclaw-substrate"
  if [ ! -d "$chart" ] || [ ! -f "$HERE/defenseclaw.sh" ]; then
    if [ "$E2E_REQUIRE_DEFENSECLAW" = 1 ]; then
      fail "the DefenseClaw chart and test/substrate-e2e/defenseclaw.sh exist"
    else
      skip "the DefenseClaw chart or defenseclaw.sh is not present on this branch yet"
    fi
    return 0
  fi
  # defenseclaw.sh is sourced: it defines dc_install, dc_actor_policy, dc_hook_deny and dc_uninstall
  # with the helpers above (check, retry, ATE, K, proxy_actor, fetch_code).
  # shellcheck disable=SC1091
  . "$HERE/defenseclaw.sh"
  dc_install && dc_actor_policy && dc_hook_deny
}

phase_uninstall() {
  log "uninstall leaves nothing open"
  if declare -F dc_uninstall >/dev/null; then dc_uninstall; else skip "dc_uninstall is not defined (no DefenseClaw phase ran)"; fi
}

phase_cleanup() {
  log "cleanup"
  stop_proxies
  local a
  for a in $(ATE get actor -a "$E2E_ATESPACE" -o json 2>/dev/null | python3 -c 'import sys,json
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
items = d.get("actors", d.get("items", []))
for i in items:
    print((i.get("metadata") or i).get("name", ""))' 2>/dev/null); do
    [ -n "$a" ] && ATE delete actor "$a" -a "$E2E_ATESPACE" >/dev/null 2>&1
  done
  ATE delete actor-template stub -a "$E2E_ATESPACE" >/dev/null 2>&1
  if [ "$E2E_CLUSTER_MODE" = existing ]; then
    K -n "$E2E_NAMESPACE" delete workerpool gv --ignore-not-found >/dev/null 2>&1
    ATE delete atespace "$E2E_ATESPACE" >/dev/null 2>&1
    K delete namespace "$E2E_NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1
  else
    kind delete cluster --name "$E2E_KIND_CLUSTER" >/dev/null 2>&1
  fi
  info "done"
}

PHASES=("$@")
if [ "${#PHASES[@]}" -eq 0 ]; then PHASES=(tools substrate workers stub egress defenseclaw uninstall cleanup); fi
for p in "${PHASES[@]}"; do
  if declare -F "phase_$p" >/dev/null; then
    "phase_$p" || FAILED=1
  else
    echo "unknown phase: $p" >&2; FAILED=1
  fi
done
