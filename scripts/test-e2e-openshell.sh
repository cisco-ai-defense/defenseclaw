#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Live end-to-end test of the DefenseClaw OpenShell sandbox integration.
#
# Runs on a host with OpenShell 0.1.x (gateway running, docker driver, bind
# mounts enabled), Docker, git, Python 3 and the openshell CLI on PATH. It
#
#   1. checks the host with `defenseclaw-gateway sandbox doctor`;
#   2. runs TestSandboxDaemon: the daemon REST lifecycle with the mock
#      Anthropic server (hooks at the ingress, the DefenseClaw-blocked marker
#      command, egress allow/block/unblock, direct-connection triage,
#      stop/start with a rotated binding, review, undo, delete);
#   3. runs TestSandboxCLI: the same through the `sandbox` commands
#      (`run claude --detach`, `run codex`, masked .env, live edit on the
#      host, the nested-repository guard, undo, unblock, approvals, the shell
#      wrapper toggle, a teardown dry run);
#   4. runs TestSandboxTUICodex (needs tmux, skipped without it): the real
#      Codex TUI in a tmux terminal next to `codex exec`, with the hook
#      matrix per mode, the block and its reason on screen, hook tamper,
#      --safe approvals, exit/undo and the typed shell wrapper.
#
# Every OpenShell object is named after DEFENSECLAW_E2E_PREFIX and deleted at
# the end; the OpenShell gateway itself is never reconfigured or restarted.
#
# Usage:
#   DEFENSECLAW_E2E_WORK_DIR=/data/dc-openshell/scratch/e2e \
#   DEFENSECLAW_E2E_PREFIX=dc-e2e scripts/test-e2e-openshell.sh [go test -run pattern]
#
# Environment:
#   DEFENSECLAW_E2E_WORK_DIR   scratch directory (required; keeps logs of the last run)
#   DEFENSECLAW_E2E_PREFIX     name prefix of every OpenShell object (default dc-e2e)
#   DEFENSECLAW_E2E_BEDROCK=1  add real-model runs on Amazon Bedrock (Claude Code on
#                              anthropic.claude-haiku-4-5, Codex on openai.gpt-oss-20b).
#                              Uses AWS_BEARER_TOKEN_BEDROCK, or mints a short-term key
#                              from the ambient AWS identity.
#   DEFENSECLAW_E2E_KEEP_IMAGE=1  keep the harness images the run built
#   DEFENSECLAW_E2E_TIMEOUT    go test timeout (default 120m)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

die() { echo "test-e2e-openshell: $*" >&2; exit 2; }

[ -n "${DEFENSECLAW_E2E_WORK_DIR:-}" ] || die "set DEFENSECLAW_E2E_WORK_DIR to a scratch directory"
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) die "OpenShell sandboxes run on Linux and macOS only" ;;
esac
for bin in go docker git python3 openshell; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin is not on PATH"
done
prefix="${DEFENSECLAW_E2E_PREFIX:-dc-e2e}"
case "$prefix" in
  *[!a-z0-9-]*|-*|"") die "DEFENSECLAW_E2E_PREFIX must be lowercase letters, digits and '-'" ;;
esac
export DEFENSECLAW_E2E_PREFIX="$prefix"
mkdir -p "$DEFENSECLAW_E2E_WORK_DIR"

if [ "${DEFENSECLAW_E2E_BEDROCK:-}" = "1" ] && [ -z "${AWS_BEARER_TOKEN_BEDROCK:-}" ]; then
  venv="$DEFENSECLAW_E2E_WORK_DIR/bedrock-venv"
  if [ ! -x "$venv/bin/python" ]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet aws-bedrock-token-generator
  fi
  AWS_BEARER_TOKEN_BEDROCK="$("$venv/bin/python" test/e2e/openshell/bedrock_token.py --region "${AWS_REGION:-us-east-1}")"
  export AWS_BEARER_TOKEN_BEDROCK
  echo "test-e2e-openshell: minted a short-term Bedrock key"
fi

echo "== host check"
bin="$DEFENSECLAW_E2E_WORK_DIR/doctor-bin/defenseclaw-gateway"
mkdir -p "$(dirname "$bin")"
go build -o "$bin" ./cmd/defenseclaw
# The doctor's daemon and image checks need a configured DefenseClaw; the
# host checks do not. Only the host checks gate the run.
doctor_json="$("$bin" sandbox doctor --output json 2>/dev/null || true)"
python3 - "$doctor_json" <<'PY'
import json
import sys

try:
    report = json.loads(sys.argv[1] or "{}")
except json.JSONDecodeError:
    print("sandbox doctor printed no report; continuing with the Go tests' own checks")
    sys.exit(0)
host = {"platform", "user", "landlock", "docker", "gateway-service", "openshell-cli",
        "gateway-registration", "mtls-permissions", "gateway-version", "gateway-driver", "bind-mounts"}
failed = [c for c in report.get("checks", []) if c.get("id") in host and c.get("status") == "fail"]
for c in report.get("checks", []):
    print(f"  {c.get('status', '?'):5} {c.get('id')}: {c.get('detail', '')}"[:200])
if failed:
    print("the host is not ready for sandboxes: " + ", ".join(c["id"] for c in failed))
    sys.exit(1)
PY

pattern="${1:-TestSandboxDaemon|TestSandboxCLI|TestSandboxTUICodex}"
echo "== go test -run '$pattern'"
go test -tags openshell_integration ./test/e2e/openshell/ -run "$pattern" -count=1 -v \
  -timeout "${DEFENSECLAW_E2E_TIMEOUT:-120m}" 2>&1 | tee "$DEFENSECLAW_E2E_WORK_DIR/go-test.log"
status=${PIPESTATUS[0]}
echo "== summary"
grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS|FAIL|ok )' "$DEFENSECLAW_E2E_WORK_DIR/go-test.log" | grep -E -- '--- |^(ok|FAIL|PASS)' || true
exit "$status"
