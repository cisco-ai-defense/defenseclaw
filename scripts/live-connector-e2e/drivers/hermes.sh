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
# Genuine-client Hermes Agent macOS validation.
#
# This driver uses the official installer and the official `hermes hooks test`
# command. It needs no model-provider credential: Hermes itself loads the
# resolved HERMES_HOME/config.yaml, serializes its synthetic hook payload,
# launches DefenseClaw with shlex.split + shell=False, and parses the response.
#
# Certification remains pending until this runs against a packaged
# DefenseClaw artifact on a durable hosted macOS run. A local pass is useful
# evidence but must not stamp validated_versions.json.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"

DC_E2E_CONNECTOR=hermes
export DC_E2E_CONNECTOR
HERMES_HOME="${HERMES_HOME:-${HOME}/.hermes}"
export HERMES_HOME
HERMES_RELEASE_TAG=""
HERMES_RELEASE_COMMIT=""
installer="${TMPDIR:-/tmp}/dc-e2e-hermes-installer-$$.sh"
baseline=""
block_payload=""
doctor_json=""

cleanup() {
  rm -f "${installer}" "${baseline}" "${block_payload}" "${doctor_json}"
}
trap cleanup EXIT

if [ "$(dc_detect_os)" != "macos" ]; then
  dc_record_result "live" skip "genuine Hermes driver is currently scoped to macOS"
  exit 0
fi

requested="${DC_E2E_AGENT_VERSION_REQUEST:-latest}"
if [ "${requested}" != "latest" ]; then
  dc_record_result "install" fail "Hermes official installer driver supports version=latest only (requested ${requested})"
  exit 1
fi

dc_section "genuine Hermes Agent macOS validation"

release_meta="$(python3 - <<'PY'
import json
import urllib.request

repo = "NousResearch/hermes-agent"
headers = {"Accept": "application/vnd.github+json", "User-Agent": "defenseclaw-live-e2e"}
def get(url):
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)

release = get(f"https://api.github.com/repos/{repo}/releases/latest")
tag = release["tag_name"]
ref = get(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}")["object"]
if ref["type"] == "tag":
    ref = get(f"https://api.github.com/repos/{repo}/git/tags/{ref['sha']}")["object"]
if ref["type"] != "commit":
    raise SystemExit(f"latest tag {tag} did not peel to a commit")
print(f"{tag}\t{ref['sha']}")
PY
)"
IFS=$'\t' read -r HERMES_RELEASE_TAG HERMES_RELEASE_COMMIT <<EOF
${release_meta}
EOF
if [ -z "${HERMES_RELEASE_TAG}" ] || ! printf '%s' "${HERMES_RELEASE_COMMIT}" | grep -Eq '^[0-9a-f]{40}$'; then
  dc_record_result "release-resolution" fail "could not resolve the latest official tag to an immutable commit"
  exit 1
fi
dc_record_result "release-resolution" pass "${HERMES_RELEASE_TAG} -> ${HERMES_RELEASE_COMMIT}"

curl -fsSL https://hermes-agent.nousresearch.com/install.sh -o "${installer}"
bash "${installer}" \
  --commit "${HERMES_RELEASE_COMMIT}" \
  --force-commit \
  --skip-setup \
  --skip-browser \
  --no-skills \
  --non-interactive
export PATH="${HOME}/.local/bin:${PATH}"
hermes_cmd="${HOME}/.local/bin/hermes"
if [ ! -x "${hermes_cmd}" ]; then
  dc_record_result "install" fail "official installer completed but hermes is not on PATH"
  exit 1
fi

DC_E2E_AGENT_VERSION="$(dc_capture_version hermes "${hermes_cmd}" --version)"
export DC_E2E_AGENT_VERSION
if ! python3 - "${DC_E2E_AGENT_VERSION}" <<'PY'
import re
import sys

match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", sys.argv[1])
if not match:
    raise SystemExit(1)
version = tuple(map(int, match.groups()))
raise SystemExit(0 if (0, 19, 0) <= version < (0, 20, 0) else 1)
PY
then
  dc_record_result "version" fail "latest official Hermes version is outside hermes-hooks-v1: ${DC_E2E_AGENT_VERSION}"
  exit 1
fi
dc_record_result "version" pass "${DC_E2E_AGENT_VERSION}; ${HERMES_RELEASE_TAG}@${HERMES_RELEASE_COMMIT}"

dc_init_defenseclaw

cfg="$(dc_connector_config_file hermes)"
baseline="${TMPDIR:-/tmp}/dc-e2e-hermes-config-$$.baseline"
baseline_state=missing
if [ -f "${cfg}" ]; then
  cp "${cfg}" "${baseline}"
  baseline_state=present
fi

dc_setup_connector hermes action

if python3 - "${cfg}" <<'PY'
import sys
import yaml

expected = {
    "pre_tool_call", "post_tool_call", "transform_terminal_output",
    "transform_tool_result", "transform_llm_output", "pre_llm_call",
    "post_llm_call", "pre_verify", "pre_api_request", "post_api_request",
    "api_request_error", "on_session_start", "on_session_end",
    "on_session_finalize", "on_session_reset", "subagent_start",
    "subagent_stop", "pre_gateway_dispatch", "pre_approval_request",
    "post_approval_response", "kanban_task_claimed",
    "kanban_task_completed", "kanban_task_blocked",
}
with open(sys.argv[1], encoding="utf-8") as handle:
    document = yaml.safe_load(handle) or {}
hooks = document.get("hooks")
if document.get("hooks_auto_accept") is not True:
    raise SystemExit("hooks_auto_accept is not true")
if not isinstance(hooks, dict) or set(hooks) != expected:
    raise SystemExit(f"Hermes hook inventory mismatch: {sorted(hooks or {})}")
for event, handlers in hooks.items():
    if not isinstance(handlers, list) or len(handlers) != 1:
        raise SystemExit(f"{event} does not have exactly one DefenseClaw handler")
    handler = handlers[0]
    if handler.get("timeout") != 30:
        raise SystemExit(f"{event} timeout is not 30 seconds")
PY
then
  dc_record_result "hook-inventory" pass "all 23 official v0.19 events registered"
else
  dc_record_result "hook-inventory" fail "generated config does not match official v0.19 inventory"
  exit 1
fi

doctor_json="${TMPDIR:-/tmp}/dc-e2e-hermes-doctor-$$.json"
defenseclaw doctor --json-output >"${doctor_json}" 2>/dev/null || true
if python3 - "${doctor_json}" pass <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
rows = [row for row in result.get("checks", []) if row.get("label") == "Hermes hooks (preview; fail-open)"]
raise SystemExit(0 if rows and rows[-1].get("status") == sys.argv[2] else 1)
PY
then
  dc_record_result "doctor-complete-contract" pass "Doctor accepted the exact 23-event contract"
else
  dc_record_result "doctor-complete-contract" fail "Doctor did not accept the generated Hermes contract"
  exit 1
fi

# Stop reconciliation so the deliberately incomplete config remains stable
# long enough for Doctor to inspect it; the subsequent setup restarts/heals.
defenseclaw-gateway stop
python3 - "${cfg}" <<'PY'
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as handle:
    document = yaml.safe_load(handle) or {}
document["hooks"].pop("pre_tool_call", None)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    yaml.safe_dump(document, handle, sort_keys=False)
PY
defenseclaw doctor --json-output >"${doctor_json}" 2>/dev/null || true
if python3 - "${doctor_json}" fail <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
rows = [row for row in result.get("checks", []) if row.get("label") == "Hermes hooks (preview; fail-open)"]
raise SystemExit(0 if rows and rows[-1].get("status") == sys.argv[2] else 1)
PY
then
  dc_record_result "doctor-tamper" pass "Doctor rejected a missing required event"
else
  dc_record_result "doctor-tamper" fail "Doctor accepted a partial Hermes contract"
  exit 1
fi
dc_setup_connector hermes action

before="$(dc_event_cursor)"
allow_output="$("${hermes_cmd}" hooks test pre_tool_call --for-tool terminal 2>&1)"
dc_wait_for_connector_event hermes "${before}" || true
if dc_assert_fired hermes "${before}" && printf '%s' "${allow_output}" | grep -q 'parsed: <none'; then
  dc_record_result "official-pre-tool-allow" pass "Hermes launched the hook and parsed allow"
else
  dc_record_result "official-pre-tool-allow" fail "${allow_output}"
  exit 1
fi

block_payload="${TMPDIR:-/tmp}/dc-e2e-hermes-block-$$.json"
python3 - "${block_payload}" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"args": {"command": "cat /etc/shadow"}}, handle)
PY

before="$(dc_event_cursor)"
block_output="$("${hermes_cmd}" hooks test pre_tool_call --for-tool terminal --payload-file "${block_payload}" 2>&1)"
dc_wait_for_connector_event hermes "${before}" || true
if dc_assert_fired hermes "${before}" \
  && dc_assert_verdict_block "${before}" \
  && printf '%s' "${block_output}" | grep -Eq '"action": "block"'; then
  dc_record_result "official-pre-tool-block" pass "Hermes parsed DefenseClaw's canonical block response"
else
  dc_record_result "official-pre-tool-block" fail "${block_output}"
  exit 1
fi

if dc_assert_observability; then
  dc_record_result "audit-correlation" pass "canonical audit/OTEL hook evidence present"
else
  dc_record_result "audit-correlation" fail "canonical audit validation failed"
  exit 1
fi

if dc_teardown_connector hermes \
  && dc_assert_teardown hermes "${cfg}" "${baseline}" "${baseline_state}"; then
  dc_record_result "teardown" pass "exact HERMES_HOME config state restored"
else
  dc_record_result "teardown" fail "HERMES_HOME lifecycle did not restore exact state"
  exit 1
fi
