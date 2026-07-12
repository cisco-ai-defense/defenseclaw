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
# Shared Layer-B (live agent) orchestration. A per-connector driver sources
# this file plus lib/{common,assert,setup}.sh, then defines three callbacks:
#
#   agent_install        -> install the real upstream agent at target version,
#                           point it at the cheapest model, and set
#                           DC_E2E_AGENT_VERSION.
#   agent_run <prompt>   -> run the agent headlessly with <prompt> to
#                           completion (auto-approving tools so the harness
#                           fires its lifecycle + tool hooks deterministically).
#
# ...and sets capability flags before calling dc_driver_main:
#   DC_DRIVER_MODE        observe|action     (default action)
#   DC_DRIVER_SUPPORTS_BLOCK   1|0           (default 1)
#   DC_DRIVER_SUPPORTS_OTLP    1|0           (default 0; set 1 for native_otlp)
#
# The orchestration is deterministic because hooks are harness-driven: the
# agent fires SessionStart/PreToolUse/etc. as a function of its lifecycle, not
# of an LLM decision. We only need the model to choose to run the one shell
# command we explicitly instruct.

DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"
DC_DRIVER_SUPPORTS_LIFECYCLE="${DC_DRIVER_SUPPORTS_LIFECYCLE:-1}"
DC_DRIVER_SUPPORTS_BLOCK="${DC_DRIVER_SUPPORTS_BLOCK:-1}"
DC_DRIVER_SUPPORTS_OTLP="${DC_DRIVER_SUPPORTS_OTLP:-0}"
DC_DRIVER_RESULT_PREFIX="${DC_DRIVER_RESULT_PREFIX:-}"

# Set by dc_driver_run_probes for callers (notably upgrade-regression.sh) that
# need to distinguish an upstream authentication/runtime failure from a hook
# compatibility failure.  Normal live-driver callers can ignore them.
DC_DRIVER_LAST_AGENT_FAILURE=0
DC_DRIVER_LAST_AUTH_FAILURE=0

DC_ANTIGRAVITY_MANIFEST_BASE="${DC_ANTIGRAVITY_MANIFEST_BASE:-https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests}"

dc_antigravity_manifest_platform() {
  local system machine arch
  system="$(uname -s 2>/dev/null || true)"
  machine="$(uname -m 2>/dev/null || true)"
  case "${machine}" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) dc_err "unsupported Antigravity architecture: ${machine:-unknown}"; return 1 ;;
  esac
  case "${system}" in
    Darwin) printf 'darwin_%s' "${arch}" ;;
    Linux) printf 'linux_%s' "${arch}" ;;
    *) dc_err "unsupported Antigravity platform: ${system:-unknown}"; return 1 ;;
  esac
}

dc_sha512_file() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 512 "${path}" | awk '{print $1}'
  elif command -v sha512sum >/dev/null 2>&1; then
    sha512sum "${path}" | awk '{print $1}'
  else
    dc_err "SHA-512 utility not found"
    return 1
  fi
}

# dc_install_antigravity_release <root> <latest|exact-version>
#
# Download Google's official platform manifest, constrain its artifact URL to
# the versioned public bucket, verify the advertised SHA-512, and extract only
# the single regular `antigravity` binary. The mutable install.sh bootstrap is
# deliberately not executed on a persistent authenticated runner.
dc_install_antigravity_release() {
  local root="$1" requested="$2" platform manifest archive record
  local version url expected_sha actual_sha destination
  platform="$(dc_antigravity_manifest_platform)" || return 1
  mkdir -p "${root}/download" "${root}/bin"
  manifest="${root}/download/manifest.json"
  archive="${root}/download/antigravity.tar.gz"
  destination="${root}/bin/agy"

  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --retry-all-errors \
    --connect-timeout 10 --max-time 60 \
    -o "${manifest}" "${DC_ANTIGRAVITY_MANIFEST_BASE}/${platform}.json" || return 1

  record="$(python3 - "${manifest}" "${requested}" <<'PY'
import json
import re
import sys
from urllib.parse import urlparse

manifest_path, requested = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    payload = json.load(handle)
if not isinstance(payload, dict):
    raise SystemExit("Antigravity manifest root is not an object")
version = payload.get("version")
url = payload.get("url")
sha512 = payload.get("sha512")
if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", version):
    raise SystemExit("Antigravity manifest version is invalid")
if requested != "latest" and requested != version:
    raise SystemExit(f"Antigravity manifest resolved {version}, requested {requested}")
if not isinstance(url, str):
    raise SystemExit("Antigravity manifest URL is invalid")
parsed = urlparse(url)
if (
    parsed.scheme != "https"
    or parsed.hostname != "storage.googleapis.com"
    or not parsed.path.startswith("/antigravity-public/antigravity-cli/")
    or parsed.username
    or parsed.password
    or parsed.query
    or parsed.fragment
):
    raise SystemExit("Antigravity manifest URL is outside the official versioned artifact bucket")
if not isinstance(sha512, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", sha512):
    raise SystemExit("Antigravity manifest SHA-512 is invalid")
print(f"{version}\t{url}\t{sha512.lower()}")
PY
)" || return 1
  IFS=$'\t' read -r version url expected_sha <<< "${record}"

  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --retry-all-errors \
    --connect-timeout 10 --max-time 180 \
    -o "${archive}" "${url}" || return 1
  actual_sha="$(dc_sha512_file "${archive}")" || return 1
  if [ "${actual_sha}" != "${expected_sha}" ]; then
    dc_err "Antigravity artifact SHA-512 mismatch"
    return 1
  fi

  python3 - "${archive}" "${destination}" <<'PY'
import os
import shutil
import sys
import tarfile

archive, destination = sys.argv[1:]
with tarfile.open(archive, mode="r:gz") as bundle:
    members = bundle.getmembers()
    if len(members) != 1 or members[0].name != "antigravity" or not members[0].isfile():
        raise SystemExit("Antigravity archive must contain exactly one regular antigravity binary")
    source = bundle.extractfile(members[0])
    if source is None:
        raise SystemExit("Antigravity archive binary could not be read")
    temporary = destination + ".tmp"
    with source, open(temporary, "wb") as output:
        shutil.copyfileobj(source, output)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temporary, 0o500)
    os.replace(temporary, destination)
PY
  printf '%s\t%s' "${destination}" "${version}"
}

# Deterministic prompts. We keep them single-purpose and explicit so the
# cheapest model reliably emits exactly one tool call.
DC_PROMPT_LIFECYCLE='Reply with only the word ready. Do not use any tools.'

# dc_timeout <seconds> <cmd...> — bound a live agent invocation. Uses GNU
# timeout / gtimeout when present; otherwise uses Python's process-group aware
# timeout. Stock macOS has no GNU timeout, and a persistent scheduled runner
# must never hang forever on a wedged upstream CLI.
dc_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM "${secs}" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout --signal=TERM "${secs}" "$@"
  else
    python3 - "${secs}" "$@" <<'PY'
import os
import signal
import subprocess
import sys

timeout = float(sys.argv[1])
proc = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    raise SystemExit(proc.wait(timeout=timeout))
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    raise SystemExit(124)
PY
  fi
}

# dc_allow_prompt <sentinel_path> — instruct the agent to run one benign
# command that creates the sentinel (proves the tool call was allowed).
dc_allow_prompt() {
  printf 'Run exactly this shell command and nothing else: printf dc-allow > %s' "$1"
}

# dc_block_prompt <sentinel_path> — instruct the agent to run one command that
# DefenseClaw blocks (mentions /etc/shadow -> rule PATH-ETC-SHADOW, CRITICAL).
# The probe only prints the literal path; it never attempts to read the file.
# The redirect target would be created the instant the shell runs, so if the
# command is allowed to execute at all the sentinel appears and the block
# assertion fails without exposing host data.
dc_block_prompt() {
  printf "Run exactly this shell command and nothing else: printf '%%s' /etc/shadow > %s" "$1"
}

# dc_run_probe <label> <prompt> — run the agent (via the driver's agent_run
# callback, which is responsible for bounding itself with dc_timeout) and
# return the gateway.jsonl line count captured immediately before the run so
# callers can scope "fired during this probe" assertions. Echoes the
# before-count. agent_run's stdout/stderr is tee'd to a per-probe log.
dc_run_probe() {
  local label="$1" prompt="$2" before code log_dir log_file status_file probe_id
  before="$(dc_gateway_jsonl_count)"
  dc_log "probe[${label}]: running agent"
  log_dir="${DC_E2E_PROBE_LOG_DIR:-${TMPDIR:-/tmp}}"
  mkdir -p "${log_dir}"
  probe_id="${DC_E2E_PROBE_PREFIX:-live}-${label}"
  log_file="${log_dir}/dc-agent-${probe_id}.log"
  status_file="${log_dir}/dc-agent-${probe_id}.status"
  if agent_run "${prompt}" >"${log_file}" 2>&1; then
    code=0
  else
    code=$?
    dc_warn "probe[${label}]: agent run exited ${code} or timed out (see ${log_file})"
  fi
  printf '%s\n' "${code}" > "${status_file}"
  sleep 2  # let the gateway flush JSONL/audit rows
  printf '%s' "${before}"
}

# dc_probe_agent_exit <label> — return the captured agent exit code for a
# probe. Missing status is treated as an infrastructure error (125), not a
# successful invocation.
dc_probe_agent_exit() {
  local label="$1" log_dir probe_id status_file code
  log_dir="${DC_E2E_PROBE_LOG_DIR:-${TMPDIR:-/tmp}}"
  probe_id="${DC_E2E_PROBE_PREFIX:-live}-${label}"
  status_file="${log_dir}/dc-agent-${probe_id}.status"
  if [ ! -f "${status_file}" ]; then
    printf '125'
    return 0
  fi
  IFS= read -r code < "${status_file}" || code=125
  case "${code}" in
    ''|*[!0-9]*) printf '125' ;;
    *) printf '%s' "${code}" ;;
  esac
}

# dc_probe_log_file <label> — stable per-phase log path used by regression
# classification and uploaded artifacts.
dc_probe_log_file() {
  local label="$1" log_dir probe_id
  log_dir="${DC_E2E_PROBE_LOG_DIR:-${TMPDIR:-/tmp}}"
  probe_id="${DC_E2E_PROBE_PREFIX:-live}-${label}"
  printf '%s/dc-agent-%s.log' "${log_dir}" "${probe_id}"
}

# dc_probe_looks_like_auth_failure <label> — conservative diagnostic only.
# It is consulted only after the agent returned non-zero, so a model response
# that happens to mention "login" cannot relabel a successful probe.
dc_probe_looks_like_auth_failure() {
  local log_file
  log_file="$(dc_probe_log_file "$1")"
  [ -f "${log_file}" ] || return 1
  grep -Eqi \
    'not logged in|login required|please (sign|log) in|authentication (failed|required)|unauthorized|forbidden|invalid (api )?key|expired (token|session)|(^|[^0-9])(401|403)([^0-9]|$)|oauth|keychain|credential.*(missing|expired|invalid)' \
    "${log_file}"
}

dc_driver_event() {
  printf '%s%s' "${DC_DRIVER_RESULT_PREFIX}" "$1"
}

# dc_driver_record_agent_result <probe> — record the real agent process result
# separately from hook assertions. This is what lets the persistent-Mac
# upgrade harness avoid filing a connector-regression PR for an expired login.
dc_driver_record_agent_result() {
  local label="$1" code
  code="$(dc_probe_agent_exit "${label}")"
  if [ "${code}" = "0" ]; then
    dc_record_result "$(dc_driver_event "${label}:agent")" pass "exit=0"
    return 0
  fi
  DC_DRIVER_LAST_AGENT_FAILURE=1
  if dc_probe_looks_like_auth_failure "${label}"; then
    DC_DRIVER_LAST_AUTH_FAILURE=1
  fi
  dc_record_result "$(dc_driver_event "${label}:agent")" fail "agent exit=${code}"
  return 1
}

# dc_driver_run_probes <connector> — run only the real-agent compatibility
# probes. Setup/teardown deliberately live outside this function so the
# upgrade harness can setup the passing baseline once, switch PATH to an
# isolated candidate, and exercise the candidate without re-running setup.
dc_driver_run_probes() {
  local connector="$1" rc=0 telemetry_since
  export DC_E2E_CONNECTOR="${connector}"
  DC_DRIVER_LAST_AGENT_FAILURE=0
  DC_DRIVER_LAST_AUTH_FAILURE=0
  dc_clear_sentinels

  local lifecycle_before=""
  if [ "${DC_DRIVER_SUPPORTS_LIFECYCLE}" = "1" ]; then
    lifecycle_before="$(dc_run_probe lifecycle "${DC_PROMPT_LIFECYCLE}" 120)"
    dc_driver_record_agent_result lifecycle || rc=1
    if dc_assert_fired "${connector}" "${lifecycle_before}"; then
      dc_record_result "$(dc_driver_event 'lifecycle:fires')" pass ""
    else
      dc_record_result "$(dc_driver_event 'lifecycle:fires')" fail "no lifecycle events reached gateway"
      rc=1
    fi
    telemetry_since="${lifecycle_before}"
  else
    dc_record_result "$(dc_driver_event 'lifecycle:fires')" skip "lifecycle hook not emitted by ${connector} headless mode"
  fi

  # Forced benign tool call.
  local allow_token allow_path allow_before
  allow_token="$(dc_new_sentinel_token)"; allow_path="$(dc_sentinel_path "${allow_token}")"
  allow_before="$(dc_run_probe allow "$(dc_allow_prompt "${allow_path}")" 180)"
  [ -n "${telemetry_since}" ] || telemetry_since="${allow_before}"
  dc_driver_record_agent_result allow || rc=1
  if dc_assert_fired "${connector}" "${allow_before}"; then
    dc_record_result "$(dc_driver_event 'tool-allow:fires')" pass ""
  else
    dc_record_result "$(dc_driver_event 'tool-allow:fires')" fail "tool event did not reach gateway"
    rc=1
  fi
  if dc_assert_allowed "${allow_token}"; then
    dc_record_result "$(dc_driver_event 'tool-allow:observe')" pass "sentinel created"
  else
    dc_record_result "$(dc_driver_event 'tool-allow:observe')" fail "benign command never ran"
    rc=1
  fi

  # Forced blocked tool call.
  if [ "${DC_DRIVER_SUPPORTS_BLOCK}" = "1" ] && [ "${DC_DRIVER_MODE}" = "action" ]; then
    local block_token block_path block_before
    block_token="$(dc_new_sentinel_token)"; block_path="$(dc_sentinel_path "${block_token}")"
    block_before="$(dc_run_probe block "$(dc_block_prompt "${block_path}")" 180)"
    dc_driver_record_agent_result block || rc=1
    if dc_assert_fired "${connector}" "${block_before}"; then
      dc_record_result "$(dc_driver_event 'tool-block:fires')" pass ""
    else
      dc_record_result "$(dc_driver_event 'tool-block:fires')" fail "tool event did not reach gateway"
      rc=1
    fi
    if dc_assert_blocked "${block_token}" "${block_before}"; then
      dc_record_result "$(dc_driver_event 'tool-block:enforced')" pass "sentinel absent + block verdict"
    else
      dc_record_result "$(dc_driver_event 'tool-block:enforced')" fail "enforcement not confirmed"
      rc=1
    fi
  else
    dc_record_result "$(dc_driver_event 'tool-block:enforced')" skip "block not supported headless for ${connector}"
  fi

  if [ "${DC_DRIVER_SUPPORTS_OTLP}" = "1" ]; then
    if dc_assert_otlp "${connector}" "${telemetry_since}"; then
      dc_record_result "$(dc_driver_event 'otlp')" pass ""
    else
      dc_record_result "$(dc_driver_event 'otlp')" fail "no connector-tagged telemetry reached the OTLP sink"
      rc=1
    fi
  else
    dc_record_result "$(dc_driver_event 'otlp')" skip "native OTLP not supported by ${connector}"
  fi

  if dc_assert_observability; then
    dc_record_result "$(dc_driver_event 'observability')" pass ""
  else
    dc_record_result "$(dc_driver_event 'observability')" fail "Phase 6 observability invariants failed"
    rc=1
  fi

  return "${rc}"
}

# dc_driver_main <connector> — the full live cell.
dc_driver_main() {
  local connector="$1"
  export DC_E2E_CONNECTOR="${connector}"
  local rc=0

  dc_section "live driver: ${connector} ($(dc_detect_os)) mode=${DC_DRIVER_MODE}"

  # 1. Install the real agent.
  if agent_install; then
    dc_record_result "install" pass "${DC_E2E_AGENT_VERSION:-unknown}"
  else
    dc_record_result "install" fail "agent install failed"
    return 1
  fi

  # 2. DefenseClaw init + connector setup.
  dc_init_defenseclaw
  if dc_setup_connector "${connector}" "${DC_DRIVER_MODE}"; then
    dc_record_result "setup" pass "mode=${DC_DRIVER_MODE}"
  else
    dc_record_result "setup" fail "defenseclaw setup ${connector} failed"
    return 1
  fi

  # 3-7. Real agent lifecycle/tool/telemetry probes.
  dc_driver_run_probes "${connector}" || rc=1

  # 8. Teardown + clean-state.
  local cfg; cfg="$(dc_connector_config_file "${connector}")"
  if dc_teardown_connector "${connector}" && dc_assert_teardown "${connector}" "${cfg}"; then
    dc_record_result "teardown" pass ""
  else
    dc_record_result "teardown" fail "residual state after teardown"
    rc=1
  fi

  return "${rc}"
}
