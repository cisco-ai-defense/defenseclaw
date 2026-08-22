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
# Live driver for Anthropic Claude Code.
#   - install:  checksum-verified official native release manifest + binary
#   - headless: claude -p "<prompt>" --output-format json
#   - auth:     ANTHROPIC_API_KEY (Anthropic direct) OR Amazon Bedrock when
#               DC_USE_BEDROCK=1 (CLAUDE_CODE_USE_BEDROCK + AWS creds).
#   - hooks:    SessionStart / UserPromptSubmit / PreToolUse / PostToolUse /
#               Stop. PreToolUse deny is honored even when tools are
#               auto-approved, so block enforcement is testable headless.
#   - ask:      Claude's native PermissionRequest "ask" path is NOT reachable
#               headless (no interactive approver), so ask coverage stays in
#               Layer A only — we do not assert it here.
#   - OTLP:     native exporter wired by `defenseclaw setup claude-code`.
#
# Bedrock: when DC_USE_BEDROCK=1 we set CLAUDE_CODE_USE_BEDROCK=1, point the
# model at a Bedrock inference-profile id, and rely on the AWS credential chain
# (AWS_BEARER_TOKEN_BEDROCK, or AWS_ACCESS_KEY_ID/SECRET[/SESSION_TOKEN]) +
# AWS_REGION. The small/fast background model must also be a Bedrock id.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=1

CLAUDE_MODEL="${CLAUDE_MODEL:-claude-haiku-4-5}"

claude_sha256_file() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  else
    dc_err "SHA-256 utility not found"
    return 1
  fi
}

_claude_install_release() {
  local requested="$1"
  local version platform manifest_file manifest_record expected_checksum expected_size
  local download_dir download_path versions_root target staged launcher actual_checksum

  download_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-claude.XXXXXX")" || return 1
  trap 'rm -rf -- "${download_dir:-}"; trap - RETURN' RETURN

  if [ "${requested}" = "latest" ]; then
    curl --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 60 \
      --max-filesize 1024 \
      --output "${download_dir}/latest" \
      https://downloads.claude.ai/claude-code-releases/latest || return 1
    version="$(tr -d '\r\n' < "${download_dir}/latest")"
  else
    version="${requested}"
  fi
  if ! printf '%s' "${version}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    dc_err "invalid Claude Code release version"
    return 1
  fi

  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform="darwin-arm64" ;;
    Darwin-x86_64) platform="darwin-x64" ;;
    Linux-aarch64|Linux-arm64) platform="linux-arm64" ;;
    Linux-x86_64) platform="linux-x64" ;;
    *) dc_err "unsupported Claude Code live platform: $(uname -s)-$(uname -m)"; return 1 ;;
  esac

  manifest_file="${download_dir}/manifest.json"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 60 \
    --max-filesize 1048576 \
    --output "${manifest_file}" \
    "https://downloads.claude.ai/claude-code-releases/${version}/manifest.json" || return 1
  manifest_record="$(python3 - "${manifest_file}" "${platform}" <<'PY'
import json
import re
import sys

path, platform = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    document = json.load(handle)
if not isinstance(document, dict):
    raise SystemExit("Claude Code manifest root is not an object")
platforms = document.get("platforms")
entry = platforms.get(platform) if isinstance(platforms, dict) else None
if not isinstance(entry, dict):
    raise SystemExit("Claude Code manifest lacks the selected platform")
checksum = entry.get("checksum")
size = entry.get("size")
if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
    raise SystemExit("Claude Code manifest checksum is invalid")
if isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > 536_870_912:
    raise SystemExit("Claude Code manifest size is invalid")
print(f"{checksum}\t{size}")
PY
)" || return 1
  IFS=$'\t' read -r expected_checksum expected_size <<< "${manifest_record}"

  download_path="${download_dir}/claude"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 300 \
    --max-filesize 536870912 \
    --output "${download_path}" \
    "https://downloads.claude.ai/claude-code-releases/${version}/${platform}/claude" || return 1
  if [ "$(wc -c < "${download_path}" | tr -d '[:space:]')" != "${expected_size}" ]; then
    dc_err "Claude Code native download size does not match official manifest"
    return 1
  fi
  actual_checksum="$(claude_sha256_file "${download_path}")" || return 1
  if [ "${actual_checksum}" != "${expected_checksum}" ]; then
    dc_err "Claude Code native download digest does not match official manifest"
    return 1
  fi

  versions_root="${HOME}/.local/share/claude/versions"
  target="${versions_root}/${version}"
  staged="${versions_root}/.${version}.defenseclaw-$$"
  launcher="${HOME}/.local/bin/claude"
  mkdir -p "${versions_root}" "${HOME}/.local/bin"
  chmod 0700 "${versions_root}" "${HOME}/.local/bin"
  if [ -e "${target}" ] || [ -L "${target}" ] || [ -e "${launcher}" ] || [ -L "${launcher}" ]; then
    dc_err "refusing to overwrite an existing Claude Code native installation"
    return 1
  fi
  install -m 0500 "${download_path}" "${staged}" || return 1
  actual_checksum="$(claude_sha256_file "${staged}")" || return 1
  if [ "${actual_checksum}" != "${expected_checksum}" ]; then
    dc_err "staged Claude Code native digest does not match official manifest"
    return 1
  fi
  mv "${staged}" "${target}" || return 1
  ln -s "${target}" "${launcher}" || return 1

  # This is the sole stdout value consumed by agent_install. All release
  # resolution, download, parsing, hashing, and publication above runs inside
  # dc_without_provider_credentials, including every child process.
  printf '%s' "${version}"
}

agent_install() {
  local requested="${CLAUDE_VERSION:-${DC_E2E_AGENT_VERSION_REQUEST:-latest}}"
  local version

  version="$(dc_without_provider_credentials _claude_install_release "${requested}")" || return 1
  export PATH="${HOME}/.local/bin:${PATH}"
  export DISABLE_AUTOUPDATER=1
  DC_E2E_AGENT_VERSION="${version}"
  export DC_E2E_AGENT_VERSION

  # Credential-free installer consumers (including enterprise hardening CI)
  # reuse the checksum-verified native release path but stop before auth setup.
  if [ "${DC_E2E_CLIENT_PROVISION_ONLY:-0}" = "1" ]; then
    return 0
  fi

  if [ "${DC_USE_BEDROCK:-0}" = "1" ]; then
    if [ -z "${AWS_BEARER_TOKEN_BEDROCK:-}" ] && [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
      dc_err "DC_USE_BEDROCK=1 needs AWS auth (AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
      return 1
    fi
    export CLAUDE_CODE_USE_BEDROCK=1
    export AWS_REGION="${AWS_REGION:-us-east-1}"
    CLAUDE_MODEL="${CLAUDE_BEDROCK_MODEL:-us.anthropic.claude-haiku-4-5-20251001-v1:0}"
    export ANTHROPIC_MODEL="${CLAUDE_MODEL}"
    export ANTHROPIC_SMALL_FAST_MODEL="${ANTHROPIC_SMALL_FAST_MODEL:-${CLAUDE_MODEL}}"
    dc_log "claude code configured for Bedrock model ${CLAUDE_MODEL} (region ${AWS_REGION})"
  else
    dc_write_env_key ANTHROPIC_API_KEY "${ANTHROPIC_API_KEY:-}"
  fi
}

agent_run() {
  local prompt="$1"
  # acceptEdits auto-approves benign tool calls so the allow probe runs, while
  # PreToolUse hooks still fire (and can still deny) for the block probe.
  dc_timeout 180 claude -p "${prompt}" \
    --output-format json \
    --model "${CLAUDE_MODEL}" \
    --permission-mode acceptEdits \
    --allowedTools "Bash"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  dc_driver_main claudecode
fi
