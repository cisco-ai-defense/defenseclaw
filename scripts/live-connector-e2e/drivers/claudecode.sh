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

agent_install() {
  local requested="${CLAUDE_VERSION:-latest}"
  local version platform manifest expected_checksum expected_size
  local download_dir download_path target versions_root launcher
  if [ "$requested" = "latest" ]; then
    version="$(curl -fsSL --connect-timeout 5 --max-time 20 \
      https://downloads.claude.ai/claude-code-releases/latest)" || return 1
  else
    version="$requested"
  fi
  case "$version" in
    *[!0-9.]*|.*|*.) dc_err "invalid Claude Code release version: ${version}"; return 1 ;;
  esac
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform="darwin-arm64" ;;
    Darwin-x86_64) platform="darwin-x64" ;;
    Linux-aarch64|Linux-arm64) platform="linux-arm64" ;;
    Linux-x86_64) platform="linux-x64" ;;
    *) dc_err "unsupported Claude Code live platform: $(uname -s)-$(uname -m)"; return 1 ;;
  esac
  manifest="$(curl -fsSL --connect-timeout 5 --max-time 20 \
    "https://downloads.claude.ai/claude-code-releases/${version}/manifest.json")" || return 1
  expected_checksum="$(printf '%s' "$manifest" | _dc_jq -r \
    ".platforms[\"${platform}\"].checksum // empty")"
  expected_size="$(printf '%s' "$manifest" | _dc_jq -r \
    ".platforms[\"${platform}\"].size // empty")"
  if ! printf '%s' "$expected_checksum" | grep -Eq '^[0-9a-f]{64}$' ||
     ! printf '%s' "$expected_size" | grep -Eq '^[1-9][0-9]*$'; then
    dc_err "official Claude Code manifest lacks valid ${platform} evidence"
    return 1
  fi
  download_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/defenseclaw-claude.XXXXXX")" || return 1
  download_path="${download_dir}/claude"
  trap 'rm -rf -- "${download_dir:-}"' RETURN
  curl -fsSL --connect-timeout 5 --max-time 300 \
    --output "$download_path" \
    "https://downloads.claude.ai/claude-code-releases/${version}/${platform}/claude" || return 1
  if [ "$(wc -c < "$download_path" | tr -d ' ')" != "$expected_size" ]; then
    dc_err "Claude Code native download size does not match official manifest"
    return 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_checksum" "$download_path" | shasum -a 256 -c - || return 1
  else
    printf '%s  %s\n' "$expected_checksum" "$download_path" | sha256sum -c - || return 1
  fi
  versions_root="${HOME}/.local/share/claude/versions"
  target="${versions_root}/${version}"
  launcher="${HOME}/.local/bin/claude"
  mkdir -p "$versions_root" "${HOME}/.local/bin"
  chmod 0500 "$download_path"
  if [ -e "$target" ]; then
    dc_err "refusing to overwrite existing Claude Code version target: ${target}"
    return 1
  fi
  mv "$download_path" "$target"
  ln -sfn "$target" "$launcher"
  export PATH="${HOME}/.local/bin:${PATH}"
  DC_E2E_AGENT_VERSION="$(dc_capture_version claudecode claude --version)"
  export DC_E2E_AGENT_VERSION

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

dc_driver_main claudecode
