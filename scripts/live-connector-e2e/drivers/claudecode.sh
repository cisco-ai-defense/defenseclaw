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
#   - install:  npm i -g @anthropic-ai/claude-code@${CLAUDE_VERSION:-latest}
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
  npm install -g "@anthropic-ai/claude-code@${CLAUDE_VERSION:-latest}" || return 1
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
