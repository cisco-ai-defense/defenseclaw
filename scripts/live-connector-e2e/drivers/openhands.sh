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
# Live driver for OpenHands (headless CLI).
#   - install:  pipx/uv install openhands-ai (the `openhands` console script)
#   - headless: openhands --headless -t "<prompt>"
#   - auth:     LLM_API_KEY + LLM_MODEL (OpenHands' provider-agnostic env).
#               OpenHands routes through LiteLLM, so it can target the public
#               provider (default), Amazon Bedrock (DC_USE_BEDROCK=1), or
#               Azure OpenAI (DC_USE_AZURE=1). Bedrock wins if both are set.
#   - runtime:  Docker. LINUX ONLY — macOS/Windows runners lack a usable Docker
#               daemon for the agent runtime, so the workflow restricts this
#               connector to ubuntu-latest.
#   - hooks:    PreToolUse deny is honored (exit-2 style), so block is testable.
#
# Bedrock: LLM_MODEL=bedrock/<inference-profile>; LiteLLM uses the AWS chain
#   (AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID/SECRET[/SESSION_TOKEN]) +
#   AWS_REGION. No LLM_API_KEY needed.
# Azure:   LLM_MODEL=azure/<deployment>; LiteLLM reads AZURE_API_KEY /
#   AZURE_API_BASE / AZURE_API_VERSION (derived from AZURE_OPENAI_* here).

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=0

OPENHANDS_MODEL="${OPENHANDS_MODEL:-openai/gpt-5-mini}"

agent_install() {
  if [ "$(dc_detect_os)" != "linux" ]; then
    dc_warn "openhands requires Docker runtime; only supported on linux"
    return 1
  fi
  if command -v uv >/dev/null 2>&1; then
    uv tool install "openhands-ai${OPENHANDS_VERSION:+==${OPENHANDS_VERSION}}" || return 1
  else
    pipx install "openhands-ai${OPENHANDS_VERSION:+==${OPENHANDS_VERSION}}" || \
      pip install --user "openhands-ai${OPENHANDS_VERSION:+==${OPENHANDS_VERSION}}" || return 1
  fi
  DC_E2E_AGENT_VERSION="$(dc_capture_version openhands openhands --version)"
  export DC_E2E_AGENT_VERSION

  # OpenHands resolves the LLM via LLM_* env (litellm-style model id).
  if [ "${DC_USE_BEDROCK:-0}" = "1" ]; then
    if [ -z "${AWS_BEARER_TOKEN_BEDROCK:-}" ] && [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
      dc_err "DC_USE_BEDROCK=1 needs AWS auth (AWS_BEARER_TOKEN_BEDROCK or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
      return 1
    fi
    export AWS_REGION="${AWS_REGION:-us-east-1}"
    export LLM_MODEL="${OPENHANDS_BEDROCK_MODEL:-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0}"
    dc_log "openhands configured for Bedrock model ${LLM_MODEL} (region ${AWS_REGION})"
  elif [ "${DC_USE_AZURE:-0}" = "1" ]; then
    if [ -z "${AZURE_OPENAI_ENDPOINT:-}" ] || [ -z "${AZURE_OPENAI_DEPLOYMENT:-}" ] || [ -z "${AZURE_OPENAI_API_KEY:-}" ]; then
      dc_err "DC_USE_AZURE=1 needs AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_DEPLOYMENT + AZURE_OPENAI_API_KEY"
      return 1
    fi
    export AZURE_API_KEY="${AZURE_OPENAI_API_KEY}"
    export AZURE_API_BASE="${AZURE_OPENAI_ENDPOINT%/}"
    export AZURE_API_VERSION="${AZURE_OPENAI_API_VERSION:-2025-04-01-preview}"
    export LLM_API_KEY="${AZURE_OPENAI_API_KEY}"
    export LLM_MODEL="azure/${AZURE_OPENAI_DEPLOYMENT}"
    dc_write_env_key LLM_API_KEY "${AZURE_OPENAI_API_KEY}"
    dc_log "openhands configured for Azure OpenAI deployment ${AZURE_OPENAI_DEPLOYMENT}"
  else
    dc_write_env_key LLM_API_KEY "${LLM_API_KEY:-${OPENAI_API_KEY:-}}"
    export LLM_MODEL="${OPENHANDS_MODEL}"
    export LLM_API_KEY="${LLM_API_KEY:-${OPENAI_API_KEY:-}}"
  fi
}

agent_run() {
  local prompt="$1"
  dc_timeout 300 openhands --headless -t "${prompt}"
}

dc_driver_main openhands
