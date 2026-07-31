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
#   - install:  uv tool install openhands (the official CLI package)
#   - headless: openhands --headless -t "<prompt>"
#   - auth:     LLM_API_KEY + LLM_MODEL (OpenHands' provider-agnostic env).
#               OpenHands routes through LiteLLM, so it can target the public
#               provider (default), Amazon Bedrock (DC_USE_BEDROCK=1), or
#               Azure OpenAI (DC_USE_AZURE=1). Bedrock wins if both are set.
#   - runtime:  local OpenHands SDK workspace for CLI/headless mode. Docker is
#               required by `openhands serve`, not by the CLI path exercised
#               here. The official CLI supports Linux and macOS; native Windows
#               remains unsupported upstream.
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
DC_DRIVER_SUPPORTS_OTLP=1

OPENHANDS_MODEL="${OPENHANDS_MODEL:-openai/gpt-5-mini}"

agent_install() {
  case "$(dc_detect_os)" in
    linux|macos) ;;
    *) dc_warn "openhands live driver supports the official Linux/macOS CLI only"; return 1 ;;
  esac
  local requested="${OPENHANDS_VERSION:-${DC_E2E_AGENT_VERSION_REQUEST:-latest}}"
  local package="openhands"
  if [ "${requested}" != "latest" ]; then
    package="${package}==${requested}"
  fi
  if command -v uv >/dev/null 2>&1; then
    uv tool install --python 3.12 --force "${package}" || return 1
  else
    dc_err "openhands requires uv and Python 3.12 (the upstream-recommended install path)"
    return 1
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
  local otlp_token_file="${DEFENSECLAW_HOME}/hooks/.otlp-openhands.token"
  local otlp_token api_port
  if [ ! -f "${otlp_token_file}" ]; then
    dc_err "OpenHands scoped OTLP token was not provisioned"
    return 1
  fi
  IFS= read -r otlp_token < "${otlp_token_file}" || return 1
  api_port="${DC_PERSIST_API_PORT:-18970}"
  export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="http://127.0.0.1:${api_port}/v1/traces"
  export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL="http/protobuf"
  export OTEL_EXPORTER_OTLP_TRACES_HEADERS="authorization=Bearer%20${otlp_token},x-defenseclaw-client=openhands-otel%2F1.0,x-defenseclaw-source=openhands"
  export OTEL_TRACES_EXPORTER=otlp
  dc_timeout 300 openhands --headless --override-with-envs -t "${prompt}"
}

dc_driver_main openhands
