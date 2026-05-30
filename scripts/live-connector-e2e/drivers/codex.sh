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
# Live driver for OpenAI Codex CLI.
#   - install:  npm i -g @openai/codex@${CODEX_VERSION:-latest}
#   - headless: codex exec --json --full-auto "<prompt>"
#   - auth:     OPENAI_API_KEY (public OpenAI) OR Azure OpenAI when
#               DC_USE_AZURE=1 (Codex cannot use Bedrock — it is OpenAI-only).
#   - hooks:    SessionStart / UserPromptSubmit / PreToolUse / PostToolUse /
#               Stop. Native OTLP exporter is wired by `defenseclaw setup
#               codex --restart`, so OTLP is asserted.
#   - trust:    Codex hashes the hook command and refuses to run an
#               unrecognized one. `defenseclaw setup codex` pre-seeds trust;
#               on Windows the native `defenseclaw-gateway hook` command +
#               .hookcfg keep the hash stable. CODEX_BYPASS_HOOK_TRUST=1 adds
#               the documented escape hatch if a runner starts cold.
#
# Azure: when DC_USE_AZURE=1 we write a [model_providers.azure] block into
# ~/.codex/config.toml BEFORE `defenseclaw setup codex`. That setup only
# mutates the [hooks]/[otel]/notify tables (it parses the file into a map and
# re-marshals), so the Azure provider survives. Codex then talks to Azure
# directly for LLM traffic; the hook bus + OTLP are unaffected. Requires
# AZURE_OPENAI_ENDPOINT (resource URL), AZURE_OPENAI_DEPLOYMENT (used as the
# model — must be a Codex-capable deployment), and AZURE_OPENAI_API_KEY.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE=action
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_OTLP=1

CODEX_MODEL="${CODEX_MODEL:-gpt-5-mini}"

# _codex_azure_base_url — normalize AZURE_OPENAI_ENDPOINT to the v1 Responses
# base URL Codex expects (".../openai/v1"). Idempotent if the caller already
# included /openai or /openai/v1.
_codex_azure_base_url() {
  local ep="${AZURE_OPENAI_ENDPOINT%/}"
  ep="${ep%/openai/v1}"
  ep="${ep%/openai}"
  ep="${ep%/}"
  printf '%s/openai/v1' "${ep}"
}

# _codex_write_azure_config — seed ~/.codex/config.toml with the Azure provider
# so `defenseclaw setup codex` merges its tables on top of it. env_key holds the
# NAME of the env var (never the key value), so no secret is written to disk.
_codex_write_azure_config() {
  mkdir -p "${HOME}/.codex"
  cat > "${HOME}/.codex/config.toml" <<EOF
model = "${AZURE_OPENAI_DEPLOYMENT}"
model_provider = "azure"

[model_providers.azure]
name = "Azure OpenAI"
base_url = "$(_codex_azure_base_url)"
env_key = "AZURE_OPENAI_API_KEY"
wire_api = "responses"
EOF
}

agent_install() {
  npm install -g "@openai/codex@${CODEX_VERSION:-latest}" || return 1
  DC_E2E_AGENT_VERSION="$(dc_capture_version codex codex --version)"
  export DC_E2E_AGENT_VERSION

  if [ "${DC_USE_AZURE:-0}" = "1" ]; then
    if [ -z "${AZURE_OPENAI_ENDPOINT:-}" ] || [ -z "${AZURE_OPENAI_DEPLOYMENT:-}" ] || [ -z "${AZURE_OPENAI_API_KEY:-}" ]; then
      dc_err "DC_USE_AZURE=1 needs AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_DEPLOYMENT + AZURE_OPENAI_API_KEY"
      return 1
    fi
    CODEX_MODEL="${AZURE_OPENAI_DEPLOYMENT}"
    export AZURE_OPENAI_API_KEY
    _codex_write_azure_config
    dc_log "codex configured for Azure OpenAI deployment ${AZURE_OPENAI_DEPLOYMENT}"
  else
    dc_write_env_key OPENAI_API_KEY "${OPENAI_API_KEY:-}"
  fi
}

agent_run() {
  local prompt="$1" extra=()
  [ "${CODEX_BYPASS_HOOK_TRUST:-0}" = "1" ] && extra+=(--dangerously-bypass-hook-trust)
  dc_timeout 180 codex exec --json --full-auto \
    --model "${CODEX_MODEL}" \
    "${extra[@]}" \
    "${prompt}"
}

dc_driver_main codex
