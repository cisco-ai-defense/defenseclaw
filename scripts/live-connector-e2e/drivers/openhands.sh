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
#   - install:  Linux uses uv; macOS arm64 uses the checksum-pinned official
#               standalone release so the sealed path is the real executable.
#   - headless: openhands --headless -t "<prompt>"
#   - auth:     LLM_API_KEY + LLM_MODEL (OpenHands' provider-agnostic env).
#               OpenHands routes through LiteLLM, so it can target the public
#               provider (default), Amazon Bedrock (DC_USE_BEDROCK=1), or
#               Azure OpenAI (DC_USE_AZURE=1). Bedrock wins if both are set.
#   - runtime:  local OpenHands SDK workspace for CLI/headless mode. Docker is
#               required by `openhands serve`, not by this Linux/macOS path.
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

DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"
DC_DRIVER_SUPPORTS_BLOCK=1
if [ "$(dc_detect_os)" = "macos" ]; then
  DC_DRIVER_SUPPORTS_OTLP=1
else
  DC_DRIVER_SUPPORTS_OTLP=0
fi

OPENHANDS_MODEL="${OPENHANDS_MODEL:-openai/gpt-5-mini}"
OPENHANDS_REVIEWED_MACOS_VERSION="1.16.0"
OPENHANDS_REVIEWED_MACOS_ARM64_SIZE="86732736"
OPENHANDS_REVIEWED_MACOS_ARM64_SHA256="fa238330a452f2f1e933affb7edffda43c01f1ebd84194ecc564c5a6a306317f"

openhands_sha256_file() {
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

openhands_install_macos_arm64() {
  local requested="$1" version download_dir download_path actual_checksum
  local versions_root target_dir target staged_dir launcher

  if [ "$(uname -m)" != "arm64" ] && [ "$(uname -m)" != "aarch64" ]; then
    dc_err "OpenHands protected macOS live execution is supported only on arm64"
    return 1
  fi
  if [ "${requested}" = "latest" ]; then
    version="${OPENHANDS_REVIEWED_MACOS_VERSION}"
  elif [ "${requested}" = "${OPENHANDS_REVIEWED_MACOS_VERSION}" ]; then
    version="${requested}"
  else
    dc_err "OpenHands macOS live execution is pinned to reviewed standalone release ${OPENHANDS_REVIEWED_MACOS_VERSION}"
    return 1
  fi

  download_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-openhands.XXXXXX")" || return 1
  staged_dir=""
  trap '[ -z "${download_dir:-}" ] || rm -rf -- "${download_dir}"; [ -z "${staged_dir:-}" ] || rm -rf -- "${staged_dir}"; trap - RETURN' RETURN
  download_path="${download_dir}/openhands"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 300 \
    --max-filesize 100663296 \
    --output "${download_path}" \
    "https://github.com/OpenHands/OpenHands-CLI/releases/download/${version}/openhands-macos-arm64" || return 1
  if [ "$(wc -c < "${download_path}" | tr -d '[:space:]')" != "${OPENHANDS_REVIEWED_MACOS_ARM64_SIZE}" ]; then
    dc_err "OpenHands standalone download size does not match the reviewed release asset"
    return 1
  fi
  actual_checksum="$(openhands_sha256_file "${download_path}")" || return 1
  if [ "${actual_checksum}" != "${OPENHANDS_REVIEWED_MACOS_ARM64_SHA256}" ]; then
    dc_err "OpenHands standalone download digest does not match the reviewed release asset"
    return 1
  fi

  versions_root="${HOME}/.local/share/openhands/versions"
  target_dir="${versions_root}/${version}"
  target="${target_dir}/openhands"
  launcher="${HOME}/.local/bin/openhands"
  mkdir -p "${versions_root}" "${HOME}/.local/bin"
  chmod 0700 "${versions_root}" "${HOME}/.local/bin"
  if [ -e "${target_dir}" ] || [ -L "${target_dir}" ] || [ -e "${launcher}" ] || [ -L "${launcher}" ]; then
    dc_err "refusing to overwrite an existing OpenHands standalone installation"
    return 1
  fi
  staged_dir="$(mktemp -d "${versions_root}/.${version}.defenseclaw.XXXXXX")" || return 1
  chmod 0700 "${staged_dir}"
  install -m 0500 "${download_path}" "${staged_dir}/openhands" || return 1
  if [ "$(wc -c < "${staged_dir}/openhands" | tr -d '[:space:]')" != "${OPENHANDS_REVIEWED_MACOS_ARM64_SIZE}" ]; then
    dc_err "staged OpenHands standalone size does not match the reviewed release asset"
    return 1
  fi
  actual_checksum="$(openhands_sha256_file "${staged_dir}/openhands")" || return 1
  if [ "${actual_checksum}" != "${OPENHANDS_REVIEWED_MACOS_ARM64_SHA256}" ]; then
    dc_err "staged OpenHands standalone digest does not match the reviewed release asset"
    return 1
  fi
  mv "${staged_dir}" "${target_dir}" || return 1
  staged_dir=""
  ln -s "${target}" "${launcher}" || return 1
  export PATH="${HOME}/.local/bin:${PATH}"
  DC_E2E_AGENT_VERSION="${version}"
  export DC_E2E_AGENT_VERSION
}

agent_install() {
  local host_os requested package
  host_os="$(dc_detect_os)"
  case "${host_os}" in
    linux|macos) ;;
    *) dc_warn "openhands live driver supports the official Linux/macOS CLI only"; return 1 ;;
  esac
  requested="${OPENHANDS_VERSION:-${DC_E2E_AGENT_VERSION_REQUEST:-latest}}"
  if [ "${host_os}" = "macos" ]; then
    openhands_install_macos_arm64 "${requested}" || return 1
  else
    package="openhands"
    if [ "${requested}" != "latest" ]; then
      if ! printf '%s' "${requested}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        dc_err "invalid OpenHands CLI version"
        return 1
      fi
      package="${package}==${requested}"
    fi
    if ! command -v uv >/dev/null 2>&1; then
      dc_err "openhands requires uv and Python 3.12 on Linux"
      return 1
    fi
    dc_without_provider_credentials uv tool install --python 3.12 --force "${package}" || return 1
    DC_E2E_AGENT_VERSION="$(dc_capture_version openhands openhands --version)"
    export DC_E2E_AGENT_VERSION
  fi

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
  if [ "$(dc_detect_os)" = "macos" ]; then
    # Darwin native OTLP is intentionally available only through the product's
    # protected launch boundary. It revalidates the exact setup-selected
    # standalone Mach-O and hook digest before loading the scoped credential.
    dc_timeout 300 defenseclaw-gateway connector launch --connector openhands -- \
      --headless --override-with-envs -t "${prompt}"
  else
    dc_timeout 300 openhands --headless --override-with-envs -t "${prompt}"
  fi
}

dc_driver_main openhands
