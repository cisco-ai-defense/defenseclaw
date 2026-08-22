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
# Manual macOS live driver for the official OpenCode npm distribution.
# OpenCode uses a managed JavaScript plugin rather than the executable
# shell-hook contract exercised by Layer A. The reviewed compatibility window
# is deliberately narrow and fail-closed; "latest" never pulls an unreviewed
# release into this evidence-only lane.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/../lib/common.sh"
. "${HERE}/../lib/assert.sh"
. "${HERE}/../lib/setup.sh"
. "${HERE}/_driver_common.sh"

DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"
DC_DRIVER_SUPPORTS_BLOCK=1
DC_DRIVER_SUPPORTS_LIFECYCLE=0
DC_DRIVER_SUPPORTS_OTLP=0

OPENCODE_REVIEWED_VERSION="1.18.19"
OPENCODE_MODEL="${OPENCODE_MODEL:-openai/gpt-5-mini}"
# OpenCode 1.18.x enables startup auto-update by default. Keep every version
# probe and live invocation inside the reviewed compatibility window.
export OPENCODE_DISABLE_AUTOUPDATE=1

_opencode_supported_version() {
  [[ "$1" =~ ^1\.18\.1[0-9]$ ]]
}

_opencode_requested_version() {
  local requested="${OPENCODE_VERSION:-${DC_E2E_AGENT_VERSION_REQUEST:-latest}}"
  requested="${requested#v}"
  case "${requested}" in
    ""|latest|default) requested="${OPENCODE_REVIEWED_VERSION}" ;;
  esac
  if ! _opencode_supported_version "${requested}"; then
    dc_err "OpenCode ${requested} is outside the reviewed live window >=1.18.10,<1.18.20"
    return 1
  fi
  printf '%s' "${requested}"
}

_opencode_resolved_version() {
  local raw="$1"
  if [[ "${raw}" =~ (^|[^0-9])([0-9]+\.[0-9]+\.[0-9]+)([^0-9]|$) ]]; then
    printf '%s' "${BASH_REMATCH[2]}"
    return 0
  fi
  dc_err "OpenCode returned an unrecognized version: ${raw}"
  return 1
}

agent_install() {
  local requested raw resolved
  if [ "$(dc_detect_os)" != "macos" ]; then
    dc_err "the OpenCode live driver is currently scoped to macOS"
    return 1
  fi
  if [ -z "${OPENAI_API_KEY:-}" ]; then
    dc_err "OPENAI_API_KEY is required for the OpenCode live driver"
    return 1
  fi
  requested="$(_opencode_requested_version)" || return 1
  # opencode-ai's official package requires postinstall.mjs to select/copy the
  # platform binary, so scripts cannot be disabled. Run it with every live
  # provider credential removed from the child environment instead.
  dc_without_provider_credentials npm install -g "opencode-ai@${requested}" || return 1
  raw="$(dc_capture_version opencode opencode --version)"
  resolved="$(_opencode_resolved_version "${raw}")" || return 1
  if ! _opencode_supported_version "${resolved}" || [ "${resolved}" != "${requested}" ]; then
    dc_err "OpenCode resolved ${resolved}; expected reviewed version ${requested}"
    return 1
  fi
  DC_E2E_AGENT_VERSION="${raw}"
  export DC_E2E_AGENT_VERSION
  dc_write_env_key OPENAI_API_KEY "${OPENAI_API_KEY}"
}

agent_run() {
  local prompt="$1"
  dc_timeout 180 opencode run --format json --model "${OPENCODE_MODEL}" --auto "${prompt}"
}

dc_driver_main opencode
