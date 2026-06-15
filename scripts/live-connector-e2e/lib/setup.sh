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
# DefenseClaw bootstrap + per-connector setup/teardown helpers shared by the
# contract-smoke and live drivers. Mirrors the init/setup/health/teardown flow
# in .github/workflows/e2e.yml but parameterized per hook connector.

# dc_setup_subcommand <connector> — map a registry connector name to its
# `defenseclaw setup` subcommand. Only claude diverges (claude-code); every
# other hook connector's subcommand equals its registry name.
dc_setup_subcommand() {
  case "$1" in
    claudecode) printf 'claude-code' ;;
    *)          printf '%s' "$1" ;;
  esac
}

# dc_connector_config_file <connector> — the agent-side config file
# `defenseclaw setup` patches, used by the teardown assertion. Paths mirror
# the *PathOverride defaults in internal/gateway/connector and cmd_setup.py.
dc_connector_config_file() {
  case "$1" in
    codex)       printf '%s/.codex/config.toml' "${HOME}" ;;
    claudecode)  printf '%s/.claude/settings.json' "${HOME}" ;;
    geminicli)   printf '%s/.gemini/settings.json' "${HOME}" ;;
    cursor)      printf '%s/.cursor/hooks.json' "${HOME}" ;;
    windsurf)    printf '%s/.codeium/windsurf/hooks.json' "${HOME}" ;;
    copilot)     printf '%s/.copilot/hooks/defenseclaw.json' "${HOME}" ;;
    openhands)   printf '%s/.openhands/hooks.json' "${HOME}" ;;
    antigravity) printf '%s/.gemini/config/hooks.json' "${HOME}" ;;
    hermes)      printf '%s/.hermes/config.yaml' "${HOME}" ;;
    *)           printf '' ;;
  esac
}

# dc_write_env_key <KEY> <VALUE> — idempotently append an env line to
# ~/.defenseclaw/.env (consumed by the gateway + hook scripts). No-op on empty
# value so a missing optional secret never writes a blank line.
dc_write_env_key() {
  local key="$1" value="$2"
  [ -n "${value}" ] || return 0
  mkdir -p "${DEFENSECLAW_HOME}"
  touch "${DEFENSECLAW_HOME}/.env"
  if grep -q "^${key}=" "${DEFENSECLAW_HOME}/.env" 2>/dev/null; then
    return 0
  fi
  printf '%s=%s\n' "${key}" "${value}" >> "${DEFENSECLAW_HOME}/.env"
}

# dc_init_defenseclaw — run `defenseclaw init` once and stand up the gateway.
# Idempotent: re-running against an initialized home is a no-op for config.
dc_init_defenseclaw() {
  if [ ! -f "${DEFENSECLAW_HOME}/config.yaml" ]; then
    dc_log "running defenseclaw init"
    defenseclaw init
  else
    dc_log "defenseclaw already initialized at ${DEFENSECLAW_HOME}"
  fi
}

# dc_setup_connector <connector> <mode> — install DefenseClaw into the
# connector via its setup subcommand and wait for the gateway to come back
# healthy. mode is observe|action. --restart wires hook scripts + OTel block.
dc_setup_connector() {
  local connector="$1" mode="${2:-action}" sub
  sub="$(dc_setup_subcommand "${connector}")"
  dc_log "defenseclaw setup ${sub} --mode ${mode} --restart"
  defenseclaw setup "${sub}" --yes --mode "${mode}" --restart
  dc_wait_for_gateway 30
}

# dc_teardown_connector <connector> — remove the connector's config patches
# and verify no residual state. Returns the verify exit code (0 = clean).
dc_teardown_connector() {
  local connector="$1"
  dc_log "tearing down ${connector}"
  defenseclaw-gateway connector teardown --connector "${connector}" || \
    dc_warn "teardown command returned non-zero for ${connector}"
  defenseclaw-gateway connector verify --connector "${connector}"
}
