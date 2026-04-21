#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#
# Post-install interactive prompt for DEFENSECLAW_LLM_KEY + default LLM
# model, invoked by `make all` after `defenseclaw quickstart`. Can also
# be run standalone.
#
# Implementation: this is a thin wrapper around `defenseclaw setup llm`
# — the Click command in cli/defenseclaw/commands/cmd_setup.py that is
# the single source of truth for the unified LLM config. Keeping the
# logic there (not here) means:
#   * Atomic .env writes, 0600 permissions, quoting, and legacy-field
#     cleanup all happen once, with matching unit tests.
#   * `defenseclaw setup llm` and `make all` always behave identically.
#   * Adding a new provider is a one-file change.
#
# Idempotence: `defenseclaw setup llm` already skips prompts the
# operator dismisses with Enter, so re-running `make all` after a
# successful first run is effectively a no-op (it re-prompts only for
# values the operator actively wants to change).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolution order for the CLI binary, most-specific first:
#   1. An explicit $DEFENSECLAW_BIN override (CI / packagers).
#   2. The repo venv built by `make pycli` (the canonical dev path).
#   3. A previously-installed symlink at $(INSTALL_DIR)/defenseclaw
#      (what `make install` drops next to `defenseclaw-gateway`).
#   4. Whatever `defenseclaw` resolves to on PATH.
# We never silently fall back to a half-built venv — if none of the
# above exists, tell the operator how to fix it and exit non-zero so
# the Makefile's "LLM setup exited with errors" hint fires.
resolve_defenseclaw() {
	if [ -n "${DEFENSECLAW_BIN:-}" ] && [ -x "${DEFENSECLAW_BIN}" ]; then
		printf '%s' "${DEFENSECLAW_BIN}"
		return 0
	fi
	if [ -x "${REPO_ROOT}/.venv/bin/defenseclaw" ]; then
		printf '%s' "${REPO_ROOT}/.venv/bin/defenseclaw"
		return 0
	fi
	local install_dir="${DEFENSECLAW_INSTALL_DIR:-$HOME/.local/bin}"
	if [ -x "${install_dir}/defenseclaw" ]; then
		printf '%s' "${install_dir}/defenseclaw"
		return 0
	fi
	if command -v defenseclaw >/dev/null 2>&1; then
		command -v defenseclaw
		return 0
	fi
	return 1
}

if ! DC_BIN="$(resolve_defenseclaw)"; then
	echo "  setup-llm: defenseclaw binary not found." >&2
	echo "  setup-llm: run 'make pycli' (or 'make install') first, or set" >&2
	echo "  setup-llm: DEFENSECLAW_BIN to an installed binary." >&2
	exit 1
fi

# Hand off to the Click command. It handles:
#   * hidden-input API key prompt, atomic write to ~/.defenseclaw/.env
#     with mode 0600 (see _save_secret_to_dotenv / _write_dotenv)
#   * provider / model / base_url prompts with sensible defaults
#   * api_key_env suggestion from the chosen provider/model pair
#   * clearing legacy v4 inspect_llm: / default_llm_* fields so the
#     next save converges on the canonical v5 shape
exec "$DC_BIN" setup llm "$@"
