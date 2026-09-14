#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Refuse root/sudo writes into a user-owned checkout. `sudo make all` copies
# bundled policies and the gateway as root, then source-install fails because
# ~/.local/bin/.defenseclaw-install-custody is caller-owned by the operator.
# A later unprivileged `make all` cannot replace those leftovers.

set -euo pipefail

ROOT="${1:-.}"

if [[ "${OS:-}" == "Windows_NT" ]]; then
    exit 0
fi

if ! command -v id >/dev/null 2>&1; then
    exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
    exit 0
fi

if [[ ! -e "${ROOT}" ]]; then
    echo "error: checkout path does not exist: ${ROOT}" >&2
    exit 64
fi

if owner="$(stat -f %u "${ROOT}" 2>/dev/null)"; then
    :
elif owner="$(stat -c %u "${ROOT}" 2>/dev/null)"; then
    :
else
    echo "error: cannot inspect checkout owner: ${ROOT}" >&2
    exit 1
fi

if [[ "${owner}" == "0" ]]; then
    exit 0
fi

cat >&2 <<'EOF'
error: do not run this as root/sudo against a user-owned checkout.
Run 'make all' as the checkout owner.

If a previous sudo make left root-owned files, reclaim them first:
  sudo chown -R "$(id -un):$(id -gn)" -- \
    cli/defenseclaw/_data \
    cli/defenseclaw/__pycache__ \
    internal/gateway/connector/openclaw_extension \
    defenseclaw-gateway
  sudo chown "$(id -un):$(id -gn)" -- "$HOME/.local/bin/defenseclaw-gateway"
EOF
exit 1
