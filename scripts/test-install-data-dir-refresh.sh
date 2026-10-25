#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Exercise the installer's real refresh functions without swapping an install.
set -euo pipefail
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
export DEFENSECLAW_HOME="$root/home"
export DEFENSECLAW_CONFIG="$root/config.yaml"
export DC_TEST_DATA_DIR="$root/other-data"
export DC_TEST_REFRESH_CALLS="$root/calls"
STAGING="$root/staging"
mkdir -p "$DEFENSECLAW_HOME" "$DC_TEST_DATA_DIR/hooks" "$STAGING/bin"
printf 'data_dir: %s\n' "$DC_TEST_DATA_DIR" > "$DEFENSECLAW_CONFIG"
cat > "$STAGING/bin/defenseclaw-gateway" <<'SH'
#!/bin/sh
test "$1" = connector && test "$2" = refresh-fail-modes || exit 2
shift 2
for arg do
  test "$arg" != --data-dir || exit 3
done
test -d "$DC_TEST_DATA_DIR/hooks" || exit 4
printf '%s\n' "$*" >> "$DC_TEST_REFRESH_CALLS"
case " $* " in *" --hold-until-exit "*) echo 'Holding the hook fail modes'; sleep 0.2 ;; esac
SH
chmod 700 "$STAGING/bin/defenseclaw-gateway"

installer="$(dirname "$0")/install.sh"
source <(sed -n '/^refresh_hook_fail_modes() {/,/^}/p' "$installer")
source <(sed -n '/^hold_hook_fail_modes() {/,/^}/p' "$installer")
source <(sed -n '/^finish_hook_fail_mode_hold() {/,/^}/p' "$installer")
hook_fail_mode_refresh_probe() { return 0; }
warn() { printf '%s\n' "$*" >&2; }
HOLD_PID=""
HOLD_LOG=""

refresh_hook_fail_modes
hold_hook_fail_modes 4242
finish_hook_fail_mode_hold
test "$(wc -l < "$DC_TEST_REFRESH_CALLS")" -eq 2
grep -q -- '--hold-until-exit 4242' "$DC_TEST_REFRESH_CALLS"
