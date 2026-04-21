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
# add-to-path.sh — idempotently prepend a directory to the user's shell PATH.
#
# Shared by ``make all`` / ``make path`` and the release installer so the
# end-to-end flow ends with ``defenseclaw`` and ``defenseclaw-gateway``
# resolvable in new shells without any copy-paste step.
#
# Usage:
#   scripts/add-to-path.sh <dir>                     # prompt unless --yes
#   scripts/add-to-path.sh <dir> --yes               # non-interactive
#   scripts/add-to-path.sh <dir> --shell zsh         # force a specific rc file
#
# Behaviour:
#   - Exits 0 with no change if <dir> is already on PATH.
#   - Detects the user's rc file from ${SHELL} (zsh/bash/fish). ``--shell``
#     overrides the detection.
#   - Appends a single ``export PATH="<dir>:$PATH"`` line guarded by a
#     ``# added by defenseclaw install`` marker. Re-runs are no-ops.
#   - Fish gets ``fish_add_path -g <dir>`` instead because PATH mutation
#     via ``export`` is not how fish models path — doing it the POSIX way
#     in fish silently breaks the user's environment.
#   - Never uses sudo. Never touches files outside ${HOME}.
#
# Exit codes:
#   0 — already on PATH, or rc file updated successfully
#   1 — user declined / invalid args / rc write failed
#
set -euo pipefail

TARGET_DIR=""
YES_MODE=false
SHELL_OVERRIDE=""

die()  { printf '  ✗ %s\n' "$*" >&2; exit 1; }
warn() { printf '  ! %s\n' "$*" >&2; }
ok()   { printf '  ✓ %s\n' "$*"; }
info() { printf '  ▸ %s\n' "$*"; }

usage() {
    cat <<'USAGE'
Usage: add-to-path.sh <dir> [--yes] [--shell zsh|bash|fish]

Options:
  --yes            Skip the confirmation prompt
  --shell NAME     Override shell detection (zsh|bash|fish|profile)
  --help           Print this message
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y) YES_MODE=true; shift ;;
        --shell)  [[ $# -ge 2 ]] || die "--shell requires a value"; SHELL_OVERRIDE="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        -*)       usage; die "unknown flag: $1" ;;
        *)        [[ -z "${TARGET_DIR}" ]] || die "only one <dir> accepted"; TARGET_DIR="$1"; shift ;;
    esac
done

[[ -n "${TARGET_DIR}" ]] || { usage; exit 1; }

# Normalize to an absolute path. A non-existent directory is still a
# valid target — callers often invoke us before the install step that
# populates it — but we resolve any ``~``/relative forms up-front.
case "${TARGET_DIR}" in
    "~/"*) TARGET_DIR="${HOME}/${TARGET_DIR#"~/"}" ;;
    "~")   TARGET_DIR="${HOME}" ;;
esac
if [[ "${TARGET_DIR}" != /* ]]; then
    TARGET_DIR="$(cd "$(dirname "${TARGET_DIR}")" 2>/dev/null && pwd)/$(basename "${TARGET_DIR}")" \
        || die "cannot resolve ${TARGET_DIR}"
fi

# Fast path: the directory is already on PATH in this shell.
case ":${PATH}:" in
    *":${TARGET_DIR}:"*)
        ok "${TARGET_DIR} already on PATH"
        exit 0
        ;;
esac

# Decide which shell's rc file to mutate. Honour the override, then fall
# back to ${SHELL}, then to a plain ~/.profile that every POSIX shell
# reads at login.
detect_shell() {
    if [[ -n "${SHELL_OVERRIDE}" ]]; then
        echo "${SHELL_OVERRIDE}"
        return
    fi
    case "${SHELL:-}" in
        */zsh)  echo "zsh" ;;
        */bash) echo "bash" ;;
        */fish) echo "fish" ;;
        *)      echo "profile" ;;
    esac
}

SHELL_NAME="$(detect_shell)"

rc_file_for() {
    case "$1" in
        zsh)     echo "${HOME}/.zshrc" ;;
        bash)
            # bash on macOS defaults to ~/.bash_profile; Linux defaults
            # to ~/.bashrc. Prefer whichever already exists; otherwise
            # pick the per-OS default so the file lands where the shell
            # will actually source it.
            if   [[ -f "${HOME}/.bashrc"        ]]; then echo "${HOME}/.bashrc"
            elif [[ -f "${HOME}/.bash_profile"  ]]; then echo "${HOME}/.bash_profile"
            elif [[ "$(uname -s)" == "Darwin"   ]]; then echo "${HOME}/.bash_profile"
            else echo "${HOME}/.bashrc"
            fi
            ;;
        fish)    echo "${HOME}/.config/fish/config.fish" ;;
        profile) echo "${HOME}/.profile" ;;
        *)       die "unsupported shell: $1" ;;
    esac
}

RC_FILE="$(rc_file_for "${SHELL_NAME}")"

info "Will add ${TARGET_DIR} to ${RC_FILE} (${SHELL_NAME})"

if [[ "${YES_MODE}" != true ]]; then
    # Read from /dev/tty so ``curl | bash`` still gets a prompt instead
    # of silently defaulting.
    printf '  Add %s to PATH via %s? [Y/n] ' "${TARGET_DIR}" "${RC_FILE}" >&2
    reply=""
    if ! read -r reply < /dev/tty 2>/dev/null; then
        warn "no tty available — re-run with --yes to apply, or skip"
        exit 1
    fi
    reply="${reply:-y}"
    case "${reply}" in
        y|Y|yes|YES) ;;
        *) warn "skipped — add manually: export PATH=\"${TARGET_DIR}:\$PATH\""; exit 1 ;;
    esac
fi

mkdir -p "$(dirname "${RC_FILE}")"
touch "${RC_FILE}"

# Marker comments let us detect a previous run without parsing shell
# syntax. Grep for an exact-line match so a substring in an unrelated
# comment can't fool us into skipping.
MARKER="# added by defenseclaw install — adds ${TARGET_DIR} to PATH"
if grep -Fxq "${MARKER}" "${RC_FILE}"; then
    ok "${RC_FILE} already references ${TARGET_DIR}"
    exit 0
fi

case "${SHELL_NAME}" in
    fish)
        {
            echo ""
            echo "${MARKER}"
            echo "if test -d \"${TARGET_DIR}\""
            echo "    fish_add_path -g \"${TARGET_DIR}\""
            echo "end"
        } >> "${RC_FILE}"
        ;;
    *)
        {
            echo ""
            echo "${MARKER}"
            echo "if [ -d \"${TARGET_DIR}\" ] && [[ \":\$PATH:\" != *\":${TARGET_DIR}:\"* ]]; then"
            echo "    export PATH=\"${TARGET_DIR}:\$PATH\""
            echo "fi"
        } >> "${RC_FILE}"
        ;;
esac

ok "Added ${TARGET_DIR} to ${RC_FILE}"
info "Open a new shell or run:  source ${RC_FILE}"
