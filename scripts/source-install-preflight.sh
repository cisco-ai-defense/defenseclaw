#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Guard developer/source installs from becoming an out-of-band release upgrade.
#
# Usage:
#   source-install-preflight.sh <mode> REPO_ROOT INSTALL_DIR VENV_BIN CLI_NAME GATEWAY_NAME
#
# `check` is read-only. `claim` first repeats the check, requires the installed
# CLI to be the exact symlink for this checkout, then atomically records source
# ownership so a later same-checkout rebuild stays idempotent. `ensure-dir`
# reserves the source-owned install directory; `publish-cli` and
# `publish-gateway` perform create-new publication under that claim.

set -euo pipefail

usage() {
    echo "usage: $0 <check|claim|ensure-dir|publish-cli|publish-gateway> REPO_ROOT INSTALL_DIR VENV_BIN CLI_NAME GATEWAY_NAME" >&2
    exit 64
}

[[ $# -eq 6 ]] || usage

readonly REQUESTED_MODE="$1"
readonly REPO_ROOT_INPUT="$2"
readonly INSTALL_DIR_INPUT="$3"
readonly VENV_BIN="$4"
readonly CLI_NAME="$5"
readonly GATEWAY_NAME="$6"
IS_WINDOWS=0
if [[ "${OS:-}" == "Windows_NT" ]]; then
    IS_WINDOWS=1
fi

DEV_RECLAIM_SOURCE=0
case "${REQUESTED_MODE}" in
    check|claim|ensure-dir|publish-cli|publish-gateway)
        MODE="${REQUESTED_MODE}"
        ;;
    dev-check|dev-claim|dev-ensure-dir|dev-publish-cli|dev-publish-gateway)
        DEV_RECLAIM_SOURCE=1
        MODE="${REQUESTED_MODE#dev-}"
        ;;
    *) usage ;;
esac
readonly MODE DEV_RECLAIM_SOURCE

refuse() {
    echo "error: source install refused: $1" >&2
    echo "No installed files or services were changed." >&2
    echo "Release-managed hosts must use the release-owned resolver: scripts/upgrade.sh (macOS/Linux) or scripts\\upgrade.ps1 (Windows)." >&2
    echo "Developer state already owned by this exact checkout may use 'make all'; otherwise keep the checkout and state unchanged, use an isolated fresh developer HOME/install directory, or contact DefenseClaw support." >&2
    exit 1
}

[[ -d "${REPO_ROOT_INPUT}" ]] || {
    echo "error: source-install repository root does not exist: ${REPO_ROOT_INPUT}" >&2
    exit 64
}

REPO_ROOT="$(cd "${REPO_ROOT_INPUT}" && pwd -P)"
readonly REPO_ROOT
if [[ "${IS_WINDOWS}" -eq 1 ]]; then
    if [[ "${INSTALL_DIR_INPUT}" =~ ^[A-Za-z]:[\\/] \
       || "${INSTALL_DIR_INPUT}" =~ ^\\\\ \
       || "${INSTALL_DIR_INPUT}" =~ ^// ]]; then
        INSTALL_DIR="${INSTALL_DIR_INPUT}"
    else
        if [[ "${INSTALL_DIR_INPUT}" = /* ]]; then
            MSYS_INSTALL_DIR="${INSTALL_DIR_INPUT}"
        else
            MSYS_INSTALL_DIR="$(pwd)/${INSTALL_DIR_INPUT}"
        fi
        readonly MSYS_INSTALL_DIR
        if ! INSTALL_DIR="$(cygpath -aw "${MSYS_INSTALL_DIR}" 2>/dev/null)"; then
            refuse "Git Bash could not convert the source-install directory to an absolute Windows path"
        fi
    fi
    # Keep one explicit representation for Bash ownership checks and native
    # Python publication. This also avoids relying on MSYS argv rewriting when
    # HOME or an override is expressed as /c/... or another MSYS mount path.
    INSTALL_DIR="${INSTALL_DIR//\\//}"
    if [[ ! "${INSTALL_DIR}" =~ ^[A-Za-z]:/ && ! "${INSTALL_DIR}" =~ ^//[^/]+/[^/]+(/|$) ]]; then
        refuse "the resolved source-install directory is not an absolute Windows drive or UNC path"
    fi
elif [[ "${INSTALL_DIR_INPUT}" = /* ]]; then
    INSTALL_DIR="${INSTALL_DIR_INPUT}"
else
    INSTALL_DIR="$(pwd)/${INSTALL_DIR_INPUT}"
fi
readonly INSTALL_DIR
readonly MARKER="${INSTALL_DIR}/.defenseclaw-source-root"
readonly CLI_PATH="${INSTALL_DIR}/${CLI_NAME}"
readonly EXPECTED_CLI="${REPO_ROOT}/${VENV_BIN}/${CLI_NAME}"
readonly GATEWAY_PATH="${INSTALL_DIR}/${GATEWAY_NAME}"
readonly EXPECTED_GATEWAY="${REPO_ROOT}/${GATEWAY_NAME}"
readonly MANAGED_HOME="${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"
readonly PATH_COMMAND="${CLI_NAME%.exe}"
readonly PUBLISH_HELPER="${REPO_ROOT}/scripts/source-install-publish.py"
readonly PUBLISH_MODULE="${REPO_ROOT}/cli/defenseclaw/install_publish.py"
readonly SOURCE_IDENTITY_HELPER="${REPO_ROOT}/scripts/source_release_identity.py"
VERIFIED_GATEWAY_DIGEST=""
VERIFIED_MARKER_DIGEST=""
SOURCE_RELEASE=""
SOURCE_INSTALL_COMPATIBILITY_EPOCH=""
SOURCE_RUNTIME_CONFIG_VERSION=""
VERIFIED_CLI_DIGEST=""

sha256_regular() {
    python3 "${PUBLISH_HELPER}" sha256-regular "$@"
}

matching_gateway_digest() {
    python3 "${PUBLISH_HELPER}" compare-regular \
        "${EXPECTED_GATEWAY}" "${GATEWAY_PATH}" --require-executable
}

matching_cli_digest() {
    # Windows source installs publish a byte-identical regular-file copy. This
    # avoids the privileged symlink operation while preserving an exact,
    # descriptor-bound ownership proof.
    python3 "${PUBLISH_HELPER}" compare-regular \
        "${EXPECTED_CLI}" "${CLI_PATH}" --require-executable
}

check_gateway_claim() {
    # Open both names before hashing either one.  The returned digest therefore
    # describes the exact simultaneously opened source and destination, not a
    # path that may have been exchanged between cmp(1) and a later hash.
    if ! VERIFIED_GATEWAY_DIGEST="$(matching_gateway_digest)"; then
        refuse "the installed gateway and this checkout's gateway are not matching regular executables"
    fi
    [[ "${VERIFIED_GATEWAY_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
        || refuse "the descriptor-bound gateway comparison returned an invalid digest"
}

check_recorded_gateway() {
    local expected_digest="$1"
    local actual_digest=""
    [[ "${expected_digest}" =~ ^[0-9a-f]{64}$ ]] \
        || refuse "the source-install ownership marker has an invalid gateway digest"
    if ! actual_digest="$(sha256_regular "${GATEWAY_PATH}" --require-executable)"; then
        refuse "the source-owned gateway is missing or no longer a regular executable"
    fi
    if [[ "${actual_digest}" != "${expected_digest}" ]]; then
        # Admit an interrupted same-checkout rebuild only when the two exact
        # descriptors match.  Publication will independently bind its source
        # read to this digest before it can replace the destination.
        if VERIFIED_GATEWAY_DIGEST="$(matching_gateway_digest)"; then
            [[ "${VERIFIED_GATEWAY_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "the descriptor-bound gateway comparison returned an invalid digest"
            return
        fi
        refuse "the installed gateway changed since the last successful source claim"
    fi
    VERIFIED_GATEWAY_DIGEST="${expected_digest}"
}

bind_dev_gateway() {
    [[ -e "${GATEWAY_PATH}" || -L "${GATEWAY_PATH}" ]] || return 0
    if ! VERIFIED_GATEWAY_DIGEST="$(sha256_regular "${GATEWAY_PATH}" --require-executable)"; then
        refuse "the developer-owned gateway is missing or no longer a regular executable"
    fi
    [[ "${VERIFIED_GATEWAY_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
        || refuse "the developer-owned gateway returned an invalid digest"
}

check_owner() {
    local owned=0
    local cli_target=""
    local path_cli=""
    local marker_owned=0
    local marker_reclaim=0
    local cli_owned=0
    local marker_fields=""
    local marker_gateway_digest=""

    if [[ -e "${MARKER}" || -L "${MARKER}" ]]; then
        if [[ "${DEV_RECLAIM_SOURCE}" -eq 1 ]]; then
            if ! marker_fields="$(
                python3 "${SOURCE_IDENTITY_HELPER}" validate-marker \
                    --path "${MARKER}" \
                    --checkout-root "${REPO_ROOT}" \
                    --source-release "${SOURCE_RELEASE}" \
                    --compatibility-epoch "${SOURCE_INSTALL_COMPATIBILITY_EPOCH}" \
                    --runtime-config-version "${SOURCE_RUNTIME_CONFIG_VERSION}" \
                    --allow-source-transition 2>&1
            )"; then
                refuse "the developer source-install marker is invalid or belongs to another checkout (${marker_fields})"
            fi
            IFS=$'\t' read -r VERIFIED_MARKER_DIGEST marker_gateway_digest <<< "${marker_fields}"
            [[ "${VERIFIED_MARKER_DIGEST}" =~ ^[0-9a-f]{64}$ \
               && "${marker_gateway_digest}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "the developer source-install marker returned an invalid digest contract"
            marker_reclaim=1
        else
            if ! marker_fields="$(
                python3 "${SOURCE_IDENTITY_HELPER}" validate-marker \
                    --path "${MARKER}" \
                    --checkout-root "${REPO_ROOT}" \
                    --source-release "${SOURCE_RELEASE}" \
                    --compatibility-epoch "${SOURCE_INSTALL_COMPATIBILITY_EPOCH}" \
                    --runtime-config-version "${SOURCE_RUNTIME_CONFIG_VERSION}" 2>&1
            )"; then
                if [[ "${marker_fields}" == *"legacy source-install marker"* ]]; then
                    refuse "the existing legacy source-install marker cannot prove its original release or compatibility epoch; it was preserved"
                fi
                refuse "the source-install ownership marker is invalid or belongs to another release identity (${marker_fields})"
            fi
            IFS=$'\t' read -r VERIFIED_MARKER_DIGEST marker_gateway_digest <<< "${marker_fields}"
            [[ "${VERIFIED_MARKER_DIGEST}" =~ ^[0-9a-f]{64}$ \
               && "${marker_gateway_digest}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "the validated source-install marker returned an invalid digest contract"
            owned=1
            marker_owned=1
        fi
    fi

    if [[ -e "${CLI_PATH}" || -L "${CLI_PATH}" ]]; then
        if [[ "${IS_WINDOWS}" -eq 1 ]]; then
            [[ ! -L "${CLI_PATH}" ]] \
                || refuse "${CLI_PATH} is a reparse-backed CLI and is not owned by this checkout"
            if ! VERIFIED_CLI_DIGEST="$(matching_cli_digest)"; then
                refuse "${CLI_PATH} is not the exact CLI copy owned by this checkout"
            fi
            [[ "${VERIFIED_CLI_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "the descriptor-bound CLI comparison returned an invalid digest"
        else
            [[ -L "${CLI_PATH}" ]] \
                || refuse "${CLI_PATH} is not the CLI symlink owned by this checkout"
            cli_target="$(readlink "${CLI_PATH}")"
            [[ "${cli_target}" == "${EXPECTED_CLI}" ]] \
                || refuse "${CLI_PATH} points to another installation (${cli_target})"
        fi
        cli_owned=1
    fi

    path_cli="$(command -v "${PATH_COMMAND}" 2>/dev/null || true)"
    if [[ "${IS_WINDOWS}" -eq 1 && -n "${path_cli}" \
       && "${path_cli,,}" != *.exe && -f "${path_cli}.exe" ]]; then
        # Git Bash may omit PATHEXT from `command -v` even though it executes
        # the .exe. Normalize that presentation before the ownership check.
        path_cli="${path_cli}.exe"
    fi
    if [[ -n "${path_cli}" && "${path_cli}" != "${CLI_PATH}" && "${path_cli}" != "${EXPECTED_CLI}" ]]; then
        refuse "PATH resolves ${PATH_COMMAND} to another installation (${path_cli})"
    fi

    if [[ "${marker_reclaim}" -eq 1 && "${cli_owned}" -ne 1 ]]; then
        refuse "make all can reclaim developer state only when the installed CLI belongs to this exact checkout"
    fi

    if [[ "${marker_owned}" -eq 1 ]]; then
        check_recorded_gateway "${marker_gateway_digest}"
    elif [[ "${cli_owned}" -eq 1 ]]; then
        # A markerless exact CLI can be a first-install crash. Direct install
        # targets still fail closed when managed state exists because the
        # editable checkout may have advanced across a release boundary.
        # `make all` is the explicit developer-machine reinstall workflow and
        # opts into reclaiming this one exact-checkout layout; the successful
        # gateway publication records the strict marker for later rebuilds.
        if [[ "${DEV_RECLAIM_SOURCE}" -eq 1 \
           && ( "${marker_reclaim}" -eq 1 || -e "${MANAGED_HOME}" || -L "${MANAGED_HOME}" ) ]]; then
            bind_dev_gateway
        elif [[ -e "${MANAGED_HOME}" || -L "${MANAGED_HOME}" ]]; then
            refuse "managed state exists beside a markerless source CLI, so its original release identity is unknowable"
        elif [[ -e "${GATEWAY_PATH}" || -L "${GATEWAY_PATH}" ]]; then
            check_gateway_claim
        fi
    elif [[ "${owned}" -ne 1 ]]; then
        if [[ -e "${GATEWAY_PATH}" || -L "${GATEWAY_PATH}" ]]; then
            refuse "an unowned gateway already exists at ${GATEWAY_PATH}"
        fi
        if [[ -e "${MANAGED_HOME}" || -L "${MANAGED_HOME}" ]]; then
            refuse "existing managed state was found at ${MANAGED_HOME}"
        fi
    fi
}

[[ -f "${PUBLISH_HELPER}" && ! -L "${PUBLISH_HELPER}" ]] \
    || refuse "the descriptor-bound source publication helper is unavailable"
[[ -f "${PUBLISH_MODULE}" && ! -L "${PUBLISH_MODULE}" ]] \
    || refuse "the descriptor-bound source publication module is unavailable"
[[ -f "${SOURCE_IDENTITY_HELPER}" && ! -L "${SOURCE_IDENTITY_HELPER}" ]] \
    || refuse "the reviewed source-release identity validator is unavailable"

if ! SOURCE_IDENTITY_FIELDS="$(
    python3 "${SOURCE_IDENTITY_HELPER}" check --root "${REPO_ROOT}" --machine 2>&1
)"; then
    refuse "the checkout source-release identity is invalid (${SOURCE_IDENTITY_FIELDS})"
fi
readonly SOURCE_IDENTITY_FIELDS
IFS=$'\t' read -r SOURCE_RELEASE SOURCE_INSTALL_COMPATIBILITY_EPOCH \
    SOURCE_RUNTIME_CONFIG_VERSION <<< "${SOURCE_IDENTITY_FIELDS}"
[[ "${SOURCE_RELEASE}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ \
   && "${SOURCE_INSTALL_COMPATIBILITY_EPOCH}" =~ ^[1-9][0-9]*$ \
   && "${SOURCE_RUNTIME_CONFIG_VERSION}" =~ ^[1-9][0-9]*$ ]] \
    || refuse "the checkout source-release identity returned invalid machine fields"
readonly SOURCE_RELEASE SOURCE_INSTALL_COMPATIBILITY_EPOCH SOURCE_RUNTIME_CONFIG_VERSION

check_owner

case "${MODE}" in
    check)
        ;;
    ensure-dir)
        python3 "${PUBLISH_HELPER}" ensure-directory "${INSTALL_DIR}" \
            || refuse "could not reserve a real source-install directory"
        ;;
    publish-cli)
        if [[ "${IS_WINDOWS}" -eq 1 ]]; then
            if ! SOURCE_CLI_DIGEST="$(sha256_regular "${EXPECTED_CLI}" --require-executable)"; then
                refuse "this checkout's built CLI is unavailable for publication"
            fi
            readonly SOURCE_CLI_DIGEST
            cli_args=(
                regular "${EXPECTED_CLI}" "${CLI_PATH}"
                --expected-source-sha256 "${SOURCE_CLI_DIGEST}"
            )
            if [[ -n "${VERIFIED_CLI_DIGEST}" ]]; then
                cli_args+=(--expected-current-sha256 "${VERIFIED_CLI_DIGEST}")
            fi
            python3 "${PUBLISH_HELPER}" "${cli_args[@]}" \
                || refuse "the source CLI destination changed after preflight"
        else
            python3 "${PUBLISH_HELPER}" symlink "${EXPECTED_CLI}" "${CLI_PATH}" \
                || refuse "the source CLI destination changed after preflight"
        fi
        ;;
    publish-gateway)
        if ! SOURCE_GATEWAY_DIGEST="$(sha256_regular "${EXPECTED_GATEWAY}" --require-executable)"; then
            refuse "this checkout's built gateway is unavailable for publication"
        fi
        readonly SOURCE_GATEWAY_DIGEST
        if [[ -e "${GATEWAY_PATH}" || -L "${GATEWAY_PATH}" ]]; then
            [[ -n "${VERIFIED_GATEWAY_DIGEST}" ]] \
                || refuse "the installed gateway was not bound to the completed ownership check"
        fi
        publish_args=(
            regular "${EXPECTED_GATEWAY}" "${GATEWAY_PATH}"
            --expected-source-sha256 "${SOURCE_GATEWAY_DIGEST}"
        )
        if [[ -n "${VERIFIED_GATEWAY_DIGEST}" ]]; then
            publish_args+=(--expected-current-sha256 "${VERIFIED_GATEWAY_DIGEST}")
        fi
        python3 "${PUBLISH_HELPER}" "${publish_args[@]}" \
            || refuse "the source gateway destination changed after preflight"
        ;;
    claim)
        if [[ "${IS_WINDOWS}" -eq 1 ]]; then
            [[ ! -L "${CLI_PATH}" && "${VERIFIED_CLI_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "cannot claim ownership without this checkout's exact CLI copy"
        else
            [[ -L "${CLI_PATH}" && "$(readlink "${CLI_PATH}")" == "${EXPECTED_CLI}" ]] \
                || refuse "cannot claim ownership without this checkout's exact CLI symlink"
        fi
        check_gateway_claim
        readonly GATEWAY_DIGEST="${VERIFIED_GATEWAY_DIGEST}"
        umask 077
        MARKER_TMP="$(mktemp "${MARKER}.claim.XXXXXX")" \
            || refuse "could not create a private source ownership marker"
        readonly MARKER_TMP
        trap 'rm -f "${MARKER_TMP}"' EXIT INT TERM
        python3 "${SOURCE_IDENTITY_HELPER}" render-marker \
            --checkout-root "${REPO_ROOT}" \
            --source-release "${SOURCE_RELEASE}" \
            --compatibility-epoch "${SOURCE_INSTALL_COMPATIBILITY_EPOCH}" \
            --runtime-config-version "${SOURCE_RUNTIME_CONFIG_VERSION}" \
            --gateway-sha256 "${GATEWAY_DIGEST}" > "${MARKER_TMP}" \
            || refuse "could not render the strict source ownership marker"
        if ! MARKER_SOURCE_DIGEST="$(sha256_regular "${MARKER_TMP}")"; then
            refuse "could not bind the staged source ownership marker"
        fi
        readonly MARKER_SOURCE_DIGEST
        marker_args=(
            regular "${MARKER_TMP}" "${MARKER}"
            --expected-source-sha256 "${MARKER_SOURCE_DIGEST}"
        )
        if [[ -e "${MARKER}" || -L "${MARKER}" ]]; then
            [[ "${VERIFIED_MARKER_DIGEST}" =~ ^[0-9a-f]{64}$ ]] \
                || refuse "the existing source ownership marker was not bound to its completed identity check"
            marker_args+=(--expected-current-sha256 "${VERIFIED_MARKER_DIGEST}")
        fi
        python3 "${PUBLISH_HELPER}" "${marker_args[@]}" \
            || refuse "the source ownership marker changed after verification"
        ;;
esac
