#!/bin/bash
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

# Handoff from DefenseClaw 0.8.8-0.8.10 to the 1.x installer.
#
# `defenseclaw upgrade` on those versions downloads this file through the
# signed 0.8.x release channel and runs it as
#   bash defenseclaw-upgrade.sh [--yes] [--recover-corrupt-audit] --version X
# This script fetches the requested release's install.sh (or the latest when
# none was requested), verifies its checksums and signature, and runs it.
# --help and an unknown option stop it before it downloads anything
# (GAP-0466), and with no --version a latest release older than the install
# is "up to date", never a downgrade.
# Keep it small: 0.8.x clients
# run whatever version of it the channel names, so it cannot be hot-patched.
# The last line must stay exactly as it is; 0.8.x clients require it.

set -eu

dc_usage() {
    cat <<'USAGE'
Usage: bash defenseclaw-upgrade.sh [--yes] [--version X.Y.Z] [--plan]

Downloads the install.sh of DefenseClaw X.Y.Z (default: the latest release),
checks it against the release's checksums.txt and signature, and runs it.
`defenseclaw upgrade` on DefenseClaw 0.8.8-0.8.10 runs this file; from 1.0
run `defenseclaw upgrade`.

Options:
  --yes, -y          Do not prompt
  --version X.Y.Z    Install release X.Y.Z (an older one too)
  --plan             Say which installer would run, and change nothing
  --help, -h         Show this help

Exit codes:
  0  Done, or already up to date
  1  Not upgraded
  2  An unknown option or value (nothing was changed)
  Otherwise the exit code of the release's install.sh.
USAGE
}

dc_installed_version() {
    # What install.sh reports as "Installed": the gateway on PATH, else the
    # release venv's package.
    local version="" info
    if [ -x "${HOME}/.local/bin/defenseclaw-gateway" ]; then
        version="$("${HOME}/.local/bin/defenseclaw-gateway" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    fi
    if [ -z "${version}" ]; then
        for info in "${DEFENSECLAW_HOME:-${HOME}/.defenseclaw}"/.venv/lib/python*/site-packages/defenseclaw-*.dist-info; do
            [ -d "${info}" ] || continue
            version="$(printf '%s' "${info##*/defenseclaw-}" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+' || true)"
            break
        done
    fi
    printf '%s' "${version}"
}

dc_version_key() {
    local IFS=.
    # shellcheck disable=SC2086 # split X.Y.Z on the dots.
    set -- $1
    printf '%05d%05d%05d' "${1:-0}" "${2:-0}" "${3:-0}"
}

dc_usage_error() {
    echo "  ✗ $*; nothing was changed" >&2
    echo "    Run with --help for the options." >&2
}

dc_handoff() {
    # DEFENSECLAW_REPO only changes where the release is downloaded from; the
    # signature is always checked against the official release identity.
    local repo="${DEFENSECLAW_REPO:-cisco-ai-defense/defenseclaw}" release_base yes="" plan=0 requested="" version_given=0 tag tmp expected major stamped installed
    local signer='^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$'
    case "${repo}" in
        https://*) release_base="${repo%/}" ;;
        *) release_base="https://github.com/${repo}" ;;
    esac
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --yes|-y) yes="--yes" ;;
            --version)
                [ "$#" -ge 2 ] || { dc_usage_error "--version needs a release such as 1.0.0"; return 2; }
                requested="$2"; version_given=1; shift ;;
            --version=*) requested="${1#*=}"; version_given=1 ;;
            --plan) plan=1 ;;
            # The 1.x gateway moves a corrupt audit store aside on its own when
            # it starts, which is the recovery 0.8.x asks for with this flag.
            --recover-corrupt-audit)
                echo "  - a corrupt audit store is moved aside and replaced when the new gateway starts" >&2 ;;
            --help|-h) dc_usage; return 0 ;;
            # Nothing is downloaded yet: a typo never installs a release.
            *) dc_usage_error "unknown option: $1"; return 2 ;;
        esac
        shift
    done
    # An owner/name or an https:// URL; anything else would be appended to github.com (GAP-1065).
    if ! [[ "${repo}" =~ ^https://[^[:space:]]+$ || "${repo}" =~ ^[^[:space:]/:@]+/[^[:space:]/:@]+$ ]]; then
        dc_usage_error "DEFENSECLAW_REPO must be a GitHub owner/name or an https:// mirror URL (an http:// URL is not accepted)"; return 2
    fi
    if [ "${version_given}" = 1 ] && ! [[ "${requested}" =~ ^[1-9][0-9]*\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
        dc_usage_error "--version must look like 1.0.0"; return 2
    fi
    # A computer managed by the organization is updated through its MDM.
    for descriptor in /etc/defenseclaw/managed-runtime.json /opt/cisco/defenseclaw/etc/managed-runtime.json; do
        if [ -f "${descriptor}" ] && [ ! -L "${descriptor}" ]; then
            echo "  ✗ this computer's DefenseClaw is managed by your organization; your IT department updates it. Nothing was changed." >&2
            return 1
        fi
    done
    # A 0.8.x gateway that the installer restores on failure would skip its
    # readiness wait with this marker from the 0.8.x controller.
    unset DEFENSECLAW_UPGRADE_FRESH_PROCESS 2>/dev/null || true

    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064 # tmp is local; expand it now.
    trap "rm -rf '${tmp}'" EXIT
    if [ -n "${DEFENSECLAW_UPGRADE_LOCAL_DIR:-}" ]; then
        # Tests only: run the installer from a local release directory.
        cp "${DEFENSECLAW_UPGRADE_LOCAL_DIR}/install.sh" "${DEFENSECLAW_UPGRADE_LOCAL_DIR}/checksums.txt" "${tmp}/"
        set -- --local "${DEFENSECLAW_UPGRADE_LOCAL_DIR}"
        tag="local"
    else
        if [ "${version_given}" = 1 ]; then
            tag="${requested}"
        else
            tag="$(curl -fsSI --proto '=https' --tlsv1.2 "${release_base}/releases/latest" \
                | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -1)"
            tag="${tag##*/tag/}"
        fi
        case "${tag}" in
            [1-9]*.*.*) ;;
            *) echo "  ✗ could not find a DefenseClaw 1.x release; nothing was changed" >&2; return 1 ;;
        esac
        installed="$(dc_installed_version)"
        if [ "${version_given}" = 0 ] && [ -n "${installed}" ] \
            && [[ "$(dc_version_key "${tag#v}")" < "$(dc_version_key "${installed}")" ]]; then
            # An install newer than the latest release (a release candidate,
            # or a release not marked latest yet) is up to date; a downgrade
            # takes an explicit --version.
            echo "  ✓ DefenseClaw ${installed} is up to date (latest release: ${tag#v} is older). Nothing was changed."
            echo "    To install a specific release: bash defenseclaw-upgrade.sh --version X.Y.Z"
            return 0
        fi
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/install.sh" \
            "${release_base}/releases/download/${tag}/install.sh"
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt" \
            "${release_base}/releases/download/${tag}/checksums.txt"
        # With cosign 2.0 or later, check the release signature on checksums.txt.
        major="$(cosign version 2>/dev/null | awk '/GitVersion/{print $2}' | sed 's/^v//' | cut -d. -f1 || true)"
        case "${major}" in
            ''|*[!0-9]*) major=0 ;;
        esac
        if [ "${major}" -lt 2 ] && [ "${repo}" != "cisco-ai-defense/defenseclaw" ]; then
            echo "  ✗ a release from ${repo} needs cosign 2.0 or later to check its signature; nothing was changed" >&2
            return 1
        fi
        if [ "${major}" -ge 2 ]; then
            curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt.bundle" \
                "${release_base}/releases/download/${tag}/checksums.txt.bundle"
            if ! cosign verify-blob --bundle "${tmp}/checksums.txt.bundle" \
                --certificate-identity-regexp "${signer}" \
                --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                "${tmp}/checksums.txt" >/dev/null 2>&1; then
                echo "  ✗ the release signature on checksums.txt did not verify; nothing was changed" >&2
                return 1
            fi
        fi
        # The installer installs its own stamped version; say so explicitly.
        set -- --version "${tag}"
    fi
    expected="$(awk '$2=="install.sh"||$2=="*install.sh"{print $1}' "${tmp}/checksums.txt")"
    if [ -z "${expected}" ] || [ "${expected}" != "$( (sha256sum "${tmp}/install.sh" 2>/dev/null || shasum -a 256 "${tmp}/install.sh") | awk '{print $1}')" ]; then
        echo "  ✗ install.sh does not match checksums.txt; nothing was changed" >&2
        return 1
    fi
    if [ "${tag}" != "local" ]; then
        # Every release is signed by the same identity, so the signature alone
        # would let a mirror serve another (older) release under this tag.
        stamped="$(sed -n 's/^readonly DC_VERSION="\(.*\)"$/\1/p' "${tmp}/install.sh" | head -1)"
        if [ "${stamped#v}" != "${tag#v}" ]; then
            echo "  ✗ the installer served for ${tag} is release ${stamped:-unknown}; nothing was changed" >&2
            return 1
        fi
    fi
    if [ "${plan}" = 1 ]; then
        echo "  → would upgrade to DefenseClaw ${tag} by running its install.sh"
        return 0
    fi
    echo "  → handing off to the DefenseClaw ${tag} installer"
    /bin/bash "${tmp}/install.sh" ${yes} "$@"
}

dc_handoff "$@"
# DefenseClaw upgrade resolver complete v1
