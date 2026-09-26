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
# This script only fetches the latest release's install.sh, checks it against
# that release's checksums.txt, and runs it. Keep it this small: 0.8.x clients
# run whatever version of it the channel names, so it cannot be hot-patched.
# The last line must stay exactly as it is; 0.8.x clients require it.

set -eu

dc_handoff() {
    local repo="${DEFENSECLAW_REPO:-cisco-ai-defense/defenseclaw}" yes="" plan=0 tag tmp expected
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --yes|-y) yes="--yes" ;;
            # 0.8.x always passes its channel's target; 1.x installs the latest release.
            --version) [ "$#" -gt 1 ] && shift ;;
            --version=*) ;;
            --plan) plan=1 ;;
            *) echo "  ! ignoring unsupported option: $1" >&2 ;;
        esac
        shift
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
        tag="$(curl -fsSI --proto '=https' --tlsv1.2 "https://github.com/${repo}/releases/latest" \
            | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}' | tail -1)"
        tag="${tag##*/tag/}"
        case "${tag}" in
            [1-9]*.*.*) ;;
            *) echo "  ✗ could not find a DefenseClaw 1.x release; nothing was changed" >&2; return 1 ;;
        esac
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/install.sh" \
            "https://github.com/${repo}/releases/download/${tag}/install.sh"
        curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "${tmp}/checksums.txt" \
            "https://github.com/${repo}/releases/download/${tag}/checksums.txt"
        set --
    fi
    expected="$(awk '$2=="install.sh"||$2=="*install.sh"{print $1}' "${tmp}/checksums.txt")"
    if [ -z "${expected}" ] || [ "${expected}" != "$( (sha256sum "${tmp}/install.sh" 2>/dev/null || shasum -a 256 "${tmp}/install.sh") | awk '{print $1}')" ]; then
        echo "  ✗ install.sh does not match checksums.txt; nothing was changed" >&2
        return 1
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
