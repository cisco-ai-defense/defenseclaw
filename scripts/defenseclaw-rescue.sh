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

# Minimal external recovery entry point. It authenticates the mutable stable
# channel, validates that every target locator is derived from the immutable
# tag, verifies the exact tagged resolver digest, and only then executes it.

set -euo pipefail
umask 077

readonly REPOSITORY="cisco-ai-defense/defenseclaw"
readonly CHANNEL_BASE_URL="https://raw.githubusercontent.com/${REPOSITORY}/release-channel"
readonly RELEASE_WORKFLOW_IDENTITY="https://github.com/${REPOSITORY}/.github/workflows/release.yaml@refs/heads/main"
readonly SIGSTORE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly COSIGN_VERSION="2.6.3"
readonly COSIGN_RELEASE_URL="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}"
readonly CHANNEL_SCHEMA="defenseclaw-release-channel-v1"
readonly CHANNEL_NAME="stable"
readonly RESOLVER_NAME="defenseclaw-upgrade.sh"
readonly RESOLVER_COMPLETENESS_MARKER="# DefenseClaw upgrade resolver complete v1"
readonly MAX_CHANNEL_FILE_BYTES=65536
readonly MAX_RESOLVER_BYTES=4194304
readonly MAX_COSIGN_BYTES=209715200

die() {
    printf 'DefenseClaw rescue failed: %s\n' "$*" >&2
    exit 1
}

download() {
    local url="$1" destination="$2" max_bytes="$3"
    for _ in 1 2 3; do
        if curl --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --max-filesize "${max_bytes}" \
            --output "${destination}" "${url}"; then
            [[ -f "${destination}" && ! -L "${destination}" ]] \
                || die "download did not create a regular file: ${url}"
            local size
            size="$(wc -c < "${destination}" | tr -d '[:space:]')"
            [[ "${size}" =~ ^[0-9]+$ && "${size}" -gt 0 && "${size}" -le "${max_bytes}" ]] \
                || die "download has invalid size: ${url}"
            return 0
        fi
    done
    die "could not download ${url}"
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v bash >/dev/null 2>&1 || die "bash is required"
for argument in "$@"; do
    case "${argument}" in
        --version | --version=*)
            die "the authenticated stable channel owns the rescue target version"
            ;;
        --allow-unverified)
            die "the authenticated rescue path does not permit --allow-unverified"
            ;;
    esac
done

workdir="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-rescue.XXXXXX")"
readonly workdir
cleanup() {
    local status=$?
    rm -rf -- "${workdir}"
    return "${status}"
}
trap cleanup EXIT

cosign_bin="$(command -v cosign || true)"
if [[ -z "${cosign_bin}" ]]; then
    platform="$(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)"
    case "${platform}" in
        darwin/x86_64)
            cosign_asset="cosign-darwin-amd64"
            cosign_sha256="5715d61dd00a9b6dcb344de14910b434145855b7f82690b94183c553ac1b68be"
            ;;
        darwin/arm64)
            cosign_asset="cosign-darwin-arm64"
            cosign_sha256="ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e"
            ;;
        linux/x86_64 | linux/amd64)
            cosign_asset="cosign-linux-amd64"
            cosign_sha256="7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4"
            ;;
        linux/aarch64 | linux/arm64)
            cosign_asset="cosign-linux-arm64"
            cosign_sha256="b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917"
            ;;
        *)
            die "unsupported platform for automatic Cosign verification: ${platform}"
            ;;
    esac
    cosign_bin="${workdir}/${cosign_asset}"
    download \
        "${COSIGN_RELEASE_URL}/${cosign_asset}" \
        "${cosign_bin}" \
        "${MAX_COSIGN_BYTES}"
    [[ "$(sha256_file "${cosign_bin}")" == "${cosign_sha256}" ]] \
        || die "downloaded Cosign digest mismatch"
    chmod 700 "${cosign_bin}"
fi

channel="${workdir}/stable.txt"
for suffix in "" ".bundle"; do
    download \
        "${CHANNEL_BASE_URL}/stable.txt${suffix}" \
        "${channel}${suffix}" \
        "${MAX_CHANNEL_FILE_BYTES}"
done

"${cosign_bin}" verify-blob \
    --bundle "${channel}.bundle" \
    --certificate-identity "${RELEASE_WORKFLOW_IDENTITY}" \
    --certificate-oidc-issuer "${SIGSTORE_OIDC_ISSUER}" \
    "${channel}" >/dev/null

line_count="$(wc -l < "${channel}" | tr -d '[:space:]')"
[[ "${line_count}" == "10" ]] \
    || die "authenticated channel must contain exactly 10 canonical fields"

schema="$(sed -n '1s/^schema=//p' "${channel}")"
channel_name="$(sed -n '2s/^channel=//p' "${channel}")"
repository="$(sed -n '3s/^repository=//p' "${channel}")"
target_version="$(sed -n '4s/^target_version=//p' "${channel}")"
target_tag="$(sed -n '5s/^target_tag=//p' "${channel}")"
target_ref="$(sed -n '6s/^target_ref=//p' "${channel}")"
target_commit="$(sed -n '7s/^target_commit=//p' "${channel}")"
resolver_name="$(sed -n '8s/^resolver_name=//p' "${channel}")"
resolver_url="$(sed -n '9s/^resolver_url=//p' "${channel}")"
resolver_sha256="$(sed -n '10s/^resolver_sha256=//p' "${channel}")"

[[ "${schema}" == "${CHANNEL_SCHEMA}" ]] || die "unsupported channel schema"
[[ "${channel_name}" == "${CHANNEL_NAME}" ]] || die "unexpected release channel"
[[ "${repository}" == "${REPOSITORY}" ]] || die "channel repository mismatch"
[[ "${target_version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "channel target version is not canonical"
[[ "${target_tag}" == "${target_version}" ]] || die "channel tag/version mismatch"
[[ "${target_ref}" == "refs/tags/${target_version}" ]] \
    || die "channel ref is not the exact target tag"
[[ "${target_commit}" =~ ^[0-9a-f]{40}$ ]] \
    || die "channel target commit is invalid"
[[ "${resolver_name}" == "${RESOLVER_NAME}" ]] || die "channel resolver name mismatch"
expected_resolver_url="https://github.com/${REPOSITORY}/releases/download/${target_version}/${RESOLVER_NAME}"
[[ "${resolver_url}" == "${expected_resolver_url}" ]] \
    || die "channel resolver URL is not derived from its immutable tag"
[[ "${resolver_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "channel resolver digest is invalid"

canonical="${workdir}/stable.canonical"
printf '%s\n' \
    "schema=${schema}" \
    "channel=${channel_name}" \
    "repository=${repository}" \
    "target_version=${target_version}" \
    "target_tag=${target_tag}" \
    "target_ref=${target_ref}" \
    "target_commit=${target_commit}" \
    "resolver_name=${resolver_name}" \
    "resolver_url=${resolver_url}" \
    "resolver_sha256=${resolver_sha256}" \
    > "${canonical}"
cmp -s "${channel}" "${canonical}" || die "channel encoding is not canonical"

resolver="${workdir}/${RESOLVER_NAME}"
download "${resolver_url}" "${resolver}" "${MAX_RESOLVER_BYTES}"
[[ "$(sha256_file "${resolver}")" == "${resolver_sha256}" ]] \
    || die "tagged resolver digest does not match the authenticated channel"
[[ "$(tail -n 1 "${resolver}")" == "${RESOLVER_COMPLETENESS_MARKER}" ]] \
    || die "tagged resolver is incomplete"
bash -n "${resolver}" || die "tagged resolver has invalid shell syntax"

printf 'Authenticated stable resolver %s (%s); starting recovery controller.\n' \
    "${target_version}" "${target_commit}"
unset VERSION
unset DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED
bash "${resolver}" --version "${target_version}" "$@"
# DefenseClaw rescue bootstrap complete v1
