#!/bin/sh
# shellcheck shell=bash
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
# tag, verifies the exact tagged resolver or POSIX installer digest, and only
# then executes the selected recovery or fresh-install controller.

# Enter a fixed system Bash through a minimal POSIX trampoline. /bin/sh does not
# consume BASH_ENV or import exported Bash functions for this script. A second
# POSIX shell starts with an empty environment, restores only the explicit
# network and operator-path allowlist, and then executes the embedded Bash
# payload from a dedicated descriptor. The payload is embedded instead of
# re-executing this file, so no inherited marker can suppress the clean
# environment boundary. The allowed values remain positional data until the
# clean shell exports them.
rescue_script="${0-}"
case "${rescue_script}" in
    sh | bash | -sh | -bash | */sh | */bash)
        rescue_script=""
        ;;
esac
rescue_script_header=""
if [ -z "${rescue_script}" ] ||
    [ ! -f "${rescue_script}" ] ||
    [ ! -r "${rescue_script}" ] ||
    ! IFS= read -r rescue_script_header < "${rescue_script}" ||
    [ "${rescue_script_header}" != "#!/bin/sh" ]; then
    printf '%s\n' \
        'DefenseClaw rescue failed: save this bootstrap as a readable regular file before running it; shell pipes and standard input are unsupported' \
        >&2
    exit 1
fi
rescue_cosign_candidate="$(
    PATH="${PATH-}" command -v cosign 2>/dev/null || true
)"
rescue_bash_failure() {
    printf 'DefenseClaw rescue failed: could not enter trusted system Bash\n' >&2
    exit 1
}
# The clean child shell, not this ambient trampoline, expands the environment
# values. Descriptor 3 contains only the reviewed payload; standard input stays
# attached to the operator for installer prompts.
# shellcheck disable=SC2016
exec /usr/bin/env -i /bin/sh -c '
    while [ "$#" -ge 3 ] && [ "$1" != "--" ]; do
        if [ "$2" = x ]; then
            export "$1=$3"
        fi
        shift 3
    done
    [ "${1-}" = "--" ] || exit 125
    shift
    exec /bin/bash /dev/fd/3 "$@"
' defenseclaw-rescue-environment \
    PATH x "/usr/bin:/bin:/usr/sbin:/sbin" \
    HOME "${HOME+x}" "${HOME-}" \
    TMPDIR "${TMPDIR+x}" "${TMPDIR-}" \
    XDG_CONFIG_HOME "${XDG_CONFIG_HOME+x}" "${XDG_CONFIG_HOME-}" \
    XDG_CACHE_HOME "${XDG_CACHE_HOME+x}" "${XDG_CACHE_HOME-}" \
    XDG_DATA_HOME "${XDG_DATA_HOME+x}" "${XDG_DATA_HOME-}" \
    XDG_STATE_HOME "${XDG_STATE_HOME+x}" "${XDG_STATE_HOME-}" \
    DEFENSECLAW_HOME "${DEFENSECLAW_HOME+x}" "${DEFENSECLAW_HOME-}" \
    DEFENSECLAW_CONFIG "${DEFENSECLAW_CONFIG+x}" "${DEFENSECLAW_CONFIG-}" \
    OPENCLAW_HOME "${OPENCLAW_HOME+x}" "${OPENCLAW_HOME-}" \
    HTTP_PROXY "${HTTP_PROXY+x}" "${HTTP_PROXY-}" \
    HTTPS_PROXY "${HTTPS_PROXY+x}" "${HTTPS_PROXY-}" \
    ALL_PROXY "${ALL_PROXY+x}" "${ALL_PROXY-}" \
    NO_PROXY "${NO_PROXY+x}" "${NO_PROXY-}" \
    http_proxy "${http_proxy+x}" "${http_proxy-}" \
    https_proxy "${https_proxy+x}" "${https_proxy-}" \
    all_proxy "${all_proxy+x}" "${all_proxy-}" \
    no_proxy "${no_proxy+x}" "${no_proxy-}" \
    SSL_CERT_FILE "${SSL_CERT_FILE+x}" "${SSL_CERT_FILE-}" \
    SSL_CERT_DIR "${SSL_CERT_DIR+x}" "${SSL_CERT_DIR-}" \
    CURL_CA_BUNDLE "${CURL_CA_BUNDLE+x}" "${CURL_CA_BUNDLE-}" \
    REQUESTS_CA_BUNDLE "${REQUESTS_CA_BUNDLE+x}" "${REQUESTS_CA_BUNDLE-}" \
    DEFENSECLAW_RESCUE_COSIGN_CANDIDATE x "${rescue_cosign_candidate}" \
    -- "$@" 3<<'# DefenseClaw rescue bootstrap complete v1' || rescue_bash_failure

cosign_candidate="${DEFENSECLAW_RESCUE_COSIGN_CANDIDATE-}"
unset DEFENSECLAW_RESCUE_COSIGN_CANDIDATE
set -euo pipefail
umask 077
# These values can change how Bash parses later constructs. Clear them before
# the first Bash-specific compound command; they are cleared again before
# every authenticated child process below.
unset BASH_ENV ENV BASH_COMPAT POSIXLY_CORRECT

readonly REPOSITORY="cisco-ai-defense/defenseclaw"
readonly CHANNEL_REF_URL="https://api.github.com/repos/${REPOSITORY}/git/ref/heads/release-channel"
readonly CHANNEL_RAW_BASE_URL="https://raw.githubusercontent.com/${REPOSITORY}"
readonly RELEASE_WORKFLOW_IDENTITY="https://github.com/${REPOSITORY}/.github/workflows/release.yaml@refs/heads/main"
readonly SIGSTORE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly COSIGN_VERSION="2.6.3"
readonly COSIGN_RELEASE_URL="https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}"
readonly CHANNEL_SCHEMA="defenseclaw-release-channel-v1"
readonly CHANNEL_NAME="stable"
readonly RESOLVER_NAME="defenseclaw-upgrade.sh"
readonly POSIX_INSTALLER_NAME="install.sh"
readonly WINDOWS_INSTALLER_NAME="install.ps1"
readonly RESOLVER_COMPLETENESS_MARKER="# DefenseClaw upgrade resolver complete v1"
readonly MAX_CHANNEL_REF_BYTES=65536
readonly MAX_CHANNEL_BYTES=16384
readonly MAX_CHANNEL_BUNDLE_BYTES=1048576
readonly MAX_RESOLVER_BYTES=4194304
readonly MAX_INSTALLER_BYTES=4194304
readonly MAX_COSIGN_BYTES=209715200
readonly MAX_SYSTEM_BASH_BYTES=67108864
readonly CURL_CONNECT_TIMEOUT_SECONDS=30
readonly CURL_TOTAL_TIMEOUT_SECONDS=300
readonly CURL_LOW_SPEED_LIMIT_BYTES=1024
readonly CURL_LOW_SPEED_TIME_SECONDS=60
readonly TRUSTED_BASH="/bin/bash"
readonly CURL_BIN="/usr/bin/curl"
readonly STAT_BIN="/usr/bin/stat"
readonly UNAME_BIN="/usr/bin/uname"
readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"
readonly TRUSTED_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# An existing Cosign is only an optimization source. It is never executed in
# place: its bytes must first be copied into the private work directory and
# match the platform's pinned digest.
readonly cosign_candidate
PATH="${TRUSTED_PATH}"
export PATH

macos_hardware_machine() {
    local machine="$1"
    if [[ "${machine}" == "x86_64" || "${machine}" == "amd64" ]] \
        && [[ -x "${MACOS_SYSCTL_BIN}" && ! -L "${MACOS_SYSCTL_BIN}" ]] \
        && [[ "$("${MACOS_SYSCTL_BIN}" -in sysctl.proc_translated 2>/dev/null || true)" == "1" ]]; then
        printf '%s\n' "arm64"
        return 0
    fi
    printf '%s\n' "${machine}"
}

sanitize_authenticated_environment() {
    unset BASH_ENV ENV CDPATH GLOBIGNORE BASH_COMPAT POSIXLY_CORRECT
    unset PROMPT_COMMAND
    unset VERSION DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED
    unset GODEBUG GOFLAGS
    unset PYTHONPATH PYTHONHOME PYTHONINSPECT PYTHONSTARTUP PYTHONUSERBASE
    unset PYTHONWARNINGS PYTHONBREAKPOINT
    unset PERL5OPT PERL5DB PERL5LIB PERLLIB
    unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT
    unset LD_PROFILE LD_USE_LOAD_BIAS
    unset DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH
    unset DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH
    unset DYLD_PRINT_APIS DYLD_PRINT_BINDINGS DYLD_PRINT_INITIALIZERS
    unset DYLD_PRINT_LIBRARIES DYLD_PRINT_LIBRARIES_POST_LAUNCH
    unset DYLD_PRINT_OPTS DYLD_PRINT_REBASINGS DYLD_PRINT_RPATHS
    unset DYLD_PRINT_SEGMENTS DYLD_PRINT_STATISTICS
    unset SIGSTORE_ROOT_FILE SIGSTORE_REKOR_PUBLIC_KEY
    unset SIGSTORE_CT_LOG_PUBLIC_KEY_FILE SIGSTORE_TSA_CERTIFICATE_FILE
    unset TUF_ROOT TUF_MIRROR TUF_ROOT_JSON
    export -n BASHOPTS SHELLOPTS 2>/dev/null || true
    IFS=$' \t\n'
}

system_bash_identity() {
    local identity
    case "$("${UNAME_BIN}" -s)" in
        Darwin)
            identity="$("${STAT_BIN}" -f '%d:%i:%u:%Lp:%z' "${TRUSTED_BASH}")"
            ;;
        Linux)
            identity="$("${STAT_BIN}" -c '%d:%i:%u:%a:%s' "${TRUSTED_BASH}")"
            ;;
        *)
            return 1
            ;;
    esac
    printf '%s\n' "${identity}"
}

validate_trusted_bash() {
    [[ -f "${TRUSTED_BASH}" && ! -L "${TRUSTED_BASH}" && -x "${TRUSTED_BASH}" ]] \
        || die "a trusted system Bash interpreter is unavailable"

    local identity device inode owner mode size
    identity="$(system_bash_identity)" \
        || die "could not inspect the trusted system Bash interpreter"
    IFS=: read -r device inode owner mode size <<< "${identity}"
    [[ "${device}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ ]] \
        || die "trusted system Bash identity is invalid"
    [[ "${owner}" == "0" ]] || die "trusted system Bash is not root-owned"
    [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || die "trusted system Bash mode is invalid"
    [[ "${size}" =~ ^[0-9]+$ && "${size}" -gt 0 && "${size}" -le "${MAX_SYSTEM_BASH_BYTES}" ]] \
        || die "trusted system Bash size is invalid"
    (( (8#${mode} & 8#022) == 0 )) \
        || die "trusted system Bash is writable by group or other"
    (( (8#${mode} & 8#111) != 0 )) || die "trusted system Bash is not executable"
    printf '%s\n' "${identity}"
}

assert_trusted_bash_stable() {
    local current_identity
    current_identity="$(validate_trusted_bash)"
    [[ "${current_identity}" == "${trusted_bash_identity}" ]] \
        || die "trusted system Bash identity changed before execution"
}

private_temp_root_identity() {
    local path="$1"
    case "$("${UNAME_BIN}" -s)" in
        Darwin)
            # BSD stat splits the special mode bits (%Mp) from the ordinary
            # permission bits (%Lp). Keep both so a sticky shared root is not
            # mistaken for an ordinary 0755 directory.
            "${STAT_BIN}" -f '%d:%i:%u:%Mp%Lp' "${path}"
            ;;
        Linux)
            "${STAT_BIN}" -c '%d:%i:%u:%a' "${path}"
            ;;
        *)
            return 1
            ;;
    esac
}

validate_private_workdir() {
    local path="$1"
    [[ -d "${path}" && ! -L "${path}" ]] \
        || die "private rescue work directory is unavailable"

    local identity device inode owner mode
    identity="$(private_temp_root_identity "${path}")" \
        || die "could not inspect private rescue work directory"
    IFS=: read -r device inode owner mode <<< "${identity}"
    [[ "${device}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ \
        && "${owner}" == "${EUID}" && "${mode}" =~ ^[0-7]{3,4}$ ]] \
        || die "private rescue work directory identity is invalid"
    (( (8#${mode} & 8#7777) == 8#700 )) \
        || die "private rescue work directory mode is not 0700"
    printf '%s\n' "${identity}"
}

assert_trusted_execution_custody() {
    local current_workdir_identity
    current_workdir_identity="$(validate_private_workdir "${workdir}")"
    [[ "${current_workdir_identity}" == "${workdir_identity}" ]] \
        || die "private rescue work directory identity changed before execution"
    assert_trusted_bash_stable
}

regular_file_size() {
    local path="$1"
    case "$("${UNAME_BIN}" -s)" in
        Darwin)
            "${STAT_BIN}" -f '%z' "${path}"
            ;;
        Linux)
            "${STAT_BIN}" -c '%s' "${path}"
            ;;
        *)
            return 1
            ;;
    esac
}

die() {
    printf 'DefenseClaw rescue failed: %s\n' "$*" >&2
    exit 1
}

download() {
    local url="$1" destination="$2" max_bytes="$3"
    local attempt
    for attempt in 1 2 3; do
        if "${CURL_BIN}" --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout "${CURL_CONNECT_TIMEOUT_SECONDS}" \
            --max-time "${CURL_TOTAL_TIMEOUT_SECONDS}" \
            --speed-limit "${CURL_LOW_SPEED_LIMIT_BYTES}" \
            --speed-time "${CURL_LOW_SPEED_TIME_SECONDS}" \
            --header 'Cache-Control: no-cache' \
            --header 'Pragma: no-cache' \
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
        if (( attempt < 3 )); then
            sleep 1
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

release_channel_commit_from_ref() {
    local path="$1" ref_matches type_matches sha_matches sha_count commit
    ref_matches="$(
        grep -Eo '"ref"[[:space:]]*:[[:space:]]*"refs/heads/release-channel"' \
            "${path}" || true
    )"
    [[ "$(printf '%s\n' "${ref_matches}" | grep -c . || true)" == "1" ]] \
        || die "release channel ref response does not name the exact branch once"
    type_matches="$(
        grep -Eo '"type"[[:space:]]*:[[:space:]]*"commit"' "${path}" || true
    )"
    [[ "$(printf '%s\n' "${type_matches}" | grep -c . || true)" == "1" ]] \
        || die "release channel ref response does not name one commit"
    sha_matches="$(
        grep -Eo '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"' \
            "${path}" || true
    )"
    sha_count="$(printf '%s\n' "${sha_matches}" | grep -c . || true)"
    [[ "${sha_count}" == "1" ]] \
        || die "release channel ref response does not contain exactly one canonical commit ID"
    commit="$(
        printf '%s\n' "${sha_matches}" \
            | sed -E 's/^"sha"[[:space:]]*:[[:space:]]*"([0-9a-f]{40})"$/\1/'
    )"
    [[ "${commit}" =~ ^[0-9a-f]{40}$ ]] \
        || die "release channel commit locator is invalid"
    printf '%s\n' "${commit}"
}

[[ -x "${CURL_BIN}" && ! -L "${CURL_BIN}" ]] || die "trusted system curl is required"
[[ -x "${STAT_BIN}" && ! -L "${STAT_BIN}" ]] || die "trusted system stat is required"
[[ -x "${UNAME_BIN}" && ! -L "${UNAME_BIN}" ]] || die "trusted system uname is required"
sanitize_authenticated_environment
trusted_bash_identity="$(validate_trusted_bash)"
readonly trusted_bash_identity
rescue_mode="upgrade"
operator_arguments=()
while (($#)); do
    argument="$1"
    case "${argument}" in
        --install)
            [[ "${rescue_mode}" == "upgrade" ]] \
                || die "--install may be supplied only once"
            rescue_mode="install"
            ;;
        --install=*)
            die "--install does not accept a value"
            ;;
        --version | --version=*)
            die "the authenticated stable channel owns the rescue target version"
            ;;
        --allow-unverified | --allow-unverified=*)
            die "the authenticated rescue path does not permit --allow-unverified"
            ;;
        --local | --local=*)
            die "--local cannot replace the authenticated stable release"
            ;;
        --cosign-path | --cosign-path=*)
            die "--cosign-path cannot replace the authenticated rescue verifier"
            ;;
        *)
            operator_arguments+=("${argument}")
            ;;
    esac
    shift
done
if [[ "${rescue_mode}" == "install" ]]; then
    for argument in "${operator_arguments[@]+"${operator_arguments[@]}"}"; do
        case "${argument}" in
            --recover-corrupt-audit | --recover-corrupt-audit=* | --plan | --plan=*)
                die "${argument} is an upgrade-recovery option and is incompatible with --install"
                ;;
        esac
    done
fi
readonly rescue_mode

platform_os="$("${UNAME_BIN}" -s | tr '[:upper:]' '[:lower:]')"
platform_arch="$("${UNAME_BIN}" -m)"
if [[ "${platform_os}" == "darwin" ]]; then
    platform_arch="$(macos_hardware_machine "${platform_arch}")"
fi
platform="${platform_os}/${platform_arch}"
case "${platform}" in
    darwin/x86_64)
        die "Intel macOS is unsupported; DefenseClaw for macOS requires Apple Silicon (arm64)"
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
readonly platform cosign_asset cosign_sha256

temp_root_input="${TMPDIR:-/tmp}"
[[ "${temp_root_input}" == /* ]] || die "temporary directory root must be absolute"
temp_root="$(cd -P -- "${temp_root_input}" 2>/dev/null && pwd -P)" \
    || die "temporary directory root is unavailable"
[[ -d "${temp_root}" && ! -L "${temp_root}" ]] \
    || die "temporary directory root is unsafe"
temp_root_identity="$(private_temp_root_identity "${temp_root}")" \
    || die "could not inspect temporary directory root"
IFS=: read -r temp_device temp_inode temp_owner temp_mode <<< "${temp_root_identity}"
[[ "${temp_device}" =~ ^[0-9]+$ && "${temp_inode}" =~ ^[0-9]+$ \
    && "${temp_owner}" =~ ^[0-9]+$ && "${temp_mode}" =~ ^[0-7]{3,4}$ ]] \
    || die "temporary directory root identity is invalid"
if [[ "${temp_owner}" == "${EUID}" ]]; then
    (( (8#${temp_mode} & 8#022) == 0 )) \
        || die "current-user temporary directory root is group or other writable"
else
    [[ "${temp_owner}" == "0" ]] \
        || die "temporary directory root has an unexpected owner"
    (( (8#${temp_mode} & 8#1000) != 0 || (8#${temp_mode} & 8#022) == 0 )) \
        || die "shared system temporary directory root is non-sticky and group or other-writable"
fi
readonly temp_root temp_root_identity

workdir="$(mktemp -d "${temp_root}/defenseclaw-rescue.XXXXXX")"
readonly workdir
cleanup() {
    local status=$?
    rm -rf -- "${workdir}"
    return "${status}"
}
trap cleanup EXIT
[[ -d "${workdir}" && ! -L "${workdir}" && -O "${workdir}" ]] \
    || die "could not establish a private rescue work directory"
[[ "$(private_temp_root_identity "${temp_root}")" == "${temp_root_identity}" ]] \
    || die "temporary directory root changed while creating rescue custody"
chmod 700 "${workdir}"
workdir_identity="$(validate_private_workdir "${workdir}")"
readonly workdir_identity
cosign_home="${workdir}/cosign-home"
cosign_config="${workdir}/cosign-config"
cosign_cache="${workdir}/cosign-cache"
cosign_data="${workdir}/cosign-data"
cosign_state="${workdir}/cosign-state"
mkdir -m 700 "${cosign_home}" "${cosign_config}" "${cosign_cache}" \
    "${cosign_data}" "${cosign_state}"
readonly cosign_home cosign_config cosign_cache cosign_data cosign_state

cosign_bin="${workdir}/${cosign_asset}"
cosign_candidate_copy="${workdir}/.${cosign_asset}.candidate"
if [[ "${cosign_candidate}" == /* && -f "${cosign_candidate}" && ! -L "${cosign_candidate}" ]]; then
    cosign_candidate_size="$(regular_file_size "${cosign_candidate}" 2>/dev/null || true)"
    if [[ "${cosign_candidate_size}" =~ ^[0-9]+$ \
        && "${cosign_candidate_size}" -gt 0 \
        && "${cosign_candidate_size}" -le "${MAX_COSIGN_BYTES}" ]]; then
        cp "${cosign_candidate}" "${cosign_candidate_copy}"
        chmod 600 "${cosign_candidate_copy}"
        cosign_candidate_copy_size="$(regular_file_size "${cosign_candidate_copy}" 2>/dev/null || true)"
        if [[ "${cosign_candidate_copy_size}" == "${cosign_candidate_size}" \
            && "$(sha256_file "${cosign_candidate_copy}")" == "${cosign_sha256}" ]]; then
            mv "${cosign_candidate_copy}" "${cosign_bin}"
        else
            rm -f -- "${cosign_candidate_copy}"
        fi
    fi
fi

if [[ ! -f "${cosign_bin}" ]]; then
    download \
        "${COSIGN_RELEASE_URL}/${cosign_asset}" \
        "${cosign_bin}" \
        "${MAX_COSIGN_BYTES}"
    chmod 600 "${cosign_bin}"
    [[ "$(sha256_file "${cosign_bin}")" == "${cosign_sha256}" ]] \
        || die "downloaded Cosign digest mismatch"
fi
chmod 700 "${cosign_bin}"
readonly cosign_bin

download_channel_generation() (
    local channel_attempt="$1"
    local channel_attempt_dir channel_ref_document channel_commit channel_candidate

    channel_attempt_dir="${workdir}/channel-attempt-${channel_attempt}"
    mkdir -m 700 "${channel_attempt_dir}" \
        || die "could not create channel attempt ${channel_attempt}"
    channel_ref_document="${channel_attempt_dir}/release-channel-ref.json"
    download \
        "${CHANNEL_REF_URL}" \
        "${channel_ref_document}" \
        "${MAX_CHANNEL_REF_BYTES}"
    channel_commit="$(release_channel_commit_from_ref "${channel_ref_document}")" \
        || exit $?
    channel_candidate="${channel_attempt_dir}/stable.txt"
    if (( channel_attempt % 2 == 1 )); then
        download \
            "${CHANNEL_RAW_BASE_URL}/${channel_commit}/stable.txt" \
            "${channel_candidate}" \
            "${MAX_CHANNEL_BYTES}"
        download \
            "${CHANNEL_RAW_BASE_URL}/${channel_commit}/stable.txt.bundle" \
            "${channel_candidate}.bundle" \
            "${MAX_CHANNEL_BUNDLE_BYTES}"
    else
        download \
            "${CHANNEL_RAW_BASE_URL}/${channel_commit}/stable.txt.bundle" \
            "${channel_candidate}.bundle" \
            "${MAX_CHANNEL_BUNDLE_BYTES}"
        download \
            "${CHANNEL_RAW_BASE_URL}/${channel_commit}/stable.txt" \
            "${channel_candidate}" \
            "${MAX_CHANNEL_BYTES}"
    fi
    printf '%s\n' "${channel_candidate}"
)

channel=""
for channel_attempt in 1 2 3; do
    if channel_candidate="$(download_channel_generation "${channel_attempt}")"; then
        sanitize_authenticated_environment
        if HOME="${cosign_home}" \
            XDG_CONFIG_HOME="${cosign_config}" \
            XDG_CACHE_HOME="${cosign_cache}" \
            XDG_DATA_HOME="${cosign_data}" \
            XDG_STATE_HOME="${cosign_state}" \
            "${cosign_bin}" verify-blob \
                --bundle "${channel_candidate}.bundle" \
                --certificate-identity "${RELEASE_WORKFLOW_IDENTITY}" \
                --certificate-oidc-issuer "${SIGSTORE_OIDC_ISSUER}" \
                "${channel_candidate}" >/dev/null; then
            channel="${channel_candidate}"
            break
        fi
    fi
done
[[ -n "${channel}" ]] \
    || die "stable channel proof did not authenticate after 3 bounded generations"
readonly channel

line_count="$(wc -l < "${channel}" | tr -d '[:space:]')"
[[ "${line_count}" == "16" ]] \
    || die "authenticated channel must contain exactly 16 canonical fields"

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
posix_installer_name="$(sed -n '11s/^posix_installer_name=//p' "${channel}")"
posix_installer_url="$(sed -n '12s/^posix_installer_url=//p' "${channel}")"
posix_installer_sha256="$(sed -n '13s/^posix_installer_sha256=//p' "${channel}")"
windows_installer_name="$(sed -n '14s/^windows_installer_name=//p' "${channel}")"
windows_installer_url="$(sed -n '15s/^windows_installer_url=//p' "${channel}")"
windows_installer_sha256="$(sed -n '16s/^windows_installer_sha256=//p' "${channel}")"

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
[[ "${posix_installer_name}" == "${POSIX_INSTALLER_NAME}" ]] \
    || die "channel POSIX installer name mismatch"
expected_posix_installer_url="https://github.com/${REPOSITORY}/releases/download/${target_version}/${POSIX_INSTALLER_NAME}"
[[ "${posix_installer_url}" == "${expected_posix_installer_url}" ]] \
    || die "channel POSIX installer URL is not derived from its immutable tag"
[[ "${posix_installer_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "channel POSIX installer digest is invalid"
[[ "${windows_installer_name}" == "${WINDOWS_INSTALLER_NAME}" ]] \
    || die "channel Windows installer name mismatch"
expected_windows_installer_url="https://github.com/${REPOSITORY}/releases/download/${target_version}/${WINDOWS_INSTALLER_NAME}"
[[ "${windows_installer_url}" == "${expected_windows_installer_url}" ]] \
    || die "channel Windows installer URL is not derived from its immutable tag"
[[ "${windows_installer_sha256}" =~ ^[0-9a-f]{64}$ ]] \
    || die "channel Windows installer digest is invalid"

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
    "posix_installer_name=${posix_installer_name}" \
    "posix_installer_url=${posix_installer_url}" \
    "posix_installer_sha256=${posix_installer_sha256}" \
    "windows_installer_name=${windows_installer_name}" \
    "windows_installer_url=${windows_installer_url}" \
    "windows_installer_sha256=${windows_installer_sha256}" \
    > "${canonical}"
cmp -s "${channel}" "${canonical}" || die "channel encoding is not canonical"

if [[ "${rescue_mode}" == "install" ]]; then
    installer="${workdir}/${POSIX_INSTALLER_NAME}"
    download "${posix_installer_url}" "${installer}" "${MAX_INSTALLER_BYTES}"
    [[ "$(sha256_file "${installer}")" == "${posix_installer_sha256}" ]] \
        || die "tagged POSIX installer digest does not match the authenticated channel"
    sanitize_authenticated_environment
    assert_trusted_execution_custody
    "${TRUSTED_BASH}" -n "${installer}" || die "tagged POSIX installer has invalid shell syntax"
    printf 'Authenticated stable POSIX installer %s (%s); starting fresh installation.\n' \
        "${target_version}" "${target_commit}"
    sanitize_authenticated_environment
    assert_trusted_execution_custody
    VERSION="${target_version}" \
        "${TRUSTED_BASH}" "${installer}" \
            "${operator_arguments[@]+"${operator_arguments[@]}"}"
else
    resolver="${workdir}/${RESOLVER_NAME}"
    download "${resolver_url}" "${resolver}" "${MAX_RESOLVER_BYTES}"
    [[ "$(sha256_file "${resolver}")" == "${resolver_sha256}" ]] \
        || die "tagged resolver digest does not match the authenticated channel"
    [[ "$(tail -n 1 "${resolver}")" == "${RESOLVER_COMPLETENESS_MARKER}" ]] \
        || die "tagged resolver is incomplete"
    sanitize_authenticated_environment
    assert_trusted_execution_custody
    "${TRUSTED_BASH}" -n "${resolver}" || die "tagged resolver has invalid shell syntax"

    printf 'Authenticated stable resolver %s (%s); starting recovery controller.\n' \
        "${target_version}" "${target_commit}"
    sanitize_authenticated_environment
    assert_trusted_execution_custody
    "${TRUSTED_BASH}" "${resolver}" --version "${target_version}" \
        "${operator_arguments[@]+"${operator_arguments[@]}"}"
fi
# DefenseClaw rescue bootstrap complete v1
