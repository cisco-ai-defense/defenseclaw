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

# Advance the mutable stable pointer only after the immutable target release has
# been proved. The pointer bytes are signed by the release workflow's keyless
# Sigstore identity and every update is a non-forced, fast-forward Git commit.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly CHANNEL_BRANCH="release-channel"
readonly CHANNEL_REF="refs/heads/${CHANNEL_BRANCH}"
readonly CHANNEL_MANIFEST="stable.txt"
readonly CHANNEL_MANIFEST_MAX_BYTES=16384
readonly CHANNEL_SIGNATURE_MAX_BYTES=16384
readonly CHANNEL_CERTIFICATE_MAX_BYTES=65536
readonly CHANNEL_BUNDLE_MAX_BYTES=65536
readonly SIGNING_IDENTITY_PREFIX="https://github.com"
readonly SIGNING_OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly COSIGN_VERSION="2.6.3"
readonly GH_READ_ATTEMPTS=3
readonly GH_READ_RETRY_DELAYS=(1 2)
readonly GH_WRITE_ATTEMPTS=3
readonly GH_WRITE_RETRY_DELAYS=(1 2)
readonly CHANNEL_FILES=(
    "stable.txt"
    "stable.txt.sig"
    "stable.txt.pem"
    "stable.txt.bundle"
)

die() {
    printf 'release channel publication failed: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

assert_exact_cosign_version() {
    local output line
    local -a versions=()
    output="$(LC_ALL=C cosign version 2>&1)" \
        || die "could not determine the installed Cosign version"
    while IFS= read -r line; do
        if [[ "${line}" =~ ^[[:space:]]*GitVersion:[[:space:]]+(v[^[:space:]]+)[[:space:]]*$ ]]; then
            versions+=("${BASH_REMATCH[1]}")
        fi
    done <<< "${output}"
    [[ "${#versions[@]}" -eq 1 && "${versions[0]}" == "v${COSIGN_VERSION}" ]] \
        || die "Cosign must be exactly v${COSIGN_VERSION}"
}

for name in GITHUB_REPOSITORY RELEASE_TAG RELEASE_COMMIT RELEASE_CHECKSUMS GH_TOKEN; do
    [[ -n "${!name:-}" ]] || die "required environment variable is empty: ${name}"
done
case "${RELEASE_CHANNEL_REPAIR:-}" in
    "")
        readonly REPAIR_MODE=0
        ;;
    "1")
        readonly REPAIR_MODE=1
        ;;
    *)
        die "RELEASE_CHANNEL_REPAIR must be unset or exactly 1"
        ;;
esac
[[ "${RELEASE_TAG}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "RELEASE_TAG must be canonical X.Y.Z"
[[ "${RELEASE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "RELEASE_COMMIT must be a lowercase 40-character Git object ID"
[[ -f "${RELEASE_CHECKSUMS}" && ! -L "${RELEASE_CHECKSUMS}" ]] \
    || die "RELEASE_CHECKSUMS must be a regular file"

require_command cosign
require_command cmp
require_command gh
require_command python3
require_command sleep
require_command tr
require_command wc
assert_exact_cosign_version

readonly SIGNING_IDENTITY="${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main"

# A normal release has the currently authenticated channel as its monotonic
# anchor. Explicit repair may instead encounter an invalid or absent tip, so it
# must first prove the requested target is the globally newest immutable stable
# release. That external anchor makes recovery safe without force-updating the
# branch or trusting unauthenticated tip contents.
require_latest_repair_target() {
    python3 "${ROOT}/scripts/release_api_retry.py" require-latest-immutable \
        --repository "${GITHUB_REPOSITORY}" \
        --tag "${RELEASE_TAG}" \
        --commit "${RELEASE_COMMIT}" \
        || die "repair target is not the latest immutable stable release"
}
if (( REPAIR_MODE == 1 )); then
    require_latest_repair_target
fi

gh_api_read() {
    local output="$1"
    shift
    local attempt
    for ((attempt = 1; attempt <= GH_READ_ATTEMPTS; attempt++)); do
        if gh api --method GET "$@" > "${output}"; then
            return 0
        fi
        if (( attempt < GH_READ_ATTEMPTS )); then
            sleep "${GH_READ_RETRY_DELAYS[attempt - 1]}"
        fi
    done
    die "GitHub API read failed after ${GH_READ_ATTEMPTS} attempts: output=${output} request=$*"
}

gh_api_create_object() {
    local output="$1" label="$2"
    shift 2
    local attempt
    for ((attempt = 1; attempt <= GH_WRITE_ATTEMPTS; attempt++)); do
        # Git blobs and trees are content-addressed. Commit retries can leave
        # an unreachable duplicate object when GitHub accepted a request but
        # the client lost its response; none of these calls mutate a ref.
        if gh api --method POST "$@" > "${output}"; then
            return 0
        fi
        if (( attempt < GH_WRITE_ATTEMPTS )); then
            sleep "${GH_WRITE_RETRY_DELAYS[attempt - 1]}"
        fi
    done
    die "GitHub ${label} creation failed after ${GH_WRITE_ATTEMPTS} attempts"
}

WORKDIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/defenseclaw-release-channel.XXXXXX")"
readonly WORKDIR
cleanup() {
    local status=$?
    rm -rf -- "${WORKDIR}"
    return "${status}"
}
trap cleanup EXIT

candidate="${WORKDIR}/${CHANNEL_MANIFEST}"
python3 "${ROOT}/scripts/release_channel.py" create \
    --repository "${GITHUB_REPOSITORY}" \
    --version "${RELEASE_TAG}" \
    --commit "${RELEASE_COMMIT}" \
    --checksums "${RELEASE_CHECKSUMS}" \
    --output "${candidate}"

cosign sign-blob \
    --yes \
    --bundle="${candidate}.bundle" \
    --output-certificate="${candidate}.pem" \
    --output-signature="${candidate}.sig" \
    "${candidate}"

channel_file_max_bytes() {
    case "$1" in
        stable.txt)
            printf '%s\n' "${CHANNEL_MANIFEST_MAX_BYTES}"
            ;;
        stable.txt.sig)
            printf '%s\n' "${CHANNEL_SIGNATURE_MAX_BYTES}"
            ;;
        stable.txt.pem)
            printf '%s\n' "${CHANNEL_CERTIFICATE_MAX_BYTES}"
            ;;
        stable.txt.bundle)
            printf '%s\n' "${CHANNEL_BUNDLE_MAX_BYTES}"
            ;;
        *)
            die "unsupported channel file: $1"
            ;;
    esac
}

validate_local_channel_file() {
    local name="$1" path="${WORKDIR}/$1" maximum size
    maximum="$(channel_file_max_bytes "${name}")"
    [[ -f "${path}" && ! -L "${path}" ]] \
        || die "candidate channel file is not a regular nonsymlink: ${name}"
    size="$(wc -c < "${path}" | tr -d '[:space:]')"
    [[ "${size}" =~ ^[0-9]+$ && "${size}" -gt 0 && "${size}" -le "${maximum}" ]] \
        || die "candidate channel file has invalid size: ${name}"
}

validate_channel_candidate() {
    local name
    for name in "${CHANNEL_FILES[@]}"; do
        validate_local_channel_file "${name}"
    done
}

# Validate signer outputs before feeding them to any parser or verifier.
validate_channel_candidate
python3 "${ROOT}/scripts/release_candidate.py" canonicalize-certificate \
    --certificate "${candidate}.pem"
# Canonicalization changes the certificate bytes; re-establish every bound.
validate_channel_candidate
python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
    --certificate "${candidate}.pem" \
    --signature "${candidate}.sig" \
    --certificate-identity "${SIGNING_IDENTITY}" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${candidate}"
cosign verify-blob \
    --bundle "${candidate}.bundle" \
    --certificate-identity "${SIGNING_IDENTITY}" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${candidate}" >/dev/null
# No repository ref is read or changed until the exact candidate files have
# passed type, symlink, nonempty, and per-file size validation.
validate_channel_candidate

channel_ref_sha_from_response() {
    local response="$1"
    python3 - "${response}" "${CHANNEL_REF}" <<'PY'
import json
import re
import sys
from pathlib import Path

path, expected_ref = sys.argv[1:]
document = json.loads(Path(path).read_text(encoding="utf-8"))
if not isinstance(document, list):
    raise SystemExit("matching-refs response is not a list")
matches = [row for row in document if isinstance(row, dict) and row.get("ref") == expected_ref]
if len(matches) > 1:
    raise SystemExit("release channel ref is ambiguous")
if not matches:
    print("")
    raise SystemExit(0)
obj = matches[0].get("object")
sha = obj.get("sha") if isinstance(obj, dict) else None
if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
    raise SystemExit("release channel ref lacks a canonical commit ID")
print(sha)
PY
}

read_channel_ref_sha() {
    local output="$1"
    gh_api_read \
        "${output}" \
        "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CHANNEL_BRANCH}"
    channel_ref_sha_from_response "${output}"
}

refs_json="${WORKDIR}/refs.json"
current_sha="$(read_channel_ref_sha "${refs_json}")"

download_channel_file() {
    local commit="$1" name="$2" destination="$3" maximum="$4"
    local response="${WORKDIR}/content-${name//[^A-Za-z0-9]/_}.json"
    gh_api_read \
        "${response}" \
        "repos/${GITHUB_REPOSITORY}/contents/${name}" \
        -f "ref=${commit}"
    python3 - "${response}" "${name}" "${destination}" \
        "${maximum}" <<'PY'
import base64
import binascii
import json
import os
import sys
from pathlib import Path

response_path, expected_name, output_path, max_bytes_text = sys.argv[1:]
document = json.loads(Path(response_path).read_text(encoding="utf-8"))
if not isinstance(document, dict):
    raise SystemExit("channel content response is not an object")
if document.get("type") != "file":
    raise SystemExit(f"published channel object is not a file: {expected_name}")
if document.get("name") != expected_name or document.get("path") != expected_name:
    raise SystemExit(f"published channel path mismatch: {expected_name}")
if document.get("encoding") != "base64" or not isinstance(document.get("content"), str):
    raise SystemExit(f"published channel encoding mismatch: {expected_name}")
encoded = document["content"]
if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n" for character in encoded):
    raise SystemExit(f"published channel base64 contains invalid characters: {expected_name}")
try:
    payload = base64.b64decode(encoded.replace("\r", "").replace("\n", ""), validate=True)
except (ValueError, binascii.Error) as exc:
    raise SystemExit(f"published channel base64 is invalid: {expected_name}") from exc
size = document.get("size")
if type(size) is not int or size != len(payload):
    raise SystemExit(f"published channel size mismatch: {expected_name}")
if not payload or len(payload) > int(max_bytes_text):
    raise SystemExit(f"published channel file has invalid size: {expected_name}")
descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SystemExit(f"published channel write stalled: {expected_name}")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

if [[ -n "${current_sha}" ]]; then
    current_dir="${WORKDIR}/current"
    mkdir -m 700 "${current_dir}"
    current_validation_log="${WORKDIR}/current-validation.log"
    if (
        set -e
        for name in "${CHANNEL_FILES[@]}"; do
            download_channel_file \
                "${current_sha}" \
                "${name}" \
                "${current_dir}/${name}" \
                "$(channel_file_max_bytes "${name}")" \
                || exit $?
        done
        python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
            --certificate "${current_dir}/${CHANNEL_MANIFEST}.pem" \
            --signature "${current_dir}/${CHANNEL_MANIFEST}.sig" \
            --certificate-identity "${SIGNING_IDENTITY}" \
            --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
            "${current_dir}/${CHANNEL_MANIFEST}" \
            || exit $?
        cosign verify-blob \
            --bundle "${current_dir}/${CHANNEL_MANIFEST}.bundle" \
            --certificate-identity "${SIGNING_IDENTITY}" \
            --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
            "${current_dir}/${CHANNEL_MANIFEST}" >/dev/null \
            || exit $?
        python3 "${ROOT}/scripts/release_channel.py" validate \
            --repository "${GITHUB_REPOSITORY}" \
            "${current_dir}/${CHANNEL_MANIFEST}"
    ) >"${current_validation_log}" 2>&1; then
        comparison="$(
            python3 "${ROOT}/scripts/release_channel.py" compare \
                --current "${current_dir}/${CHANNEL_MANIFEST}" \
                --candidate "${candidate}"
        )"
        if [[ "${comparison}" == "same" ]]; then
            printf 'Stable release channel already points to authenticated %s\n' \
                "${RELEASE_TAG}"
            exit 0
        fi
        [[ "${comparison}" == "advance" ]] \
            || die "unexpected channel comparison result: ${comparison}"
    elif (( REPAIR_MODE == 1 )); then
        printf '%s\n' \
            "::warning title=Repairing invalid stable channel::The current tip did not authenticate. The latest immutable release proof authorizes a fast-forward repair child." >&2
    else
        cat "${current_validation_log}" >&2
        die "current stable channel tip did not authenticate"
    fi
fi

blob_shas=()
for name in "${CHANNEL_FILES[@]}"; do
    validate_local_channel_file "${name}"
    request="${WORKDIR}/blob-request-${name//[^A-Za-z0-9]/_}.json"
    python3 - "${WORKDIR}/${name}" "${request}" <<'PY'
import base64
import json
import sys
from pathlib import Path

source, output = map(Path, sys.argv[1:])
document = {
    "content": base64.b64encode(source.read_bytes()).decode("ascii"),
    "encoding": "base64",
}
output.write_text(
    json.dumps(document, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
    response="${WORKDIR}/blob-${name//[^A-Za-z0-9]/_}.json"
    gh_api_create_object \
        "${response}" \
        "channel blob ${name}" \
        "repos/${GITHUB_REPOSITORY}/git/blobs" \
        --input "${request}"
    blob_shas+=("$(
        python3 - "${response}" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sha = document.get("sha") if isinstance(document, dict) else None
if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
    raise SystemExit("created channel blob lacks a canonical Git object ID")
print(sha)
PY
    )")
done

tree_request="${WORKDIR}/tree-request.json"
tree_name_sha_pairs=()
for ((index = 0; index < ${#CHANNEL_FILES[@]}; index++)); do
    tree_name_sha_pairs+=("${CHANNEL_FILES[index]}" "${blob_shas[index]}")
done
python3 - "${tree_request}" "${tree_name_sha_pairs[@]}" <<'PY'
import json
import re
import sys
from pathlib import Path

output = Path(sys.argv[1])
arguments = sys.argv[2:]
if not arguments or len(arguments) % 2:
    raise SystemExit("channel tree input must contain name/SHA pairs")
pairs = list(zip(arguments[0::2], arguments[1::2], strict=True))
if len({name for name, _sha in pairs}) != len(pairs):
    raise SystemExit("channel tree input repeats a file name")
if any(re.fullmatch(r"[0-9a-f]{40}", sha) is None for _name, sha in pairs):
    raise SystemExit("channel tree input contains an invalid blob SHA")
document = {
    "tree": [
        {"path": name, "mode": "100644", "type": "blob", "sha": sha}
        for name, sha in pairs
    ]
}
output.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
PY
tree_response="${WORKDIR}/tree-response.json"
gh_api_create_object \
    "${tree_response}" \
    "channel tree" \
    "repos/${GITHUB_REPOSITORY}/git/trees" \
    --input "${tree_request}"
tree_sha="$(
    python3 - "${tree_response}" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sha = document.get("sha") if isinstance(document, dict) else None
if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
    raise SystemExit("created channel tree lacks a canonical Git object ID")
print(sha)
PY
)"

commit_request="${WORKDIR}/commit-request.json"
python3 - "${commit_request}" "${tree_sha}" "${current_sha}" "${RELEASE_TAG}" <<'PY'
import json
import sys
from pathlib import Path

output, tree, parent, version = sys.argv[1:]
document = {
    "message": f"release-channel: stable -> {version}",
    "tree": tree,
    "parents": [parent] if parent else [],
}
Path(output).write_text(
    json.dumps(document, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
commit_response="${WORKDIR}/commit-response.json"
gh_api_create_object \
    "${commit_response}" \
    "channel commit" \
    "repos/${GITHUB_REPOSITORY}/git/commits" \
    --input "${commit_request}"
published_commit="$(
    python3 - "${commit_response}" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
sha = document.get("sha") if isinstance(document, dict) else None
if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
    raise SystemExit("created channel commit lacks a canonical Git object ID")
print(sha)
PY
)"

publish_channel_ref() {
    local expected_parent="$1" target_commit="$2"
    local attempt observed write_status
    local observation="${WORKDIR}/ref-write-observation.json"
    for ((attempt = 1; attempt <= GH_WRITE_ATTEMPTS; attempt++)); do
        # Close the release-list race at every repair mutation attempt. Object
        # creation above is unreachable and has not changed public state.
        if (( REPAIR_MODE == 1 )); then
            require_latest_repair_target
        fi

        write_status=0
        if [[ -n "${expected_parent}" ]]; then
            gh api --method PATCH \
                "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CHANNEL_BRANCH}" \
                -f "sha=${target_commit}" \
                -F force=false >/dev/null \
                || write_status=$?
        else
            gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
                -f "ref=${CHANNEL_REF}" \
                -f "sha=${target_commit}" >/dev/null \
                || write_status=$?
        fi

        # A failed client may have lost a successful response. Accept only the
        # intended new ref, retry only while the ref remains at the exact
        # observed parent (or absent for creation), and reject every third state.
        observed="$(read_channel_ref_sha "${observation}")"
        if [[ "${observed}" == "${target_commit}" ]]; then
            return 0
        fi
        if [[ "${observed}" != "${expected_parent}" ]]; then
            die "release channel ref changed concurrently from ${expected_parent:-<absent>} to ${observed:-<absent>}"
        fi
        if (( attempt < GH_WRITE_ATTEMPTS )); then
            sleep "${GH_WRITE_RETRY_DELAYS[attempt - 1]}"
        fi
    done
    die "release channel ref did not reach ${target_commit} after ${GH_WRITE_ATTEMPTS} attempts (last write exit ${write_status})"
}

publish_channel_ref "${current_sha}" "${published_commit}"

published_refs="${WORKDIR}/published-refs.json"
published_sha="$(read_channel_ref_sha "${published_refs}")"
[[ "${published_sha}" == "${published_commit}" ]] \
    || die "published release channel ref does not point to the new commit"

published_dir="${WORKDIR}/published"
mkdir -m 700 "${published_dir}"
for name in "${CHANNEL_FILES[@]}"; do
    download_channel_file \
        "${published_commit}" \
        "${name}" \
        "${published_dir}/${name}" \
        "$(channel_file_max_bytes "${name}")"
done
cmp -s "${candidate}" "${published_dir}/${CHANNEL_MANIFEST}" \
    || die "published channel manifest differs from the signed candidate"
python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
    --certificate "${published_dir}/${CHANNEL_MANIFEST}.pem" \
    --signature "${published_dir}/${CHANNEL_MANIFEST}.sig" \
    --certificate-identity "${SIGNING_IDENTITY}" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${published_dir}/${CHANNEL_MANIFEST}"
cosign verify-blob \
    --bundle "${published_dir}/${CHANNEL_MANIFEST}.bundle" \
    --certificate-identity "${SIGNING_IDENTITY}" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${published_dir}/${CHANNEL_MANIFEST}" >/dev/null
python3 "${ROOT}/scripts/release_channel.py" validate \
    --repository "${GITHUB_REPOSITORY}" \
    --version "${RELEASE_TAG}" \
    "${published_dir}/${CHANNEL_MANIFEST}"

printf 'Stable release channel advanced to authenticated %s at %s\n' \
    "${RELEASE_TAG}" "${published_commit}"
