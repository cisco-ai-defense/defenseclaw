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
readonly CHANNEL_MAX_PUBLISHED_BYTES=1048576
readonly SIGNING_IDENTITY_PREFIX="https://github.com"
readonly SIGNING_OIDC_ISSUER="https://token.actions.githubusercontent.com"
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

for name in GITHUB_REPOSITORY RELEASE_TAG RELEASE_COMMIT RELEASE_CHECKSUMS GH_TOKEN; do
    [[ -n "${!name:-}" ]] || die "required environment variable is empty: ${name}"
done
[[ "${RELEASE_TAG}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
    || die "RELEASE_TAG must be canonical X.Y.Z"
[[ "${RELEASE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "RELEASE_COMMIT must be a lowercase 40-character Git object ID"
[[ -f "${RELEASE_CHECKSUMS}" && ! -L "${RELEASE_CHECKSUMS}" ]] \
    || die "RELEASE_CHECKSUMS must be a regular file"

require_command base64
require_command cosign
require_command gh
require_command python3

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
python3 "${ROOT}/scripts/release_candidate.py" canonicalize-certificate \
    --certificate "${candidate}.pem"
python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
    --certificate "${candidate}.pem" \
    --signature "${candidate}.sig" \
    --certificate-identity \
      "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${candidate}"
cosign verify-blob \
    --bundle "${candidate}.bundle" \
    --certificate-identity \
      "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${candidate}" >/dev/null

refs_json="${WORKDIR}/refs.json"
gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CHANNEL_BRANCH}" \
    > "${refs_json}"
current_sha="$(
    python3 - "${refs_json}" "${CHANNEL_REF}" <<'PY'
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
)"

download_channel_file() {
    local commit="$1" name="$2" destination="$3"
    local response="${WORKDIR}/content-${name//[^A-Za-z0-9]/_}.json"
    gh api --method GET \
        "repos/${GITHUB_REPOSITORY}/contents/${name}" \
        -f "ref=${commit}" > "${response}"
    python3 - "${response}" "${name}" "${destination}" \
        "${CHANNEL_MAX_PUBLISHED_BYTES}" <<'PY'
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
    for name in "${CHANNEL_FILES[@]}"; do
        download_channel_file "${current_sha}" "${name}" "${current_dir}/${name}"
    done
    python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
        --certificate "${current_dir}/${CHANNEL_MANIFEST}.pem" \
        --signature "${current_dir}/${CHANNEL_MANIFEST}.sig" \
        --certificate-identity \
          "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
        --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
        "${current_dir}/${CHANNEL_MANIFEST}"
    cosign verify-blob \
        --bundle "${current_dir}/${CHANNEL_MANIFEST}.bundle" \
        --certificate-identity \
          "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
        --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
        "${current_dir}/${CHANNEL_MANIFEST}" >/dev/null
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
fi

declare -A blob_sha=()
for name in "${CHANNEL_FILES[@]}"; do
    payload="$(base64 < "${WORKDIR}/${name}" | tr -d '\n')"
    response="${WORKDIR}/blob-${name//[^A-Za-z0-9]/_}.json"
    gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" \
        -f "content=${payload}" \
        -f "encoding=base64" > "${response}"
    blob_sha["${name}"]="$(
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
    )"
done

tree_request="${WORKDIR}/tree-request.json"
python3 - "${tree_request}" \
    "${blob_sha[stable.txt]}" \
    "${blob_sha[stable.txt.sig]}" \
    "${blob_sha[stable.txt.pem]}" \
    "${blob_sha[stable.txt.bundle]}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
names = ("stable.txt", "stable.txt.sig", "stable.txt.pem", "stable.txt.bundle")
shas = sys.argv[2:]
document = {
    "tree": [
        {"path": name, "mode": "100644", "type": "blob", "sha": sha}
        for name, sha in zip(names, shas, strict=True)
    ]
}
output.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
PY
tree_response="${WORKDIR}/tree-response.json"
gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" \
    --input "${tree_request}" > "${tree_response}"
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
gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" \
    --input "${commit_request}" > "${commit_response}"
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

if [[ -n "${current_sha}" ]]; then
    gh api --method PATCH \
        "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CHANNEL_BRANCH}" \
        -f "sha=${published_commit}" \
        -F force=false >/dev/null
else
    gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
        -f "ref=${CHANNEL_REF}" \
        -f "sha=${published_commit}" >/dev/null
fi

published_refs="${WORKDIR}/published-refs.json"
gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CHANNEL_BRANCH}" \
    > "${published_refs}"
python3 - "${published_refs}" "${CHANNEL_REF}" "${published_commit}" <<'PY'
import json
import sys
from pathlib import Path

path, expected_ref, expected_commit = sys.argv[1:]
document = json.loads(Path(path).read_text(encoding="utf-8"))
if not isinstance(document, list):
    raise SystemExit("published matching-refs response is not a list")
matches = [row for row in document if isinstance(row, dict) and row.get("ref") == expected_ref]
if len(matches) != 1:
    raise SystemExit("published release channel ref is absent or ambiguous")
obj = matches[0].get("object")
actual_commit = obj.get("sha") if isinstance(obj, dict) else None
if actual_commit != expected_commit:
    raise SystemExit("published release channel ref does not point to the new commit")
PY

published_dir="${WORKDIR}/published"
mkdir -m 700 "${published_dir}"
for name in "${CHANNEL_FILES[@]}"; do
    download_channel_file "${published_commit}" "${name}" "${published_dir}/${name}"
done
cmp -s "${candidate}" "${published_dir}/${CHANNEL_MANIFEST}" \
    || die "published channel manifest differs from the signed candidate"
python3 "${ROOT}/scripts/verify-sigstore-blob.py" \
    --certificate "${published_dir}/${CHANNEL_MANIFEST}.pem" \
    --signature "${published_dir}/${CHANNEL_MANIFEST}.sig" \
    --certificate-identity \
      "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${published_dir}/${CHANNEL_MANIFEST}"
cosign verify-blob \
    --bundle "${published_dir}/${CHANNEL_MANIFEST}.bundle" \
    --certificate-identity \
      "${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main" \
    --certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}" \
    "${published_dir}/${CHANNEL_MANIFEST}" >/dev/null
python3 "${ROOT}/scripts/release_channel.py" validate \
    --repository "${GITHUB_REPOSITORY}" \
    --version "${RELEASE_TAG}" \
    "${published_dir}/${CHANNEL_MANIFEST}"

printf 'Stable release channel advanced to authenticated %s at %s\n' \
    "${RELEASE_TAG}" "${published_commit}"
