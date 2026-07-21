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

# Three-way merge a stable standalone macOS release into the checked-in app.
# The old upstream commit is the merge base, the current monorepo app is
# "ours" (Cisco integration), and the requested upstream tag is "theirs".

set -euo pipefail

if [[ $# -gt 1 ]]; then
    echo "usage: $0 [STABLE_TAG]" >&2
    exit 64
fi

for command in git gh python3 rsync; do
    command -v "${command}" >/dev/null || { echo "required command not found: ${command}" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="${ROOT}/macos/DefenseClawMac"
LOCK="${APP_ROOT}/upstream.lock.toml"

lock_value() {
    python3 - "${LOCK}" "$1" <<'PY'
import sys
import tomllib
from pathlib import Path

lock = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(lock[sys.argv[2]])
PY
}
REPOSITORY="$(lock_value repository)"
OLD_TAG="$(lock_value tag)"
OLD_COMMIT="$(lock_value commit)"
TAG="${1:-$(python3 "${ROOT}/scripts/check-macos-upstream.py" --lock "${LOCK}" --print-latest-tag)}"

if [[ -z "${TAG}" ]]; then
    echo "could not resolve a stable upstream release tag" >&2
    exit 1
fi
if [[ -n "$(git -C "${ROOT}" status --porcelain -- macos/DefenseClawMac)" ]]; then
    echo "macos/DefenseClawMac has uncommitted changes; commit or stash them before updating" >&2
    exit 1
fi

SYNC="${ROOT}/build/macos-upstream-sync-${TAG//\//-}"
rm -rf "${SYNC}"
mkdir -p "$(dirname "${SYNC}")"
git clone --quiet "https://github.com/${REPOSITORY}.git" "${SYNC}"
NEW_COMMIT="$(git -C "${SYNC}" rev-parse "${TAG}^{commit}")"
[[ "${NEW_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || { echo "tag ${TAG} did not resolve to a commit" >&2; exit 1; }

if [[ "${TAG}" == "${OLD_TAG}" && "${NEW_COMMIT}" == "${OLD_COMMIT}" ]]; then
    echo "macOS app is already pinned to ${TAG}@${NEW_COMMIT:0:12}"
    rm -rf "${SYNC}"
    exit 0
fi
git -C "${SYNC}" cat-file -e "${OLD_COMMIT}^{commit}" || {
    echo "locked base commit ${OLD_COMMIT} is not present in ${REPOSITORY}" >&2
    exit 1
}

git -C "${SYNC}" checkout --quiet --detach "${OLD_COMMIT}"
git -C "${SYNC}" switch --quiet -c cisco-import-overlay
git -C "${SYNC}" config user.name "DefenseClaw macOS updater"
git -C "${SYNC}" config user.email "defenseclaw@cisco.com"

copy_path() {
    local source="$1"
    local destination="$2"
    if [[ -d "${source}" ]]; then
        mkdir -p "${destination}"
        rsync -a --delete "${source}/" "${destination}/"
    elif [[ -f "${source}" ]]; then
        mkdir -p "$(dirname "${destination}")"
        cp "${source}" "${destination}"
    else
        rm -rf "${destination}"
    fi
}

maintained_paths=(
    DefenseClawMac.xcodeproj
    DefenseClawMac
    Tests
    script/build_and_run.sh
    script/test_cli_cancellation.sh
    script/test_connector_onboarding.sh
    script/test_structured_detail_parser.sh
    tools
    images
    .gitignore
)
for path in "${maintained_paths[@]}"; do
    copy_path "${APP_ROOT}/${path}" "${SYNC}/${path}"
done

git -C "${SYNC}" add --all -- "${maintained_paths[@]}"
git -C "${SYNC}" commit --quiet --allow-empty -m "Apply Cisco monorepo integration overlay"
if ! git -C "${SYNC}" merge --no-edit "${NEW_COMMIT}"; then
    echo "upstream merge has conflicts; resolve them in ${SYNC}, then copy the maintained paths back" >&2
    echo "the working repository was not modified" >&2
    exit 1
fi

for path in "${maintained_paths[@]}"; do
    copy_path "${SYNC}/${path}" "${APP_ROOT}/${path}"
done

TITLE="$(git -C "${SYNC}" log -1 --format=%s "${NEW_COMMIT}")"
IMPORTED_AT="$(date -u +%Y-%m-%d)"
SOURCE_VERSION="${TAG#v}"
python3 - "${LOCK}" "${APP_ROOT}/UPSTREAM.md" "${TAG}" "${NEW_COMMIT}" "${SOURCE_VERSION}" "${IMPORTED_AT}" "${TITLE}" <<'PY'
import re
import sys
from pathlib import Path

lock_path, provenance_path, tag, commit, version, imported_at, title = sys.argv[1:]
lock = Path(lock_path).read_text(encoding="utf-8")
replacements = {
    "tag": tag,
    "commit": commit,
    "source_version": version,
    "imported_at": imported_at,
}
for key, value in replacements.items():
    lock, count = re.subn(
        rf'(?m)^{key} = ".*"$',
        lambda _match, key=key, value=value: f'{key} = "{value}"',
        lock,
    )
    if count != 1:
        raise SystemExit(f"expected exactly one {key} field in {lock_path}")
Path(lock_path).write_text(lock, encoding="utf-8")

provenance = Path(provenance_path).read_text(encoding="utf-8")
provenance_fields = [
    (r"(?m)^- Stable release: `[^`]+`$", f"- Stable release: `{tag}`", "stable release"),
    (r"(?m)^- Commit: `[^`]+`$", f"- Commit: `{commit}`", "commit"),
    (r"(?m)^- Commit title: `[^`]+`$", f"- Commit title: `{title}`", "commit title"),
    (r"(?m)^- Imported: .+$", f"- Imported: {imported_at}", "import date"),
]
for pattern, replacement, label in provenance_fields:
    provenance, count = re.subn(pattern, lambda _match, replacement=replacement: replacement, provenance)
    if count != 1:
        raise SystemExit(f"expected exactly one {label} field in {provenance_path}")
Path(provenance_path).write_text(provenance, encoding="utf-8")
PY

rm -rf "${SYNC}"
python3 "${ROOT}/scripts/macos_license_headers.py" --fix
python3 "${ROOT}/scripts/macos_license_headers.py"
python3 "${ROOT}/scripts/check-macos-upstream.py" --offline
make -C "${ROOT}" check-version-sync
make -C "${ROOT}" macos-app-test

echo "Imported ${REPOSITORY} ${TAG}@${NEW_COMMIT:0:12}. Review the full git diff before committing."
