#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# packaging/windows/standalone/build-scanner-runtime.sh -- build the Python
# scanner runtime that cmd/defenseclaw-scanners embeds for the standalone
# Windows enterprise payload:
#
#   python/                       CPython 3.13.15 embeddable x64 (pinned) and
#                                 the app-local VC++ runtime closure
#   python/Lib/site-packages/     the locked dependency tree from uv.lock
#                                 (skill-scanner, mcp-scanner, LiteLLM, ...),
#                                 the YARA-X compatibility adapter, the
#                                 win-unicode-console source and this
#                                 checkout's DefenseClaw wheel (plugin scanner)
#
# These are the inputs and pins of the per-user Windows installer
# (scripts/build-windows-installer.ps1), so a managed host scans with the same
# scanner versions a per-user host does. Runs on Linux or macOS: uv installs
# the Windows wheels for the target platform without running them.
#
# Usage: build-scanner-runtime.sh --out-dir <dir>
#   writes <dir>/runtime.zip and <dir>/runtime.json
set -euo pipefail

die() { printf 'build-scanner-runtime: %s\n' "$*" >&2; exit 1; }

OUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir) OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "${OUT_DIR}" ] || die "--out-dir is required"
command -v uv >/dev/null || die "uv is required"
command -v python3 >/dev/null || die "python3 is required"

PYTHON_VERSION=3.13.15
PYTHON_TARGET=3.13
PYTHON_EMBED="python-${PYTHON_VERSION}-embed-amd64.zip"
PYTHON_EMBED_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PYTHON_EMBED}"
PYTHON_EMBED_SHA256=d1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf
VC_SOURCE=Microsoft.VC.14.42.17.12.CRT.Redist.X64.base.vsix
VC_SOURCE_URL=https://download.visualstudio.microsoft.com/download/pr/53b2bf3d-716a-455a-bcc0-39cfb7447fe0/49d70db282f1c74d456206501120134f021c2bc3aaabb41577fe18dea35d1454/Microsoft.VC.14.42.17.12.CRT.Redist.X64.base.vsix
VC_SOURCE_SHA256=49d70db282f1c74d456206501120134f021c2bc3aaabb41577fe18dea35d1454
VC_RETAIL_PREFIX=Contents/VC/Redist/MSVC/14.42.34433/x64/Microsoft.VC143.CRT/
WIN_UNICODE=win_unicode_console-0.5.zip
WIN_UNICODE_URL=https://files.pythonhosted.org/packages/89/8d/7aad74930380c8972ab282304a2ff45f3d4927108bb6693cabcc9fc6a099/win_unicode_console-0.5.zip
WIN_UNICODE_SHA256=d4142d4d56d46f449d6f00536a73625a871cba040f0bc1a2e305a04578f07d1e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CACHE="${DEFENSECLAW_BUILD_CACHE:-${HOME}/.cache/defenseclaw-windows-runtime}"
mkdir -p "${CACHE}" "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dc-scanner-runtime.XXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT

fetch() { # fetch <name> <url> <sha256>
    local path="${CACHE}/$1"
    if [ ! -s "${path}" ]; then
        curl -fsSL --retry 3 -o "${path}.part" "$2"
        mv "${path}.part" "${path}"
    fi
    echo "$3  ${path}" | sha256sum -c --quiet - || die "pinned download $1 does not match its SHA-256"
    printf '%s' "${path}"
}

EMBED_ZIP="$(fetch "${PYTHON_EMBED}" "${PYTHON_EMBED_URL}" "${PYTHON_EMBED_SHA256}")"
VC_ZIP="$(fetch "${VC_SOURCE}" "${VC_SOURCE_URL}" "${VC_SOURCE_SHA256}")"
WU_ZIP="$(fetch "${WIN_UNICODE}" "${WIN_UNICODE_URL}" "${WIN_UNICODE_SHA256}")"

RT="${WORK}/runtime"
PY="${RT}/python"
SITE="${PY}/Lib/site-packages"
mkdir -p "${SITE}"
echo "==> CPython ${PYTHON_VERSION} embeddable x64"
python3 -I - "${EMBED_ZIP}" "${PY}" "${VC_ZIP}" "${VC_RETAIL_PREFIX}" <<'PYCODE'
import hashlib, pathlib, sys, zipfile
embed, dest, vc, prefix = sys.argv[1:5]
dest = pathlib.Path(dest)
with zipfile.ZipFile(embed) as z:
    for info in z.infolist():
        name = info.filename
        if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts or "\\" in name:
            sys.exit(f"unsafe member in the CPython archive: {name}")
        if not name.endswith("/"):
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))
# The app-local VC++ closure the per-user installer ships (pinned per file).
closure = {
    "msvcp140.dll": "b99eb28a471311113f5c4109cb3c463f39cfd9bdb3b07f706204dedddb4516a1",
    "msvcp140_1.dll": "576d2ab235e32acc129eda78a3b9a3d3e78b0c97a01940d962cb8502acd030d1",
}
with zipfile.ZipFile(vc) as z:
    for name, want in closure.items():
        data = z.read(prefix + name)
        if hashlib.sha256(data).hexdigest() != want:
            sys.exit(f"pinned VC++ runtime file {name} drifted")
        (dest / name).write_bytes(data)
pth = sorted(dest.glob("python*._pth"))
if len(pth) != 1:
    sys.exit("the CPython runtime has no single ._pth file")
stdlib = pth[0].stem + ".zip"
pth[0].write_bytes(f"{stdlib}\r\n.\r\nLib\\site-packages\r\nimport site\r\n".encode("ascii"))
PYCODE

echo "==> locked site-packages (uv.lock, windows cp313)"
( cd "${REPO_ROOT}" && uv export --frozen --no-dev --no-emit-project --no-header \
    --no-emit-package win-unicode-console --no-emit-package yara-python \
    --format requirements.txt --output-file "${WORK}/requirements.txt" >/dev/null )
uv pip sync --quiet --target "${SITE}" --python-version "${PYTHON_TARGET}" --python-platform windows \
    --only-binary :all: --require-hashes "${WORK}/requirements.txt"

echo "==> YARA-X compatibility adapter"
SOURCE_DATE_EPOCH="$(git -C "${REPO_ROOT}" log -1 --format=%ct)" \
    uv build --quiet --wheel "${REPO_ROOT}/packages/yara-python-compat" --out-dir "${WORK}/yara-compat"
YARA_WHEEL="$(ls "${WORK}"/yara-compat/yara_python-*-py3-none-any.whl)"
uv pip install --quiet --target "${SITE}" --python-version "${PYTHON_TARGET}" --python-platform windows \
    --only-binary :all: --no-deps "${YARA_WHEEL}"

echo "==> win-unicode-console (pinned source, copied without running setup.py)"
python3 -I - "${WU_ZIP}" "${SITE}" <<'PYCODE'
import pathlib, sys, zipfile
src, site = sys.argv[1], pathlib.Path(sys.argv[2])
root = "win_unicode_console-0.5/"
with zipfile.ZipFile(src) as z:
    for info in z.infolist():
        name = info.filename
        if not name.startswith(root) or name.endswith("/"):
            continue
        rel = pathlib.PurePosixPath(name[len(root):])
        if ".." in rel.parts or not rel.parts or rel.parts[0] not in ("win_unicode_console", "win_unicode_console.egg-info"):
            continue
        target = site / pathlib.Path(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(z.read(info))
PYCODE

echo "==> DefenseClaw wheel (plugin scanner, MCP scan) from this checkout"
make -C "${REPO_ROOT}" --no-print-directory dist-cli DIST_DIR="${WORK}/dist" >/dev/null
DC_WHEEL="$(ls "${WORK}"/dist/defenseclaw-*-py3-none-any.whl)"
uv pip install --quiet --target "${SITE}" --python-version "${PYTHON_TARGET}" --python-platform windows \
    --only-binary :all: --no-deps "${DC_WHEEL}"

echo "==> runtime.zip"
python3 -I - "${RT}" "${OUT_DIR}" "${PYTHON_VERSION}" <<'PYCODE'
import hashlib, json, pathlib, re, shutil, sys, zipfile
rt, out, pyver = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
site = rt / "python" / "Lib" / "site-packages"
# uv --target writes POSIX console scripts the Windows runtime cannot run,
# and bytecode caches carry host paths: neither is shipped.
shutil.rmtree(site / "bin", ignore_errors=True)
for cache in sorted(rt.rglob("__pycache__"), reverse=True):
    shutil.rmtree(cache, ignore_errors=True)
versions = {"python": pyver}
for key, dist in (("skill-scanner", "cisco_ai_skill_scanner"), ("mcp-scanner", "cisco_ai_mcp_scanner"),
                  ("litellm", "litellm"), ("defenseclaw", "defenseclaw"), ("yara-python", "yara_python")):
    found = sorted(site.glob(f"{dist}-*.dist-info"))
    if len(found) != 1:
        sys.exit(f"expected one {dist} distribution in the runtime, found {len(found)}")
    versions[key] = re.match(rf"{dist}-(.+)\.dist-info$", found[0].name).group(1)
archive = out / "runtime.zip"
files = sorted(p for p in rt.rglob("*") if p.is_file())
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for path in files:
        info = zipfile.ZipInfo(path.relative_to(rt).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        z.writestr(info, path.read_bytes(), compresslevel=6)
sha = hashlib.sha256(archive.read_bytes()).hexdigest()
(out / "runtime.json").write_text(json.dumps({"schema_version": 1, "runtime_sha256": sha, "versions": versions}, indent=2) + "\n")
print(f"    {len(files)} files, {archive.stat().st_size // (1 << 20)} MiB, sha256 {sha[:16]}")
print("    " + ", ".join(f"{k} {v}" for k, v in versions.items()))
PYCODE
