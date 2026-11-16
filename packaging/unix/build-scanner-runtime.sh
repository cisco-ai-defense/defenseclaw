#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# packaging/unix/build-scanner-runtime.sh -- build the Python scanner runtime
# the managed-enterprise Linux and macOS packages install at
# <install root>/scanner-runtime (/opt/defenseclaw/scanner-runtime on Linux,
# /opt/cisco/defenseclaw/scanner-runtime on macOS), as the standalone Windows
# payload ships one (packaging/windows/standalone/build-scanner-runtime.sh):
#
#   python/                          CPython 3.13 (python-build-standalone,
#                                    pinned per target), no symlinks
#   python/lib/python3.13/site-packages/
#                                    the locked dependency tree from uv.lock
#                                    (skill-scanner, mcp-scanner, LiteLLM,
#                                    yara-python, ...) and this checkout's
#                                    DefenseClaw wheel (plugin scanner, MCP
#                                    scan), byte-compiled for the read-only
#                                    install
#   runtime.json                     schema 1: versions of the pinned parts
#
# defenseclaw-scanners (cmd/defenseclaw-scanners, built per target by
# GoReleaser into the package's bin folder) runs the scanners from this tree.
# The package manager installs the tree root-owned, so no prepare step
# unpacks it on the host. The pins are those of the per-user install (the
# same uv.lock), so a managed host scans with the scanner versions a
# per-user host does. Runs on Linux or macOS: uv installs the wheels of the
# target platform without running them.
#
# Usage: build-scanner-runtime.sh --target linux-amd64|linux-arm64|darwin-arm64 --out-dir <dir>
#   writes <dir>/python/... and <dir>/runtime.json (an existing <dir> is replaced)
set -euo pipefail

die() { printf 'build-scanner-runtime: %s\n' "$*" >&2; exit 1; }

TARGET=""
OUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="${2:?--target needs a value}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "${TARGET}" ] || die "--target is required"
[ -n "${OUT_DIR}" ] || die "--out-dir is required"
command -v uv >/dev/null || die "uv is required"
command -v curl >/dev/null || die "curl is required"

# python-build-standalone 20261003, CPython 3.13.16 install_only_stripped
# (SHA-256 from the release's SHA256SUMS).
PBS_RELEASE=20261003
PYTHON_VERSION=3.13.16
PYTHON_MINOR=3.13
case "${TARGET}" in
    linux-amd64)
        PBS_TRIPLE=x86_64-unknown-linux-gnu
        PBS_SHA256=4595c5589fff7bf0cb158d9a88a797e0d791fa33830770fcb7bf3f4b104feeae
        UV_PLATFORM=x86_64-manylinux_2_28 ;;
    linux-arm64)
        PBS_TRIPLE=aarch64-unknown-linux-gnu
        PBS_SHA256=6e9641400f8debd9b7924b27b5ff0662c372852382e291a76c450c7b67414cf6
        UV_PLATFORM=aarch64-manylinux_2_28 ;;
    darwin-arm64)
        # onnxruntime (skill-scanner) ships macOS 14 wheels only.
        export MACOSX_DEPLOYMENT_TARGET=14.0
        PBS_TRIPLE=aarch64-apple-darwin
        PBS_SHA256=9e01f63bbb08576cd9c8bc2d0564d098cb30c8453a0cd4bcf6aef458f6d2a147
        UV_PLATFORM=aarch64-apple-darwin ;;
    *) die "unknown target ${TARGET} (linux-amd64, linux-arm64 or darwin-arm64)" ;;
esac
case "${TARGET}" in
    darwin-*) INSTALL_ROOT=/opt/cisco/defenseclaw/scanner-runtime ;;
    *) INSTALL_ROOT=/opt/defenseclaw/scanner-runtime ;;
esac
PBS_NAME="cpython-${PYTHON_VERSION}+${PBS_RELEASE}-${PBS_TRIPLE}-install_only_stripped.tar.gz"
PBS_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/${PBS_NAME//+/%2B}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${XDG_CACHE_HOME:-${HOME}/.cache}/defenseclaw-unix-runtime"
mkdir -p "${CACHE}" "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dc-unix-scanner-runtime.XXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT

sha256_of() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

PBS_TAR="${CACHE}/${PBS_NAME}"
if [ ! -s "${PBS_TAR}" ]; then
    curl -fsSL --retry 3 -o "${PBS_TAR}.part" "${PBS_URL}"
    mv "${PBS_TAR}.part" "${PBS_TAR}"
fi
[ "$(sha256_of "${PBS_TAR}")" = "${PBS_SHA256}" ] || die "pinned download ${PBS_NAME} does not match its SHA-256"

RT="${WORK}/runtime"
mkdir -p "${RT}"
echo "==> CPython ${PYTHON_VERSION} (${PBS_TRIPLE})"
tar -xzf "${PBS_TAR}" -C "${RT}"
[ -d "${RT}/python/lib/python${PYTHON_MINOR}" ] || die "the CPython archive has no python/lib/python${PYTHON_MINOR}"
SITE="${RT}/python/lib/python${PYTHON_MINOR}/site-packages"
mkdir -p "${SITE}"

echo "==> locked site-packages (uv.lock, ${UV_PLATFORM} cp313)"
( cd "${REPO_ROOT}" && uv export --frozen --no-dev --no-emit-project --no-header \
    --format requirements.txt --output-file "${WORK}/requirements.txt" >/dev/null )
uv pip sync --quiet --target "${SITE}" --python-version "${PYTHON_MINOR}" --python-platform "${UV_PLATFORM}" \
    --only-binary :all: --require-hashes "${WORK}/requirements.txt"

echo "==> DefenseClaw wheel (plugin scanner, MCP scan) from this checkout"
make -C "${REPO_ROOT}" --no-print-directory dist-cli DIST_DIR="${WORK}/dist" >/dev/null
DC_WHEEL="$(ls "${WORK}"/dist/defenseclaw-*-py3-none-any.whl)"
uv pip install --quiet --target "${SITE}" --python-version "${PYTHON_MINOR}" --python-platform "${UV_PLATFORM}" \
    --only-binary :all: --no-deps "${DC_WHEEL}"

echo "==> runtime tree"
# A compiler for the bytecode: any CPython of the same minor version writes
# the same .pyc files, so the build host's own runs for every target.
HOST_PY="$(uv python find --no-project "${PYTHON_MINOR}" 2>/dev/null || true)"
if [ -z "${HOST_PY}" ]; then
    uv python install --quiet "${PYTHON_MINOR}"
    HOST_PY="$(uv python find --no-project "${PYTHON_MINOR}")"
fi
"${HOST_PY}" -I - "${RT}" "${OUT_DIR}" "${PYTHON_VERSION}" "${INSTALL_ROOT}" "${PYTHON_MINOR}" <<'PYCODE'
import compileall, json, pathlib, py_compile, re, shutil, stat, sys

rt, out, pyver, install_root, minor = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
py = rt / "python"
site = py / "lib" / f"python{minor}" / "site-packages"
# uv --target writes console scripts whose first line names the build
# host's interpreter: the scanners run as modules, so none is shipped.
shutil.rmtree(site / "bin", ignore_errors=True)
# Caches that carry build-host paths, and parts of CPython no scanner uses.
for cache in sorted(py.rglob("__pycache__"), reverse=True):
    shutil.rmtree(cache, ignore_errors=True)
for unused in ("idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "test"):
    shutil.rmtree(py / "lib" / f"python{minor}" / unused, ignore_errors=True)
for pattern in ("include", "share", "lib/pkgconfig", "lib/tcl*", "lib/tk*", "lib/itcl*", "lib/thread*", "lib/libtcl*",
                "lib/libtk*", f"lib/python{minor}/config-*", f"lib/python{minor}/lib-dynload/_tkinter*"):
    for path in py.glob(pattern):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
# Only the interpreter is run: the other programs CPython ships (pip, idle,
# pydoc, python3 and python links) are not installed.
interpreter = py / "bin" / f"python{minor}"
for path in (py / "bin").iterdir():
    if path != interpreter:
        path.unlink() if path.is_symlink() or not path.is_dir() else shutil.rmtree(path)
if interpreter.is_symlink():
    sys.exit(f"{interpreter} is a link")
# The package installs plain files only: the trust check refuses a link in
# the tree (one could point outside it). The interpreter's own library keeps
# the name it is loaded by as a copy; every other link is dropped.
keep_links = {f"libpython{minor}.so.1.0", f"libpython{minor}.dylib"}
for path in sorted(py.rglob("*"), key=lambda p: len(p.parts), reverse=True):
    if path.is_symlink() and path.name not in keep_links:
        path.unlink()
    elif path.is_symlink():
        target = path.resolve()
        if not target.is_relative_to(py):
            sys.exit(f"{path} links outside the runtime")
        path.unlink()
        if target.is_dir():
            shutil.copytree(target, path, symlinks=False)
        else:
            shutil.copy2(target, path)
# Byte-compile for the install path: the gateway runs the tree read-only
# (python -B), so no .pyc is written there at scan time. unchecked-hash keeps
# the files reproducible (no source mtimes) and lets the read-only import use
# them without re-reading the source.
ok = compileall.compile_dir(
    str(py / "lib"), quiet=2, workers=1, stripdir=str(rt), prependdir=install_root,
    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
)
if not ok:
    print("    (some files did not compile; they are imported from source)")
# Modes the package installs: folders and programs 0755, every other file
# 0644; nothing group- or other-writable.
for path in [py, *py.rglob("*")]:
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        path.chmod(0o755)
    elif stat.S_ISREG(mode):
        path.chmod(0o755 if mode & 0o111 else 0o644)
    else:
        sys.exit(f"{path} is not a file or folder")
versions = {"python": pyver}
for key, dist in (("skill-scanner", "cisco_ai_skill_scanner"), ("mcp-scanner", "cisco_ai_mcp_scanner"),
                  ("litellm", "litellm"), ("defenseclaw", "defenseclaw"), ("yara-python", "yara_python")):
    found = sorted(site.glob(f"{dist}-*.dist-info"))
    if len(found) != 1:
        sys.exit(f"expected one {dist} distribution in the runtime, found {len(found)}")
    versions[key] = re.match(rf"{dist}-(.+)\.dist-info$", found[0].name).group(1)
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True)
shutil.move(str(py), str(out / "python"))
files = sum(1 for p in (out / "python").rglob("*") if p.is_file())
manifest = {"schema_version": 1, "python": f"python/bin/python{minor}", "versions": versions, "files": files}
(out / "runtime.json").write_text(json.dumps(manifest, indent=2) + "\n")
(out / "runtime.json").chmod(0o644)
out.chmod(0o755)
print(f"    {files} files")
print("    " + ", ".join(f"{k} {v}" for k, v in versions.items()))
PYCODE

# On a build host of the target platform, the tree must import the scanners
# read-only, as the gateway runs it.
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) HOST_TARGET=linux-amd64 ;;
    Linux-aarch64) HOST_TARGET=linux-arm64 ;;
    Darwin-arm64) HOST_TARGET=darwin-arm64 ;;
    *) HOST_TARGET="" ;;
esac
if [ "${HOST_TARGET}" = "${TARGET}" ]; then
    echo "==> import check"
    "${OUT_DIR}/python/bin/python${PYTHON_MINOR}" -I -B -c \
        'import skill_scanner, mcpscanner, litellm, yara, defenseclaw.scanner.plugin_scanner, defenseclaw.scanner.mcp; print("    imports ok")'
fi
