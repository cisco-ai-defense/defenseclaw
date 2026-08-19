#!/usr/bin/env bash
#
# build-managed-windows-bundle.sh
#
# Cross-build the managed-enterprise Windows gateway zip on macOS (or any
# host with a Go toolchain), so a Windows tester can consume the zip via the
# separate scripts/build-windows-enterprise-installer.ps1 builder without
# needing SSH access to the private cisco-aispg/ai-common repo.
#
# The output is the goreleaser-shaped defenseclaw_${VERSION}_windows_amd64.zip
# (plus a small gateway-source-commit.txt sidecar so the Windows box can
# check out the same defenseclaw commit before driving the installer, so
# the manifest / provenance source_commit matches).
#
# What the script does:
#   1. Clone github.com/cisco-aispg/ai-common at ${REF} (SSH first, HTTPS
#      fallback), or reuse an existing checkout via --ai-common-dir.
#   2. Compute the Go pseudo-version for that ref (v0.0.0-<UTCstamp>-<sha>).
#   3. Snapshot internal/managed/cloudreg/provider_cisco.go + go.mod + go.sum,
#      apply the private overlay over the OSS stub, run `go get` to pin the
#      cmid pseudo-version.
#   4. Cross-build defenseclaw.exe and defenseclaw-hook.exe with
#      GOOS=windows GOARCH=amd64 -tags cmid.
#   5. Stamp VERSIONINFO / icon on both PE binaries via
#      `go run ./internal/tools/windowsresources -target windows_amd64 ...`
#      (the Go tool is cross-platform; Windows verifies via the Win32
#      VersionInfo API when the enterprise installer builder consumes the zip).
#   6. Package the two exe's plus LICENSE / README / CHANGELOG / packaging/**
#      into ${DIST_DIR}/defenseclaw_${VERSION}_windows_amd64.zip using the
#      same shape .goreleaser.yaml would produce for windows-amd64.
#   7. Restore the snapshot in an EXIT trap whether the build succeeded or
#      failed, so the OSS working tree stays untouched.
#
# What this script deliberately does NOT do:
#   - It does not run the Windows installer flow. Hand the produced zip and
#     the companion gateway-source-commit.txt to a Windows box; the tester
#     runs `.\scripts\build-windows-enterprise-installer.ps1 -DistRoot
#     <where the zip lives> -Version <version>`.
#   - It does not sign anything. Authenticode is the Windows box's job.
#   - It does not touch the pre-staged wheel or upgrade-manifest under
#     ${DIST_DIR}; only the gateway zip is (re)written.
#
# Args:
#   --ref <git-ref>       ai-common ref to build against (default: develop)
#   --ai-common-dir <p>   reuse an existing ai-common checkout; skip clone
#   --keep                keep the temporary ai-common checkout after build
#   --version <v>         defenseclaw release version (required)
#   --dist-dir <p>        output directory for the gateway zip (default: dist)
#   -h|--help             show this header and exit
#
# Environment overrides (all optional):
#   GOPRIVATE               default: github.com/cisco-aispg/*
#   AI_COMMON_REPO_SSH      default: git@github.com-aispg:cisco-aispg/ai-common.git
#   AI_COMMON_REPO_HTTPS    default: https://github.com/cisco-aispg/ai-common.git

set -euo pipefail

REF="develop"
AI_COMMON_DIR=""
KEEP="false"
VERSION=""
DIST_DIR="dist"

usage() {
  # The header comment block ends at line 54. A wider range would leak the
  # shell code that follows into --help output.
  sed -n '2,54p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref)             REF="${2:?}"; shift 2;;
    --ai-common-dir)   AI_COMMON_DIR="${2:?}"; shift 2;;
    --keep)            KEEP="true"; shift;;
    --version)         VERSION="${2:?}"; shift 2;;
    --dist-dir)        DIST_DIR="${2:?}"; shift 2;;
    -h|--help)         usage 0;;
    *) echo "unknown flag: $1" >&2; usage 64;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "build-managed-windows-bundle: --version is required" >&2
  exit 64
fi
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9_.-]+)?$ ]]; then
  echo "build-managed-windows-bundle: invalid version: ${VERSION}" >&2
  exit 64
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Derive the defenseclaw source commit up front. The enterprise Setup builder
# re-derives the same HEAD via Get-GitSourceCommit and then refuses any binary
# whose reported main.commit does not match a 40-char lowercase git OID, so
# both halves have to read the same HEAD. Without stamping -X main.commit here
# the binaries would carry the "unknown" default that main.go initializes,
# which the installer's identity gate would reject on every managed build.
SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --verify HEAD | tr '[:upper:]' '[:lower:]')"
if [[ ! "${SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "build-managed-windows-bundle: could not resolve defenseclaw HEAD as a 40-char lowercase git OID: ${SOURCE_COMMIT}" >&2
  exit 1
fi

AI_COMMON_REPO_SSH="${AI_COMMON_REPO_SSH:-git@github.com-aispg:cisco-aispg/ai-common.git}"
AI_COMMON_REPO_HTTPS="${AI_COMMON_REPO_HTTPS:-https://github.com/cisco-aispg/ai-common.git}"

: "${GOPRIVATE:=github.com/cisco-aispg/*}"
export GOPRIVATE

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "build-managed-windows-bundle: missing required tool: $1" >&2
    exit 1
  }
}

require_bin git
require_bin go
# Fail-fast on a missing `zip` before we clone the private repo, overlay
# the tree, run `go get`, or cross-build. Otherwise the operator would
# only discover the missing binary after minutes of work.
require_bin zip

# ---- ai-common checkout ------------------------------------------------

clone_ai_common() {
  local url="$1"
  rm -rf "${AI_COMMON_DIR}"
  mkdir -p "${AI_COMMON_DIR}"
  git clone --quiet --depth 50 --no-checkout "${url}" "${AI_COMMON_DIR}" || return 1
  git -C "${AI_COMMON_DIR}" fetch --quiet --depth 50 origin "${REF}" || return 1
  git -C "${AI_COMMON_DIR}" checkout --quiet --detach FETCH_HEAD || return 1
}

CLEANUP_AI_COMMON="false"
if [[ -z "${AI_COMMON_DIR}" ]]; then
  AI_COMMON_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ai-common-cmid.XXXXXX")"
  CLEANUP_AI_COMMON="true"
  echo "==> cloning cisco-aispg/ai-common (${REF}) into ${AI_COMMON_DIR}"
  if ! clone_ai_common "${AI_COMMON_REPO_SSH}" 2>/dev/null; then
    echo "    ssh clone failed, falling back to https"
    clone_ai_common "${AI_COMMON_REPO_HTTPS}"
  fi
else
  if [[ ! -d "${AI_COMMON_DIR}/.git" ]]; then
    echo "build-managed-windows-bundle: --ai-common-dir must point at a git checkout: ${AI_COMMON_DIR}" >&2
    exit 1
  fi
  echo "==> using existing ai-common checkout at ${AI_COMMON_DIR}"
  if [[ "${REF}" == "HEAD" ]]; then
    # CI checks the private repository out with a narrowly scoped token and
    # persist-credentials=false. Consume those exact reviewed bytes without a
    # second authenticated fetch or leaving credentials available to the
    # DefenseClaw build process.
    ( cd "${AI_COMMON_DIR}" && git checkout --quiet --detach HEAD )
  else
    ( cd "${AI_COMMON_DIR}" && git fetch --quiet origin "${REF}" && git checkout --quiet --detach FETCH_HEAD )
  fi
fi

# ---- validate overlay --------------------------------------------------

OVERLAY_PATH="${AI_COMMON_DIR}/defenseclaw_cmid_overlay/provider_cisco.go"
if [[ ! -f "${OVERLAY_PATH}" ]]; then
  echo "build-managed-windows-bundle: overlay file not found in ai-common@${REF}:" >&2
  echo "    ${OVERLAY_PATH}" >&2
  exit 1
fi
if [[ ! -f "${AI_COMMON_DIR}/cmid/go.mod" ]]; then
  echo "build-managed-windows-bundle: cmid module not found in ai-common@${REF}:" >&2
  echo "    ${AI_COMMON_DIR}/cmid/go.mod" >&2
  exit 1
fi

# ---- compute Go pseudo-version -----------------------------------------

echo "==> computing pseudo-version for ai-common/cmid @ ${REF}"
COMMIT_SHA="$(git -C "${AI_COMMON_DIR}" rev-parse HEAD)"
COMMIT_SHORT="${COMMIT_SHA:0:12}"
COMMIT_TS="$(TZ=UTC git -C "${AI_COMMON_DIR}" show -s --format=%cd \
  --date=format-local:'%Y%m%d%H%M%S' "${COMMIT_SHA}")"
CMID_VERSION="v0.0.0-${COMMIT_TS}-${COMMIT_SHORT}"
echo "    cmid commit: ${COMMIT_SHA}"
echo "    pseudo-ver:  ${CMID_VERSION}"

# ---- snapshot the OSS files we're about to mutate ---------------------

CLOUDREG_TARGET="${REPO_ROOT}/internal/managed/cloudreg/provider_cisco.go"
OVERLAY_APPLIED=0
OVERLAY_SNAPSHOT_DIR=""

restore_overlay() {
  if [[ "${OVERLAY_APPLIED}" -eq 1 ]] && [[ -n "${OVERLAY_SNAPSHOT_DIR}" ]] && [[ -d "${OVERLAY_SNAPSHOT_DIR}" ]]; then
    echo "==> restoring cloudreg stub + go.mod/go.sum from snapshot"
    cp "${OVERLAY_SNAPSHOT_DIR}/provider_cisco.go" "${CLOUDREG_TARGET}"
    cp "${OVERLAY_SNAPSHOT_DIR}/go.mod"           "${REPO_ROOT}/go.mod"
    cp "${OVERLAY_SNAPSHOT_DIR}/go.sum"           "${REPO_ROOT}/go.sum"
    OVERLAY_APPLIED=0
  fi
  if [[ -n "${OVERLAY_SNAPSHOT_DIR}" ]] && [[ -d "${OVERLAY_SNAPSHOT_DIR}" ]]; then
    rm -rf "${OVERLAY_SNAPSHOT_DIR}"
  fi
  if [[ "${CLEANUP_AI_COMMON}" == "true" ]] && [[ "${KEEP}" != "true" ]] && [[ -d "${AI_COMMON_DIR}" ]]; then
    echo "==> removing temporary ai-common checkout"
    rm -rf "${AI_COMMON_DIR}"
  elif [[ "${KEEP}" == "true" ]]; then
    echo "==> keeping ai-common checkout at ${AI_COMMON_DIR}"
  fi
}
trap restore_overlay EXIT

OVERLAY_SNAPSHOT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dc-cmid-overlay.XXXXXX")"
echo "==> snapshotting cloudreg stub + go.mod/go.sum to ${OVERLAY_SNAPSHOT_DIR}"
cp "${CLOUDREG_TARGET}"     "${OVERLAY_SNAPSHOT_DIR}/provider_cisco.go"
cp "${REPO_ROOT}/go.mod"    "${OVERLAY_SNAPSHOT_DIR}/go.mod"
cp "${REPO_ROOT}/go.sum"    "${OVERLAY_SNAPSHOT_DIR}/go.sum"
# Flip OVERLAY_APPLIED BEFORE the swap so a mid-write failure past this
# point still triggers a restore from the snapshot.
OVERLAY_APPLIED=1
echo "==> applying cloudreg overlay: ${OVERLAY_PATH}"
cp "${OVERLAY_PATH}" "${CLOUDREG_TARGET}"

echo "==> pinning managed cloud auth module @${CMID_VERSION}"
( cd "${REPO_ROOT}" && go get "github.com/cisco-aispg/ai-common/cmid@${CMID_VERSION}" )

# ---- cross-build gateway + hook with -tags cmid -----------------------

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dc-managed-windows-stage.XXXXXX")"
trap 'restore_overlay; rm -rf "${STAGE_DIR}"' EXIT

GATEWAY_EXE="${STAGE_DIR}/defenseclaw.exe"
HOOK_EXE="${STAGE_DIR}/defenseclaw-hook.exe"
# main.commit defaults to "unknown", which the enterprise Setup builder's
# Assert-DefenseClawBinaryIdentity rejects. Stamp the exact HEAD sha we
# derived above so identity verification passes.
LDFLAGS_GATEWAY="-s -w -buildid=defenseclaw-${VERSION}-windows-amd64 -X main.version=${VERSION} -X main.commit=${SOURCE_COMMIT}"
LDFLAGS_HOOK="-s -w -buildid=defenseclaw-hook-${VERSION}-windows-amd64 -H=windowsgui -X main.version=${VERSION} -X main.commit=${SOURCE_COMMIT}"
ICON_PATH="${REPO_ROOT}/macos/DefenseClawMac/DefenseClawMac/Assets.xcassets/AppIcon.appiconset/icon_256.png"

echo "==> building defenseclaw.exe (windows/amd64 tags=cmid)"
( cd "${REPO_ROOT}" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -tags cmid \
    -ldflags "${LDFLAGS_GATEWAY}" -o "${GATEWAY_EXE}" ./cmd/defenseclaw )

echo "==> stamping defenseclaw.exe VERSIONINFO / icon"
( cd "${REPO_ROOT}" && go run ./internal/tools/windowsresources \
    -target windows_amd64 -executable "${GATEWAY_EXE}" \
    -component gateway -version "${VERSION}" -icon "${ICON_PATH}" )

echo "==> building defenseclaw-hook.exe (windows/amd64 tags=cmid)"
( cd "${REPO_ROOT}" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -tags cmid \
    -ldflags "${LDFLAGS_HOOK}" -o "${HOOK_EXE}" ./cmd/defenseclaw-hook )

echo "==> stamping defenseclaw-hook.exe VERSIONINFO / icon"
( cd "${REPO_ROOT}" && go run ./internal/tools/windowsresources \
    -target windows_amd64 -executable "${HOOK_EXE}" \
    -component hook -version "${VERSION}" -icon "${ICON_PATH}" )

# ---- assemble the goreleaser-shaped archive ---------------------------

echo "==> assembling gateway archive contents"
for shipped in LICENSE README.md CHANGELOG.md; do
  if [[ -f "${REPO_ROOT}/${shipped}" ]]; then
    cp "${REPO_ROOT}/${shipped}" "${STAGE_DIR}/${shipped}"
  fi
done
cp -R "${REPO_ROOT}/packaging" "${STAGE_DIR}/packaging"

mkdir -p "${DIST_DIR}"
DIST_ABS="$(cd "${DIST_DIR}" && pwd)"
GATEWAY_ZIP="${DIST_ABS}/defenseclaw_${VERSION}_windows_amd64.zip"
rm -f "${GATEWAY_ZIP}"

echo "==> writing ${GATEWAY_ZIP}"
# Use zip -X to strip extra timestamps; SOURCE_DATE_EPOCH lets zip pick a
# deterministic mtime if the version is recent enough. cd + zip from the
# stage dir so entries land at the archive root, matching goreleaser.
# zip presence is fail-fast-checked next to git/go at the top of the file.
SOURCE_COMMIT_EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH="${SOURCE_COMMIT_EPOCH}"
( cd "${STAGE_DIR}" && zip -X -r -q "${GATEWAY_ZIP}" . )

# ---- write the source-commit sidecar so Windows can sync -----------------

COMMIT_FILE="${DIST_ABS}/gateway-source-commit.txt"
cat > "${COMMIT_FILE}" <<EOF
${SOURCE_COMMIT}
EOF

echo ""
echo "==> managed Windows gateway prep complete"
echo "    gateway zip:      ${GATEWAY_ZIP}"
echo "    source commit:    ${COMMIT_FILE}  (${SOURCE_COMMIT})"
echo "    pinned cmid:      ${CMID_VERSION}"
echo ""
echo "Hand ${GATEWAY_ZIP} and ${COMMIT_FILE} to the Windows tester. On the"
echo "Windows box, check the same defenseclaw commit out, drop the zip and"
echo "the pre-staged wheel + upgrade-manifest.json into one -DistRoot, then:"
echo ""
echo "  .\\scripts\\build-windows-enterprise-installer.ps1 \`"
echo "      -DistRoot <that dir> -OutRoot <output dir> \`"
echo "      -Version ${VERSION}"
echo ""
