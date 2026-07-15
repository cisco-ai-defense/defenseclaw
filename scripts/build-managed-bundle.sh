#!/usr/bin/env bash
#
# build-managed-bundle.sh
#
# Wrapper around `make packaging-macos-bundle` for the Cisco-managed
# release. Fetches the private cloudreg overlay + CMID module from
# github.com/cisco-aispg/ai-common (default: latest `develop`), computes
# the Go pseudo-version for the exact ref you're building against, and
# invokes the make target with CMID_OVERLAY + CMID_VERSION set.
#
# Prereqs (fail-fast checked before we start):
#   - macOS host with Xcode CLT (for `lipo`).
#   - go >= the version pinned in defenseclaw/go.mod.
#   - GOPRIVATE=github.com/cisco-aispg/* (or equivalent) so `go get`
#     can resolve the pinned pseudo-version at build time.
#   - Read access to git@github.com-aispg:cisco-aispg/ai-common.git
#     (SSH host alias) OR https://github.com/cisco-aispg/ai-common.git
#     with a token in $HOME/.netrc / GH_TOKEN.
#
# Usage:
#   scripts/build-managed-bundle.sh                       # develop HEAD
#   scripts/build-managed-bundle.sh --ref v1.2.3          # a tag
#   scripts/build-managed-bundle.sh --ref abcd1234        # a commit sha
#   scripts/build-managed-bundle.sh --ai-common-dir /path # skip clone; reuse an existing checkout
#   scripts/build-managed-bundle.sh --keep                # keep the ai-common checkout after the build
#
# Environment overrides (all optional, forwarded to make):
#   BUNDLE_GOARCH    (default: universal)  — see Makefile
#   BUNDLE_GOOS      (default: darwin)     — see Makefile
#   BUNDLE_TAGS      (default: cmid)       — see Makefile
#   VERSION          (default: `git describe` on the defenseclaw repo)
#   GOPRIVATE        (default: github.com/cisco-aispg/*)
#   AI_COMMON_REPO_SSH   (default: git@github.com-aispg:cisco-aispg/ai-common.git)
#   AI_COMMON_REPO_HTTPS (default: https://github.com/cisco-aispg/ai-common.git)
#                        Falls back to HTTPS if the SSH clone fails.

set -euo pipefail

# ---- args ---------------------------------------------------------------

REF="develop"
AI_COMMON_DIR=""
KEEP="false"

usage() {
  sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref)             REF="${2:?}"; shift 2;;
    --ai-common-dir)   AI_COMMON_DIR="${2:?}"; shift 2;;
    --keep)            KEEP="true"; shift;;
    -h|--help)         usage 0;;
    *) echo "unknown flag: $1" >&2; usage 64;;
  esac
done

# ---- location bookkeeping ----------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AI_COMMON_REPO_SSH="${AI_COMMON_REPO_SSH:-git@github.com-aispg:cisco-aispg/ai-common.git}"
AI_COMMON_REPO_HTTPS="${AI_COMMON_REPO_HTTPS:-https://github.com/cisco-aispg/ai-common.git}"

: "${GOPRIVATE:=github.com/cisco-aispg/*}"
export GOPRIVATE

# ---- prereq checks ------------------------------------------------------

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "build-managed-bundle: missing required tool: $1" >&2
    exit 1
  }
}

require_bin git
require_bin go
require_bin lipo   # macOS-only; the make target refuses to lipo elsewhere

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build-managed-bundle: this target is macOS-only (need lipo)" >&2
  exit 1
fi

# ---- ai-common checkout -------------------------------------------------

# clone_ai_common URL -> checks out ${REF} (branch, tag, OR commit sha)
# into ${AI_COMMON_DIR}. `git clone --branch` only accepts branch/tag
# refs, so --ref <commit-sha> failed before checkout; instead we clone
# without --branch and explicitly fetch + detach-checkout the ref, which
# GitHub serves for reachable commit shas as well as named refs.
clone_ai_common() {
  local url="$1"
  # Start from a clean empty dir so a retry after a partial clone
  # doesn't trip git's "destination path exists and is not empty".
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
    echo "build-managed-bundle: --ai-common-dir must point at a git checkout: ${AI_COMMON_DIR}" >&2
    exit 1
  fi
  echo "==> using existing ai-common checkout at ${AI_COMMON_DIR}"
  ( cd "${AI_COMMON_DIR}" && git fetch --quiet origin "${REF}" && git checkout --quiet "${REF}" )
fi

cleanup() {
  if [[ "${CLEANUP_AI_COMMON}" == "true" ]] && [[ "${KEEP}" != "true" ]] && [[ -d "${AI_COMMON_DIR}" ]]; then
    echo "==> removing temporary ai-common checkout"
    rm -rf "${AI_COMMON_DIR}"
  elif [[ "${KEEP}" == "true" ]]; then
    echo "==> keeping ai-common checkout at ${AI_COMMON_DIR}"
  fi
}
trap cleanup EXIT

# ---- validate overlay ---------------------------------------------------

OVERLAY_PATH="${AI_COMMON_DIR}/defenseclaw_cmid_overlay/provider_cisco.go"
if [[ ! -f "${OVERLAY_PATH}" ]]; then
  echo "build-managed-bundle: overlay file not found in ai-common@${REF}:" >&2
  echo "    ${OVERLAY_PATH}" >&2
  echo "    (has the cmid PR been merged into ${REF}?)" >&2
  exit 1
fi

if [[ ! -f "${AI_COMMON_DIR}/cmid/go.mod" ]]; then
  echo "build-managed-bundle: cmid module not found in ai-common@${REF}:" >&2
  echo "    ${AI_COMMON_DIR}/cmid/go.mod" >&2
  exit 1
fi

# ---- compute Go pseudo-version -----------------------------------------
#
# Go's pseudo-version format for a nested module (module path
# github.com/cisco-aispg/ai-common/cmid) uses the commit timestamp and
# short sha of the LATEST commit that touched the module subdir. We
# mirror `go list -m -json` behavior with plain git so the script has
# zero net dependencies on a resolvable proxy.

echo "==> computing pseudo-version for ai-common/cmid @ ${REF}"
# Use the checked-out commit (HEAD) rather than `git log -- cmid/`: the
# clone is shallow (--depth 50), so a path-filtered log returns empty
# whenever cmid/ hasn't changed within the retained history — and even
# when it resolves, it picks an ancestor of the requested ref instead of
# the ref itself. HEAD is exactly the ref the operator asked to build.
COMMIT_SHA="$(git -C "${AI_COMMON_DIR}" rev-parse HEAD)"
if [[ -z "${COMMIT_SHA}" ]]; then
  echo "build-managed-bundle: could not resolve HEAD commit sha on ${REF}" >&2
  exit 1
fi
COMMIT_SHORT="${COMMIT_SHA:0:12}"
# UTC timestamp of that commit in Go's pseudo-version format YYYYMMDDhhmmss.
COMMIT_TS="$(TZ=UTC git -C "${AI_COMMON_DIR}" show -s --format=%cd \
  --date=format-local:'%Y%m%d%H%M%S' "${COMMIT_SHA}")"
CMID_VERSION="v0.0.0-${COMMIT_TS}-${COMMIT_SHORT}"

echo "    cmid commit: ${COMMIT_SHA}"
echo "    pseudo-ver:  ${CMID_VERSION}"

# ---- drive the make target ---------------------------------------------

BUNDLE_GOARCH="${BUNDLE_GOARCH:-universal}"
BUNDLE_GOOS="${BUNDLE_GOOS:-darwin}"
BUNDLE_TAGS="${BUNDLE_TAGS:-cmid}"

echo "==> building managed bundle"
echo "    CMID_OVERLAY=${OVERLAY_PATH}"
echo "    CMID_VERSION=${CMID_VERSION}"
echo "    BUNDLE_GOARCH=${BUNDLE_GOARCH}"
echo "    BUNDLE_GOOS=${BUNDLE_GOOS}"
echo "    BUNDLE_TAGS=${BUNDLE_TAGS}"

MAKE_ARGS=(
  packaging-macos-bundle
  BUNDLE_GOARCH="${BUNDLE_GOARCH}"
  BUNDLE_GOOS="${BUNDLE_GOOS}"
  BUNDLE_TAGS="${BUNDLE_TAGS}"
  CMID_OVERLAY="${OVERLAY_PATH}"
  CMID_VERSION="${CMID_VERSION}"
)
if [[ -n "${VERSION:-}" ]]; then
  MAKE_ARGS+=(VERSION="${VERSION}")
fi

make -C "${REPO_ROOT}" "${MAKE_ARGS[@]}"

echo ""
echo "==> bundle build complete"
