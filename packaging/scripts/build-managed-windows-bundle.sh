#!/usr/bin/env bash
#
# build-managed-windows-bundle.sh
#
# Cross-build the managed-enterprise Windows Setup build kit on macOS/Linux
# and hand it to AVC's signing pipeline. Under the AVC-approved handoff
# (docs/WINDOWS-AVC-PACKAGING-HANDOFF.md), AVC — not DefenseClaw — signs
# both the inner payload files and the outer Setup EXE; DefenseClaw only
# emits an unsigned build kit AVC drops into its pipeline.
#
# Primary output: ${DIST_DIR}/windows-enterprise-buildkit-${VERSION}/,
# whose contents match the handoff doc byte-for-byte. See
# docs/specs/002-windows-avc-packaging/design.md for the full flow.
#
# Backward-compat: also emits the legacy goreleaser-shaped
# defenseclaw_${VERSION}_windows_amd64.zip + gateway-source-commit.txt.
# The zip is vestigial once no consumer remains and can be dropped in a
# follow-up.
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
#      (Windows verifies via the Win32 VersionInfo API at install time).
#   6. Assemble the AVC-facing kit: payload/ (5 unsigned inner files),
#      source/ (trimmed via `go list -deps`), source/vendor/
#      (`go mod vendor`), packaging/scripts/lib/ (assemble + trust
#      helpers), shipped assemble.{sh|ps1} at the kit root, and a
#      payload-metadata.json + README-AVC.md.
#   7. Also assemble the legacy goreleaser zip (backward-compat).
#   8. Restore the snapshot in an EXIT trap whether the build succeeded or
#      failed, so the OSS working tree stays untouched.
#
# What this script deliberately does NOT do:
#   - It does not sign anything. Both signing rounds (inner + outer)
#     are AVC's step 1 and step 3 per the handoff doc.
#   - It does not run under a Windows shell. The AVC-side pipeline is
#     where the Windows-capable runner is required (for signtool).
#
# Args:
#   --ref <git-ref>       ai-common ref to build against (default: develop)
#   --ai-common-dir <p>   reuse an existing ai-common checkout; skip clone
#   --keep                keep the temporary ai-common checkout after build
#   --version <v>         defenseclaw release version (required)
#   --dist-dir <p>        output directory for the gateway zip (default: dist)
#   --script-host <s>     bash|pwsh — which assemble.* to ship in the kit
#                         (spec 002 REQ-08; default: bash)
#   --allow-unsigned      developer-only mode: build kit AND run
#                         assemble.sh --allow-unsigned inline, landing a
#                         runnable but unsigned Setup EXE under
#                         dist/windows-enterprise-buildkit-<v>-unsigned/out/
#                         (spec 002 REQ-14; refuses non-disposable scopes
#                         at runtime via cmd/defenseclaw-enterprise-setup)
#   -h|--help             show this header and exit
#
# AVC-facing kit (spec 002 §2.3.A1): every invocation also emits
#     ${DIST_DIR}/windows-enterprise-buildkit-${VERSION}/
# whose contents match docs/WINDOWS-AVC-PACKAGING-HANDOFF.md. AVC signs
# the five inner files under payload/, runs the shipped
# assemble.{sh|ps1}, then signs the resulting outer Setup EXE.
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
SCRIPT_HOST="bash"
ALLOW_UNSIGNED="false"

usage() {
  # The header comment block ends where "# Args" transitions to shell
  # code below. Bump the range if the header grows.
  sed -n '2,68p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref)             REF="${2:?}"; shift 2;;
    --ai-common-dir)   AI_COMMON_DIR="${2:?}"; shift 2;;
    --keep)            KEEP="true"; shift;;
    --version)         VERSION="${2:?}"; shift 2;;
    --dist-dir)        DIST_DIR="${2:?}"; shift 2;;
    --script-host)     SCRIPT_HOST="${2:?}"; shift 2;;
    --allow-unsigned)  ALLOW_UNSIGNED="true"; shift;;
    -h|--help)         usage 0;;
    *) echo "unknown flag: $1" >&2; usage 64;;
  esac
done

if [[ "${SCRIPT_HOST}" != "bash" && "${SCRIPT_HOST}" != "pwsh" ]]; then
  echo "build-managed-windows-bundle: --script-host must be bash or pwsh (got: ${SCRIPT_HOST})" >&2
  exit 64
fi

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

# ---- assemble the AVC-facing build kit (spec 002 §2.3.A1) -------------
#
# See docs/WINDOWS-AVC-PACKAGING-HANDOFF.md for the AVC-side contract
# and docs/specs/002-windows-avc-packaging/design.md § Data flow for
# the DefenseClaw-side flow. The kit is deterministic across macOS/
# Linux hosts on the same source commit (spec 001 primitives + the
# reproducibility CI gate keep both runners in step).

mkdir -p "${DIST_DIR}"
DIST_ABS="$(cd "${DIST_DIR}" && pwd)"

# The kit dir name differs between AVC-facing builds and --allow-unsigned
# dev builds so the two artefacts can never be confused at release time.
if [[ "${ALLOW_UNSIGNED}" == "true" ]]; then
  KIT_NAME="windows-enterprise-buildkit-${VERSION}-unsigned"
else
  KIT_NAME="windows-enterprise-buildkit-${VERSION}"
fi
KIT_DIR="${DIST_ABS}/${KIT_NAME}"
rm -rf "${KIT_DIR}"
mkdir -p "${KIT_DIR}/payload" "${KIT_DIR}/source" "${KIT_DIR}/packaging/scripts/lib"

# ---- kit/payload: the five files AVC signs (or leaves unsigned in
#                   --allow-unsigned mode) ------------------------------
echo "==> staging kit payload"
# Single-source the expected filename list: EXPECTED_PAYLOAD_NAMES is
# what we tell emit-payload-metadata (--expected-filenames arg) and
# it is the same set of names we stage under payload/. Keeping the
# list in one variable prevents drift between the staged payload and
# the audit trail in payload-metadata.json (CR spec-002:PRRT_kwDORuAK-s6af8iw).
# The runtime's requiredPayloadFiles in cmd/defenseclaw-enterprise-setup/main.go
# and the assemble.{sh,ps1} EXPECTED_PAYLOAD arrays must all agree —
# scripts/check-assemble-parity.sh enforces the two assembler ends.
EXPECTED_PAYLOAD_NAMES=(
    DefenseClawEnterprise.psm1
    defenseclaw-gateway.exe
    defenseclaw-hook.exe
    defenseclaw.exe
    install-enterprise.ps1
)
# defenseclaw-gateway.exe is a byte-identical copy of defenseclaw.exe;
# they carry distinct identities in the enterprise runtime (the outer
# Setup extracts each under its own name and hash-checks separately),
# so both files must be present in the payload. The kit-staging block
# below is the one place either name is copied out — anything else
# that references the pair reaches into ${KIT_DIR}/payload/, not
# GATEWAY_EXE/HOOK_EXE.
cp "${GATEWAY_EXE}"                                      "${KIT_DIR}/payload/defenseclaw.exe"
cp "${GATEWAY_EXE}"                                      "${KIT_DIR}/payload/defenseclaw-gateway.exe"
cp "${HOOK_EXE}"                                         "${KIT_DIR}/payload/defenseclaw-hook.exe"
cp "${REPO_ROOT}/packaging/windows/DefenseClawEnterprise.psm1" \
                                                         "${KIT_DIR}/payload/DefenseClawEnterprise.psm1"
cp "${REPO_ROOT}/packaging/windows/install-enterprise.ps1" \
                                                         "${KIT_DIR}/payload/install-enterprise.ps1"

# Sanity-check: every EXPECTED_PAYLOAD_NAMES entry now exists at the
# staged path. Catches a typo in the copy block above before it
# becomes an AVC-side failure.
for _name in "${EXPECTED_PAYLOAD_NAMES[@]}"; do
    if [[ ! -f "${KIT_DIR}/payload/${_name}" ]]; then
        echo "build-managed-windows-bundle: staged payload missing ${_name} (bundler bug)" >&2
        exit 1
    fi
done

# ---- kit/source: the trimmed Go source tree AVC's `go build` needs
#                  (spec 002 REQ-04 + REQ-05 + REQ-06). We trim via
#                  `go list -deps` over the two commands AVC needs to
#                  build inside the kit: the outer Setup and the
#                  emitter that assemble.sh invokes via `go run`.
echo "==> resolving trimmed import graph (go list -deps)"
# The list must run under the OVERLAY-APPLIED tree so cmid packages
# resolve. Include both the outer Setup command AND the emitter — the
# emitter builds during assemble.sh stage 0 via `go run`, so its
# dependency closure has to ship inside the kit too.
TRIM_PKGS=$(
  cd "${REPO_ROOT}" && go list -deps \
    ./cmd/defenseclaw-enterprise-setup/... \
    ./cmd/windows-repro-manifest/... \
  | grep -E '^github\.com/defenseclaw/defenseclaw($|/)' \
  | sed 's|^github\.com/defenseclaw/defenseclaw/||;s|^github\.com/defenseclaw/defenseclaw$|.|'
)
# TRIM_PKGS is a newline-separated list of import-path suffixes rooted
# at the module root. Copy each package's directory (non-recursive so
# we don't accidentally pull in sibling packages that go list didn't
# reach). The resulting tree preserves the module layout so
# `go build -mod=vendor` inside the kit resolves without patch-ups.
echo "==> copying trimmed import graph into kit/source"
while IFS= read -r pkg; do
  [[ -z "${pkg}" ]] && continue
  if [[ "${pkg}" == "." ]]; then
    # Root-level go files (rare; safety fallback).
    dst="${KIT_DIR}/source"
    src="${REPO_ROOT}"
  else
    dst="${KIT_DIR}/source/${pkg}"
    src="${REPO_ROOT}/${pkg}"
  fi
  if [[ ! -d "${src}" ]]; then
    echo "build-managed-windows-bundle: trim missing dir: ${src}" >&2
    exit 1
  fi
  mkdir -p "${dst}"
  # -R would recurse into sibling subpackages; use find -maxdepth 1
  # to copy only the package's own files (matches go's package boundary).
  find "${src}" -mindepth 1 -maxdepth 1 -type f \
    \( -name '*.go' -o -name 'embed.*' -o -name '*.tmpl' \
       -o -name '*.json' -o -name '*.yaml' -o -name '*.txt' \
       -o -name '*.pem' -o -name '*.crt' -o -name '*.mod' \
       -o -name '*.sum' -o -name 'LICENSE*' -o -name 'NOTICE*' \) \
    -exec cp {} "${dst}/" \;
done <<<"${TRIM_PKGS}"

# The two payload embed dir + testdata dirs the compiler reads via
# //go:embed need to be present even if go list -deps didn't tag them.
# The enterprise-setup's payload/ directory ships EMPTY into the kit;
# assemble.sh populates it with signed inner files before running
# `go build`, so //go:embed picks them up. Similarly the
# windows-repro-manifest's testdata dir is empty in production.
mkdir -p "${KIT_DIR}/source/cmd/defenseclaw-enterprise-setup/payload"
touch    "${KIT_DIR}/source/cmd/defenseclaw-enterprise-setup/payload/.keep"

# ---- kit/source/vendor + go.mod/go.sum ---------------------------------
#
# `go mod vendor` writes to a `vendor/` dir under GOMOD's directory.
# We deliberately keep OSS working trees untouched (see the header
# comment "the OSS working tree stays untouched"). Before touching
# vendor:
#   - If ${REPO_ROOT}/vendor already exists, REFUSE to run so a
#     `go mod vendor` (which overwrites) followed by our `mv` (which
#     removes) does not destroy a pre-existing vendor tree the caller
#     may have staged for a different purpose.
#   - Otherwise, run go mod vendor at REPO_ROOT, mv it into the kit,
#     and rely on restore_overlay's EXIT trap to leave a clean tree.
# See CR spec-002:PRRT_kwDORuAK-s6af8io.
if [[ -d "${REPO_ROOT}/vendor" ]]; then
  echo "build-managed-windows-bundle: refusing to run — ${REPO_ROOT}/vendor already exists." >&2
  echo "  The bundler needs to run 'go mod vendor' and then move the result" >&2
  echo "  into the AVC kit. Moving an already-populated vendor tree would" >&2
  echo "  destroy work you may not have committed. Delete or move" >&2
  echo "  ${REPO_ROOT}/vendor first, then rerun." >&2
  exit 1
fi

echo "==> writing kit/source/vendor via go mod vendor"
( cd "${REPO_ROOT}" && go mod vendor -e ) || {
  echo "build-managed-windows-bundle: go mod vendor failed" >&2
  exit 1
}
# Move (not copy) the vendor tree — a 150+ MB copy inside dist/ isn't
# reversible without another mv, so bundle it once. The snapshot in
# OVERLAY_SNAPSHOT_DIR has the pre-overlay go.mod/go.sum for EXIT
# restore; because the refuse-if-exists guard above ran, moving vendor
# out never destroys OSS-side work.
rm -rf "${KIT_DIR}/source/vendor"
mv "${REPO_ROOT}/vendor" "${KIT_DIR}/source/vendor"
cp "${REPO_ROOT}/go.mod" "${KIT_DIR}/source/go.mod"
cp "${REPO_ROOT}/go.sum" "${KIT_DIR}/source/go.sum"

# ---- kit/packaging/scripts/lib: assemble + lib helpers ----------------
echo "==> copying assemble + lib helpers into kit"
LIB_SRC="${REPO_ROOT}/packaging/scripts/lib"
LIB_DST="${KIT_DIR}/packaging/scripts/lib"
# repro-flags is required regardless of script host — both variants of
# the assembler source it. Trust helpers ship as a pair (sh+ps1) so
# either shell host has what it needs.
cp "${LIB_SRC}/repro-flags.sh"                "${LIB_DST}/repro-flags.sh"
cp "${LIB_SRC}/repro-flags.ps1"               "${LIB_DST}/repro-flags.ps1"
cp "${LIB_SRC}/assert-cisco-signature.sh"     "${LIB_DST}/assert-cisco-signature.sh"
cp "${LIB_SRC}/assert-cisco-signature.ps1"    "${LIB_DST}/assert-cisco-signature.ps1"
cp "${LIB_SRC}/finalize.sh"                   "${LIB_DST}/finalize.sh"
cp "${LIB_SRC}/finalize.ps1"                  "${LIB_DST}/finalize.ps1"

# The shipped assemble.* is chosen by --script-host. Ships at the kit
# root because AVC's runbook calls it as `./assemble.sh` — no lib/
# prefix. Only one is shipped so AVC has a single verb to invoke.
if [[ "${SCRIPT_HOST}" == "pwsh" ]]; then
  cp "${LIB_SRC}/assemble.ps1" "${KIT_DIR}/assemble.ps1"
else
  cp "${LIB_SRC}/assemble.sh"  "${KIT_DIR}/assemble.sh"
  chmod +x "${KIT_DIR}/assemble.sh"
fi

# ---- kit/payload-metadata.json + README-AVC.md ------------------------
echo "==> emit-payload-metadata"
# Build a native emitter binary for THIS host, in a subshell that
# unsets GOOS/GOARCH so the binary runs locally. This mirrors the
# subshell trick in .github/workflows/windows-deterministic-build.yml.
EMITTER_TMP="$(mktemp -d "${TMPDIR:-/tmp}/dc-emitter.XXXXXX")"
trap 'restore_overlay; rm -rf "${STAGE_DIR}" "${EMITTER_TMP}"' EXIT
(
  unset GOFLAGS GOOS GOARCH GOTOOLCHAIN CGO_ENABLED || true
  cd "${REPO_ROOT}"
  go build -trimpath -buildvcs=false \
    -o "${EMITTER_TMP}/windows-repro-manifest" \
    ./cmd/windows-repro-manifest
)

# Payload-metadata is the audit trail for what AVC signs — the source
# of truth for file names AVC's pipeline expects to find under
# payload/, plus the commit + version + cmid pin binding this kit to a
# specific DefenseClaw source tree.
"${EMITTER_TMP}/windows-repro-manifest" emit-payload-metadata \
  --version "${VERSION}" \
  --source-commit "${SOURCE_COMMIT}" \
  --cmid-pseudo-version "${CMID_VERSION}" \
  --expected-filenames "$(IFS=,; echo "${EXPECTED_PAYLOAD_NAMES[*]}")" \
  --out "${KIT_DIR}/payload-metadata.json"

# ---- kit/README-AVC.md (~40-line runbook) -----------------------------
if [[ "${SCRIPT_HOST}" == "pwsh" ]]; then
  ASSEMBLE_INVOCATION='pwsh -File assemble.ps1 -SourceCommit <sha> -Version '"${VERSION}"' -CmidPseudoVersion '"${CMID_VERSION}"
  FINALIZE_INVOCATION='pwsh -File packaging/scripts/lib/finalize.ps1 -SetupExe <path> -Provenance <path>'
else
  ASSEMBLE_INVOCATION="./assemble.sh --source-commit <sha> --version ${VERSION} --cmid-pseudo-version ${CMID_VERSION}"
  FINALIZE_INVOCATION='./packaging/scripts/lib/finalize.sh --setup-exe <path> --provenance <path>'
fi

cat > "${KIT_DIR}/README-AVC.md" <<EOF
# DefenseClaw Windows managed-enterprise Setup — AVC build kit ${VERSION}

Reference contract: **docs/WINDOWS-AVC-PACKAGING-HANDOFF.md** (in the
DefenseClaw source tree). This kit implements that handoff verbatim.

## What AVC runs (three verbs)

    1. signtool sign  payload/DefenseClawEnterprise.psm1
       signtool sign  payload/*.exe
       Set-AuthenticodeSignature -FilePath payload/install-enterprise.ps1 ...

    2. export SOURCE_DATE_EPOCH=<the commit's UTC unix seconds>
       ${ASSEMBLE_INVOCATION}

    3. signtool sign  out/DefenseClawSetup-Enterprise-x64.exe

Final artefacts AVC ships back:
  - out/DefenseClawSetup-Enterprise-x64.exe          (signed)
  - out/DefenseClawSetup-Enterprise-x64.exe.sha256   (SHA-256 sidecar)
  - out/DefenseClawSetup-Enterprise-x64.exe.provenance.json

The \`.sha256\` sidecar and the \`setup_sha256\` field inside
provenance.json are the SHA-256 of the SIGNED outer EXE, computed
after step 3. AVC can compute them inside their signtool wrapper OR
invoke the optional in-kit helper:

    ${FINALIZE_INVOCATION}

Either path is fine — the DefenseClaw contract only cares that
\`setup_sha256\` matches the shipped EXE's hash by the time the artefact
reaches release engineering.

## Facts about this kit

- Source commit:            ${SOURCE_COMMIT}
- DefenseClaw version:      ${VERSION}
- CMID pseudo-version:      ${CMID_VERSION}
- Script host in kit:       ${SCRIPT_HOST}
- Offline \`go build\`:     kit/source/vendor is complete; no network
                             access needed at build time.
- Go toolchain expected:    matches GOTOOLCHAIN in
                             kit/packaging/scripts/lib/repro-flags.sh
                             (out-of-band pin per spec 001).
- Reproducibility invariant: two AVC-runner runs of the same kit
                             against byte-identical signed payload
                             MUST produce byte-identical outer Setup
                             EXEs (spec 001 REQ-07 gate).

## Questions

Route any AVC-side environmental issues (missing tools, unexpected go
version, network policy) to the DefenseClaw packaging team. Any
change to this kit's structure requires an amendment to
WINDOWS-AVC-PACKAGING-HANDOFF.md in the DefenseClaw source tree —
this file is generated, do not edit it.
EOF

# ---- --allow-unsigned local-loop mode ---------------------------------
# Runs assemble.sh --allow-unsigned inline against the (unsigned)
# payload we just staged, landing a runnable DefenseClawSetup-
# Enterprise-x64.exe under ${KIT_DIR}/out/ so a developer can iterate
# without any AVC engagement. The emitted manifest.json + provenance.json
# both carry "unsigned": true; the runtime hash gate at
# stageEnterprisePayload then requires --allow-unsigned +
# --certification-codex-home at install time (see
# cmd/defenseclaw-enterprise-setup/platform_windows.go:59-64).
if [[ "${ALLOW_UNSIGNED}" == "true" ]]; then
  echo "==> running assemble.sh --allow-unsigned inline"
  export SOURCE_DATE_EPOCH="${SOURCE_COMMIT_EPOCH:-$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD)}"
  # The kit-shipped assemble.sh lives at ${KIT_DIR}/assemble.sh (bash
  # script host). If the user passed --script-host pwsh we still use
  # the bash helper for the inline path since we're on macOS/Linux
  # here — pwsh isn't guaranteed on a DefenseClaw developer's laptop.
  ( cd "${KIT_DIR}" && bash "${LIB_SRC}/assemble.sh" \
      --payload-dir "./payload" \
      --source-dir  "./source" \
      --out-dir     "./out" \
      --source-commit "${SOURCE_COMMIT}" \
      --version "${VERSION}" \
      --cmid-pseudo-version "${CMID_VERSION}" \
      --allow-unsigned )
fi

rm -rf "${EMITTER_TMP}"

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
echo "==> managed Windows bundle prep complete"
echo "    AVC build kit:    ${KIT_DIR}"
echo "    gateway zip:      ${GATEWAY_ZIP}"
echo "    source commit:    ${COMMIT_FILE}  (${SOURCE_COMMIT})"
echo "    pinned cmid:      ${CMID_VERSION}"
if [[ "${ALLOW_UNSIGNED}" == "true" ]]; then
  echo "    unsigned Setup:   ${KIT_DIR}/out/DefenseClawSetup-Enterprise-x64.exe"
  echo ""
  echo "Local unsigned build ready. Install on a Windows test box with"
  echo "  DefenseClawSetup-Enterprise-x64.exe /install --allow-unsigned \\"
  echo "      --certification-codex-home <disposable path>"
  echo "See cmd/defenseclaw-enterprise-setup/platform_windows.go for the"
  echo "runtime hash gate that refuses non-disposable scopes."
else
  echo ""
  echo "Hand ${KIT_DIR} (or a tar of it) to AVC per"
  echo "docs/WINDOWS-AVC-PACKAGING-HANDOFF.md. AVC will:"
  echo "  1. signtool sign      payload/*.{exe,ps1,psm1}"
  echo "  2. ./assemble.sh      (or pwsh -File assemble.ps1)"
  echo "  3. signtool sign      out/DefenseClawSetup-Enterprise-x64.exe"
fi
echo ""
