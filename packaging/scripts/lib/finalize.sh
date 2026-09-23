#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# finalize.sh — optional post-signing helper for AVC's Windows pipeline.
#
# AVC runs three verbs per handoff (docs/WINDOWS-AVC-PACKAGING-HANDOFF.md):
#   1. signtool sign  payload/*
#   2. ./assemble.sh
#   3. signtool sign  out/DefenseClawSetup-Enterprise-x64.exe
#
# assemble.sh emits provenance.json with setup_sha256="" and setup_size=0
# because the SIGNED outer EXE hash is only knowable after step 3.
# `finalize.sh` is the DefenseClaw-provided convenience helper AVC's
# pipeline may invoke after step 3 to:
#
#   - compute SHA-256 of the signed outer EXE,
#   - write the .sha256 sidecar,
#   - overwrite setup_sha256 + setup_size in provenance.json in place.
#
# AVC may use this helper or fold the same three actions into their
# own signtool wrapper — DefenseClaw's contract only cares that the
# final artefact set contains a correct .sha256 sidecar and a
# provenance.json whose setup_sha256 matches. See
# docs/specs/002-windows-avc-packaging/design.md § Decisions.
#
# USAGE
#   ./finalize.sh --setup-exe out/DefenseClawSetup-Enterprise-x64.exe \
#                 --provenance out/DefenseClawSetup-Enterprise-x64.exe.provenance.json
#
# Exit codes: 0 ok, 2 usage, 6 io/parse error.

set -euo pipefail

die() {
    local code="$1"; shift
    printf 'finalize: %s\n' "$*" >&2
    exit "${code}"
}

usage() {
    cat >&2 <<'EOF'
Usage: finalize.sh --setup-exe <path> --provenance <path>

Rehashes the signed outer Setup EXE and writes:
  - <setup-exe>.sha256                 (SHA-256 sidecar)
  - <provenance> (with setup_sha256 and setup_size populated in place)

Exit codes: 0 ok, 2 usage, 6 io.
EOF
}

SETUP_EXE=""
PROVENANCE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --setup-exe)   SETUP_EXE="${2:?}"; shift 2 ;;
        --provenance)  PROVENANCE="${2:?}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage; die 2 "unknown flag: $1" ;;
    esac
done

[ -n "${SETUP_EXE}" ]  || { usage; die 2 "--setup-exe required"; }
[ -n "${PROVENANCE}" ] || { usage; die 2 "--provenance required"; }
[ -f "${SETUP_EXE}" ]  || die 6 "setup-exe not found: ${SETUP_EXE}"
[ -f "${PROVENANCE}" ] || die 6 "provenance not found: ${PROVENANCE}"

# Compute hash + size. Prefer sha256sum (GNU) then shasum (BSD/macOS).
if command -v sha256sum >/dev/null 2>&1; then
    sha=$(sha256sum "${SETUP_EXE}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    sha=$(shasum -a 256 "${SETUP_EXE}" | awk '{print $1}')
else
    die 6 "sha256sum or shasum required to compute setup_sha256"
fi
size=$(wc -c < "${SETUP_EXE}" | tr -d '[:space:]')

# .sha256 sidecar: same shape sha256sum(1) writes — one line, hash + two
# spaces + base filename. AVC's downstream verifiers grep this format.
printf '%s  %s\n' "${sha}" "$(basename "${SETUP_EXE}")" > "${SETUP_EXE}.sha256"

# In-place edit of provenance.json. We use Python for the JSON round
# trip because it preserves the byte-stable ordering emitted by
# windows-repro-manifest (sorted keys, LF, two-space indent, trailing
# LF) — a shell-only sed would risk breaking the byte-identity gate.
if ! command -v python3 >/dev/null 2>&1; then
    die 6 "python3 required for provenance.json rewrite"
fi

if ! python3 - "${PROVENANCE}" "${sha}" "${size}" <<'PY'
import json, sys
path, sha, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, "r", encoding="utf-8") as f:
    doc = json.load(f)
doc["setup_sha256"] = sha
doc["setup_size"]   = size
# Preserve byte-stable serialization: sort_keys, LF-only, two-space
# indent, trailing newline. Matches cmd/windows-repro-manifest/serialize.go.
with open(path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, sort_keys=True, indent=2, ensure_ascii=False)
    f.write("\n")
PY
then
    # Explicitly map any python-side failure (malformed provenance
    # JSON, write permission denied, missing file, etc.) to exit code
    # 6 per the header contract. Without this, `set -e` alone would
    # bubble python's exit code — usually 1 — masking the IO nature
    # of the failure. See CR spec-002:PRRT_kwDORuAK-s6af8jz.
    die 6 "provenance.json rewrite failed (see python traceback above)"
fi

printf 'finalize: setup_sha256=%s size=%s -> %s + %s.sha256\n' \
    "${sha}" "${size}" "${PROVENANCE}" "${SETUP_EXE}"
