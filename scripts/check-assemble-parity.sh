#!/usr/bin/env bash
#
# check-assemble-parity.sh
#
# Refuses drift between the two AVC-facing assembler scripts:
#   packaging/scripts/lib/assemble.sh    (bash, shipped when --script-host bash)
#   packaging/scripts/lib/assemble.ps1   (pwsh, shipped when --script-host pwsh)
#
# Both files run the same six-step sequence — source repro-flags,
# preflight envs, assert Cisco signatures, emit manifest, stage
# payload, cross-build outer Setup EXE, emit provenance — and they
# MUST behave identically so a kit built with either shipped assembler
# produces byte-identical output against the same signed payload
# (docs/specs/002-windows-avc-packaging/design.md § Risks — "AVC picks
# pwsh as their default and assemble.ps1 develops semantic drift from
# assemble.sh").
#
# The check is syntactic (regex-based) rather than semantic (execute
# both scripts and diff state). Semantic parity would require
# PowerShell in every CI runner, which is not universally available;
# the two scripts diverge in ways syntactic checks miss only if
# someone is trying to hide drift, which is out of scope.
#
# What we lint:
#   1. Ordered stage log lines ("stage N/6  <name>") — catches missing
#      stages, reordered stages, and typos in stage names.
#   2. Expected payload filenames — both scripts must accept the same
#      six files under ./payload/.
#   3. Emitter subcommand invocations — the two `emit-*` calls the
#      scripts make against windows-repro-manifest must match.
#
# See docs/specs/001-windows-deterministic-build/design.md for the
# reproducibility contract this parity lint helps enforce.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

SH="${REPO_ROOT}/packaging/scripts/lib/assemble.sh"
PS="${REPO_ROOT}/packaging/scripts/lib/assemble.ps1"

for f in "${SH}" "${PS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "check-assemble-parity: missing file: ${f}" >&2
        exit 2
    fi
done

# --- 1. Ordered stage log lines. -----------------------------------------
#
# Both files call a helper that prints `==> stage N/6  <name>` for each
# of the six sequenced stages. Extract them in source order and diff.
extract_sh_stages() {
    # bash form:  _stage "stage N/6  <name>"
    grep -E '_stage "stage [0-9]+/6' "${SH}" \
        | sed -E 's/^[[:space:]]*_stage "(stage [0-9]+\/6[^"]*)".*/\1/'
}
extract_ps_stages() {
    # pwsh form: Write-DefenseClawStage "stage N/6  <name>" (renamed
    # from the earlier non-approved-verb DefenseClaw-Stage per CR
    # spec-002:PRRT_kwDORuAK-s6af8i2).
    grep -E 'Write-DefenseClawStage "stage [0-9]+/6' "${PS}" \
        | sed -E 's/^[[:space:]]*Write-DefenseClawStage "(stage [0-9]+\/6[^"]*)".*/\1/'
}

sh_stages="$(extract_sh_stages)"
ps_stages="$(extract_ps_stages)"

if [[ "${sh_stages}" != "${ps_stages}" ]]; then
    echo "check-assemble-parity: stage log lines drift between the two files." >&2
    echo "" >&2
    echo "bash stages:" >&2
    echo "${sh_stages}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "pwsh stages:" >&2
    echo "${ps_stages}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "See docs/specs/002-windows-avc-packaging/design.md § Risks." >&2
    exit 1
fi

# --- 2. Expected payload filenames. --------------------------------------
#
# Both scripts declare an EXPECTED_PAYLOAD list (bash array / pwsh
# array). The list MUST be the same set of six filenames so a payload
# staged for one shipped assembler passes signature and hash checks
# under the other.
extract_sh_payload() {
    # Match the EXPECTED_PAYLOAD=(...) block and pull one filename per
    # line. Filenames must match [A-Za-z0-9._-]+ (fixed set from
    # cmd/defenseclaw-enterprise-setup/main.go requiredPayloadFiles).
    awk '/^EXPECTED_PAYLOAD=\(/,/^\)/' "${SH}" \
        | grep -E '^[[:space:]]+[A-Za-z0-9._-]+$' \
        | awk '{print $1}' \
        | sort
}
extract_ps_payload() {
    # pwsh form: $expectedPayload = @( 'name', 'name', ... )
    awk '/\$expectedPayload = @\(/,/^\)/' "${PS}" \
        | grep -E "^[[:space:]]+'[A-Za-z0-9._-]+',?[[:space:]]*$" \
        | sed -E "s/^[[:space:]]+'([A-Za-z0-9._-]+)',?[[:space:]]*$/\1/" \
        | sort
}

sh_payload="$(extract_sh_payload)"
ps_payload="$(extract_ps_payload)"

if [[ "${sh_payload}" != "${ps_payload}" ]]; then
    echo "check-assemble-parity: EXPECTED_PAYLOAD drift between the two files." >&2
    echo "" >&2
    echo "bash expected payload:" >&2
    echo "${sh_payload}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "pwsh expected payload:" >&2
    echo "${ps_payload}" | sed 's/^/  /' >&2
    exit 1
fi

# --- 3. Emitter subcommand set. ------------------------------------------
#
# assemble.sh and assemble.ps1 each invoke `windows-repro-manifest`
# with two subcommands: emit-manifest, emit-provenance. Anything else
# (emit-payload-metadata belongs to the bundler side, not assemble)
# indicates drift.
extract_sh_emitter_calls() {
    # Bind extraction to the actual emitter invocation form,
    # `"${EMITTER}" emit-...`, so stage labels (`_stage "stage 3/6
    # emit-manifest"`) and prose comments do not leak into the parity
    # set. Preserve source order and duplicates: `sort -u` collapsed
    # two files that invoke the SAME subcommand set in a DIFFERENT
    # order into an identical hash, which is exactly the drift this
    # lint is supposed to catch. See CR spec-002:PRRT_kwDORuAK-s6af8j4
    # (order preservation) + PRRT_kwDORuAK-s6ahACZ (bind to call site).
    grep -E '"\$\{EMITTER\}" emit-[a-z-]+' "${SH}" \
        | grep -oE "emit-[a-z-]+"
}
extract_ps_emitter_calls() {
    # pwsh form: emitter subcommands appear as the first element of
    # $manifestArgs / $provArgs arrays, formatted `'emit-<name>',`.
    # Only match those lines to avoid the same stage-label pollution.
    grep -E "^[[:space:]]+'emit-[a-z-]+'," "${PS}" \
        | grep -oE "emit-[a-z-]+"
}

sh_emit="$(extract_sh_emitter_calls)"
ps_emit="$(extract_ps_emitter_calls)"

if [[ "${sh_emit}" != "${ps_emit}" ]]; then
    echo "check-assemble-parity: emitter subcommand set drift between the two files." >&2
    echo "" >&2
    echo "bash emitter calls:" >&2
    echo "${sh_emit}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "pwsh emitter calls:" >&2
    echo "${ps_emit}" | sed 's/^/  /' >&2
    exit 1
fi

stage_count=$(printf '%s\n' "${sh_stages}" | wc -l | tr -d '[:space:]')
payload_count=$(printf '%s\n' "${sh_payload}" | wc -l | tr -d '[:space:]')
emitter_count=$(printf '%s\n' "${sh_emit}" | wc -l | tr -d '[:space:]')

echo "check-assemble-parity: OK (${stage_count} stages match; ${payload_count} expected payload names match; ${emitter_count} emitter subcommands match)"
