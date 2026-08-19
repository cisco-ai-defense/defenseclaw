#!/usr/bin/env bash
#
# check-repro-flags-parity.sh
#
# Refuses drift between the two sources of truth for the AVC
# reproducibility envs:
#   packaging/scripts/lib/repro-flags.sh   (bash, sourced by assemble.sh)
#   packaging/scripts/lib/repro-flags.ps1  (pwsh, sourced by assemble.ps1)
#
# Both files set the same six envs, ship the same required-env list,
# and export the same preflight+build functions. If they drift, the
# byte-identical outer Setup EXE contract Workstream A depends on
# quietly breaks — one script host would produce a different binary
# from the other. This lint runs from `make lint` so drift is caught
# on every PR that touches either file.
#
# The check is deliberately syntactic (grep-based) rather than
# semantic (executing both scripts and diffing state). Semantic parity
# would require running PowerShell in CI, which is not universally
# available; the two files diverge in ways that syntactic checks miss
# only if someone is trying to hide drift, which is out of scope.
#
# See docs/specs/001-windows-deterministic-build/design.md § Risks.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

SH="${REPO_ROOT}/packaging/scripts/lib/repro-flags.sh"
PS="${REPO_ROOT}/packaging/scripts/lib/repro-flags.ps1"

for f in "${SH}" "${PS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "check-repro-flags-parity: missing file: ${f}" >&2
        exit 2
    fi
done

# The six fixed-value envs must appear with identical values in both
# files. Extract them from each and sort so equivalent-but-reordered
# lists still compare equal.
extract_sh_envs() {
    grep -E '^export [A-Z_]+="[^"]*"$' "${SH}" \
        | sed -E 's/^export ([A-Z_]+)="([^"]*)"$/\1=\2/' \
        | sort
}
extract_ps_envs() {
    # PowerShell form:  $env:NAME = 'value'  (or double-quoted).
    # Normalise to NAME=value.
    grep -E "^\\\$env:[A-Z_]+ +=" "${PS}" \
        | sed -E "s/^\\\$env:([A-Z_]+) +=[[:space:]]+['\"]([^'\"]*)['\"]$/\1=\2/" \
        | sort
}

sh_envs="$(extract_sh_envs)"
ps_envs="$(extract_ps_envs)"

if [[ "${sh_envs}" != "${ps_envs}" ]]; then
    echo "check-repro-flags-parity: the fixed-value env exports drift between the two files." >&2
    echo "" >&2
    echo "bash exports:" >&2
    echo "${sh_envs}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "pwsh exports:" >&2
    echo "${ps_envs}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "See docs/specs/001-windows-deterministic-build/design.md § Risks." >&2
    exit 1
fi

# The required-env array/list must contain the same names.
extract_sh_required() {
    # Names appear inside the DEFENSECLAW_REPRO_REQUIRED_ENVS=(...) block.
    awk '/^DEFENSECLAW_REPRO_REQUIRED_ENVS=\(/,/^\)/' "${SH}" \
        | grep -E '^[[:space:]]+[A-Z_]+$' \
        | awk '{print $1}' \
        | sort
}
extract_ps_required() {
    # Handle both `'NAME',` (any-but-last) and `'NAME'` (last element,
    # no trailing comma) by making the comma optional.
    awk '/DefenseClawReproRequiredEnvs = @\(/,/^\)/' "${PS}" \
        | grep -E "^[[:space:]]+'[A-Z_]+',?[[:space:]]*$" \
        | sed -E "s/^[[:space:]]+'([A-Z_]+)',?[[:space:]]*$/\1/" \
        | sort
}

sh_required="$(extract_sh_required)"
ps_required="$(extract_ps_required)"

if [[ "${sh_required}" != "${ps_required}" ]]; then
    echo "check-repro-flags-parity: DEFENSECLAW_REPRO_REQUIRED_ENVS drift between the two files." >&2
    echo "" >&2
    echo "bash required list:" >&2
    echo "${sh_required}" | sed 's/^/  /' >&2
    echo "" >&2
    echo "pwsh required list:" >&2
    echo "${ps_required}" | sed 's/^/  /' >&2
    exit 1
fi

env_count=$(printf '%s\n' "${sh_envs}" | wc -l | tr -d '[:space:]')
required_count=$(printf '%s\n' "${sh_required}" | wc -l | tr -d '[:space:]')
echo "check-repro-flags-parity: OK (${env_count} fixed envs match; ${required_count} required-env names match)"
