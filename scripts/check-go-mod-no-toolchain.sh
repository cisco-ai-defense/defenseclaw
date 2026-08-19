#!/usr/bin/env bash
#
# check-go-mod-no-toolchain.sh
#
# Refuses a `toolchain` directive in go.mod. See
# docs/specs/001-windows-deterministic-build/design.md § Tradeoffs:
# the Go toolchain pin for the AVC-managed-enterprise reproducibility
# contract lives out-of-band (GOTOOLCHAIN=go1.26.4 in
# packaging/scripts/lib/repro-flags.{sh,ps1} and the reproducibility
# CI workflow), NOT in go.mod. A `toolchain` directive in go.mod would
# force every OSS build, contributor `go mod tidy`, and non-managed CI
# job to download that toolchain without giving OSS anything in return.
#
# This check is invoked from `make lint`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

go_mod="${REPO_ROOT}/go.mod"
if [[ ! -f "${go_mod}" ]]; then
  echo "check-go-mod-no-toolchain: go.mod not found at ${go_mod}" >&2
  exit 2
fi

# Match a real `toolchain` directive, not a comment mentioning "toolchain".
# The Go module file grammar has `toolchain` as a top-level line-start
# directive (never indented, one per file).
if grep -qE '^toolchain[[:space:]]+go' "${go_mod}"; then
  cat >&2 <<'EOF'
check-go-mod-no-toolchain: go.mod must not contain a `toolchain` directive.

The Go toolchain pin for the managed-enterprise / AVC reproducibility
contract lives out-of-band in:
  - packaging/scripts/lib/repro-flags.sh    (bash)
  - packaging/scripts/lib/repro-flags.ps1   (pwsh)
  - .github/workflows/windows-deterministic-build.yml  (CI env)

Adding a `toolchain` directive to go.mod would force every OSS build and
contributor tooling invocation to download that toolchain, without giving
OSS anything in return. See:
  docs/specs/001-windows-deterministic-build/design.md § Tradeoffs

If you have a genuine reason to pin the toolchain module-wide, open a
follow-up spec that rescopes the reproducibility invariant and update
this check.
EOF
  exit 1
fi
