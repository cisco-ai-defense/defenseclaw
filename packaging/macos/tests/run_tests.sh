#!/usr/bin/env bash
#
# Pure-bash unit test runner for the macOS installer scripts.
#
# Usage:
#   packaging/macos/tests/run_tests.sh           # run all tests
#   packaging/macos/tests/run_tests.sh -v        # verbose (show every assert)
#   packaging/macos/tests/run_tests.sh test_*.sh # run a subset
#
# Each test file is sourced in-process (not in a subshell) so it can
# share the assertion counters and helpers defined below. `set -u` is
# process-wide, so a fatal error in one test file will abort the
# runner; keep test files defensive (no undefined-variable expansions
# outside quoted `${var:-}` patterns).
#
# Failures print file:line of the failing assert (via `_fail`, which
# resolves the appropriate BASH_SOURCE/BASH_LINENO stack frame based on
# whether _fail was invoked through an assert_* wrapper or directly).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PKG_DIR}/../.." && pwd)"

VERBOSE="false"
declare -a FILES=()
for arg in "$@"; do
  case "${arg}" in
    -v|--verbose) VERBOSE="true";;
    *)            FILES+=("${arg}");;
  esac
done

if [[ ${#FILES[@]} -eq 0 ]]; then
  while IFS= read -r f; do
    FILES+=("${f}")
  done < <(find "${SCRIPT_DIR}" -maxdepth 1 -name 'test_*.sh' | sort)
fi

# ---- export paths for tests --------------------------------------------

export PKG_DIR REPO_ROOT

# ---- per-test working dir ----------------------------------------------

TMPROOT="$(mktemp -d "${TMPDIR:-/tmp}/dctest.XXXXXX")"
trap 'rm -rf "${TMPROOT}"' EXIT

# ---- assertion helpers (sourced into each test) ------------------------

TEST_FAIL_COUNT=0
TEST_OK_COUNT=0
CUR_TEST_FILE=""
CUR_TEST_NAME=""

_fail() {
  local msg="$1"
  # Resolve the "test call site" — the first frame in BASH_SOURCE that
  # is a test file (test_*.sh), skipping run_tests.sh itself. This
  # works whether _fail is called through an assert_* wrapper (2+
  # frames deep) or directly from a test case function (1 frame deep).
  # macOS bash 3.2 doesn't have BASH_SOURCE[@] with reliable @ indexing
  # inside functions, but positional loop works fine.
  local src="" line="" i
  for (( i = 1; i < ${#BASH_SOURCE[@]}; i++ )); do
    case "${BASH_SOURCE[$i]}" in
      */test_*.sh)
        src="${BASH_SOURCE[$i]}"
        line="${BASH_LINENO[$((i-1))]}"
        break
        ;;
    esac
  done
  if [[ -z "${src}" ]]; then
    # Fallback: whatever the caller of _fail was.
    src="${BASH_SOURCE[1]:-?}"
    line="${BASH_LINENO[0]:-?}"
  fi
  printf 'FAIL  %s :: %s\n  at: %s:%s\n  %s\n' \
    "${CUR_TEST_FILE}" "${CUR_TEST_NAME}" "${src}" "${line}" "${msg}" >&2
  TEST_FAIL_COUNT=$((TEST_FAIL_COUNT + 1))
  return 1
}

assert_eq() {
  local got="$1" want="$2" what="${3:-values}"
  if [[ "${got}" != "${want}" ]]; then
    _fail "${what} mismatch — got=$(printf %q "${got}") want=$(printf %q "${want}")"
    return 1
  fi
  if [[ "${VERBOSE}" == "true" ]]; then
    printf '  ok  %s == %q\n' "${what}" "${want}"
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" what="${3:-output}"
  if [[ "${haystack}" != *"${needle}"* ]]; then
    _fail "${what} missing substring $(printf %q "${needle}")\n  haystack head: $(printf %s "${haystack}" | head -5)"
    return 1
  fi
  if [[ "${VERBOSE}" == "true" ]]; then
    printf '  ok  %s contains %q\n' "${what}" "${needle}"
  fi
}

assert_not_contains() {
  local haystack="$1" needle="$2" what="${3:-output}"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    _fail "${what} should not contain $(printf %q "${needle}")"
    return 1
  fi
}

assert_status() {
  local got="$1" want="$2" what="${3:-exit status}"
  if [[ "${got}" -ne "${want}" ]]; then
    _fail "${what} got=${got} want=${want}"
    return 1
  fi
}

assert_file_exists() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    _fail "expected file to exist: ${path}"
    return 1
  fi
}

assert_file_mode() {
  local path="$1" want="$2"
  local got
  got="$(stat -f '%Lp' "${path}" 2>/dev/null || stat -c '%a' "${path}" 2>/dev/null || echo "")"
  if [[ "${got}" != "${want}" ]]; then
    _fail "mode mismatch on ${path}: got=${got} want=${want}"
    return 1
  fi
}

# 'it NAME body...' marks a test case; the body is the next callable
# function. We use a simpler convention here: each test file calls
# `run_case NAME func` to invoke a named case.
run_case() {
  local name="$1"; shift
  CUR_TEST_NAME="${name}"
  if [[ "${VERBOSE}" == "true" ]]; then
    printf 'CASE  %s :: %s\n' "${CUR_TEST_FILE}" "${name}"
  fi
  local before_fail=${TEST_FAIL_COUNT}
  # Capture the case's exit status. If the function returns non-zero but
  # never recorded a failure via _fail (typo'd name, mkdir/cd blew up,
  # bare `if` with no `else` under `set -u`, etc.), treat that as a
  # failure — the earlier "silently pass on non-zero" behavior masked
  # broken tests that never actually asserted anything.
  local rc=0
  "$@" || rc=$?
  if (( rc != 0 )) && (( TEST_FAIL_COUNT == before_fail )); then
    _fail "case '${name}' exited with status ${rc} but recorded no assertion"
  fi
  if [[ ${TEST_FAIL_COUNT} -eq ${before_fail} ]]; then
    TEST_OK_COUNT=$((TEST_OK_COUNT + 1))
    if [[ "${VERBOSE}" == "true" ]]; then
      printf '  PASS\n'
    fi
  fi
}

mktest_tmp() {
  local d
  d="$(mktemp -d "${TMPROOT}/case.XXXXXX")"
  printf '%s' "${d}"
}

# ---- runner ------------------------------------------------------------

START_TIME=$(date +%s)
for f in "${FILES[@]}"; do
  CUR_TEST_FILE="$(basename "${f}")"
  if [[ "${VERBOSE}" == "true" ]]; then
    printf '==== %s ====\n' "${CUR_TEST_FILE}"
  fi
  # shellcheck disable=SC1090
  . "${f}"
done

ELAPSED=$(($(date +%s) - START_TIME))
printf '\n----- %d passed, %d failed in %ds -----\n' \
  "${TEST_OK_COUNT}" "${TEST_FAIL_COUNT}" "${ELAPSED}"

if [[ ${TEST_FAIL_COUNT} -gt 0 ]]; then
  exit 1
fi
exit 0
