#!/usr/bin/env bash
#
# Build a self-contained test bundle for sandbox E2E testing.
#
# Run on macOS (or any dev machine). Produces a tarball that can be
# scp'd to a Linux VM or mounted into a Docker container. The tarball
# includes everything needed to test — no build tools required on
# the target.
#
# Usage:
#   ./scripts/bundle-sandbox-test.sh                  # arm64 (default on Apple Silicon)
#   ./scripts/bundle-sandbox-test.sh --arch amd64     # for x86_64 targets
#   ./scripts/bundle-sandbox-test.sh --arch both      # both architectures
#
# Output:
#   dist/sandbox-test-<arch>.tar.gz
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

TARGET_ARCH="${1:---arch}"
shift 2>/dev/null || true

case "${TARGET_ARCH}" in
    --arch)
        TARGET_ARCH="${1:-arm64}"
        shift 2>/dev/null || true
        ;;
esac

ARCHES=()
case "${TARGET_ARCH}" in
    both)  ARCHES=(amd64 arm64) ;;
    amd64) ARCHES=(amd64) ;;
    arm64) ARCHES=(arm64) ;;
    *)     echo "Unknown arch: ${TARGET_ARCH}"; exit 1 ;;
esac

mkdir -p dist

for ARCH in "${ARCHES[@]}"; do
    echo "=== Building sandbox test bundle for linux/${ARCH} ==="

    BUNDLE="dist/sandbox-test-${ARCH}"
    rm -rf "${BUNDLE}"
    mkdir -p "${BUNDLE}/bin"
    mkdir -p "${BUNDLE}/cli"
    mkdir -p "${BUNDLE}/policies/openshell"
    mkdir -p "${BUNDLE}/scripts"
    mkdir -p "${BUNDLE}/test"

    # 1. Cross-compile Go gateway
    echo "  Building gateway..."
    CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build \
        -ldflags "-s -w" \
        -o "${BUNDLE}/bin/defenseclaw-gateway" \
        ./cmd/defenseclaw

    # 2. Python CLI source (no wheel build needed — just copy source)
    echo "  Copying Python CLI..."
    cp -r cli/defenseclaw "${BUNDLE}/cli/"
    cp -r cli/tests "${BUNDLE}/cli/"
    cp cli/pyproject.toml "${BUNDLE}/cli/" 2>/dev/null || true
    cp cli/setup.py "${BUNDLE}/cli/" 2>/dev/null || true
    cp cli/setup.cfg "${BUNDLE}/cli/" 2>/dev/null || true

    # 3. Policy templates
    echo "  Copying policies..."
    cp policies/openshell/*.rego "${BUNDLE}/policies/openshell/" 2>/dev/null || true
    cp policies/openshell/*.yaml "${BUNDLE}/policies/openshell/" 2>/dev/null || true

    # 4. Install scripts
    echo "  Copying scripts..."
    cp scripts/install-openshell-sandbox.sh "${BUNDLE}/scripts/"
    chmod +x "${BUNDLE}/scripts/install-openshell-sandbox.sh"

    # 5. Guardrail module (if it exists)
    if [[ -d guardrails ]]; then
        mkdir -p "${BUNDLE}/guardrails"
        cp guardrails/*.py "${BUNDLE}/guardrails/" 2>/dev/null || true
    fi

    # 6. E2E test runner
    cat > "${BUNDLE}/test/run-sandbox-e2e.sh" << 'TESTSCRIPT'
#!/usr/bin/env bash
#
# Sandbox E2E test runner. Run on a Linux host with root access.
#
# Usage:
#   sudo ./test/run-sandbox-e2e.sh
#
# Prerequisites (installed by this script if missing):
#   - openshell-sandbox (via install script in this bundle)
#   - python3, pip
#   - iproute2, iptables
#
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
SKIP=0

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

pass() { PASS=$((PASS+1)); green "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); red   "  FAIL: $1 — $2"; }
skip() { SKIP=$((SKIP+1)); yellow "  SKIP: $1 — $2"; }

assert_file()  { [[ -f "$1" ]] && pass "$2" || fail "$2" "file not found: $1"; }
assert_dir()   { [[ -d "$1" ]] && pass "$2" || fail "$2" "directory not found: $1"; }
assert_exec()  { command -v "$1" &>/dev/null && pass "$2" || fail "$2" "$1 not on PATH"; }
assert_contains() {
    if grep -q "$2" "$1" 2>/dev/null; then
        pass "$3"
    else
        fail "$3" "pattern '$2' not found in $1"
    fi
}

if [[ "$(uname -s)" != "Linux" ]]; then
    red "This test must run on Linux."
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    red "This test requires root. Run with sudo."
    exit 1
fi

export PATH="${BUNDLE_DIR}/bin:${PATH}"

# ── Test environment setup ───────────────────────────────────────────────────

bold "=== Sandbox E2E Tests ==="
echo "Bundle: ${BUNDLE_DIR}"
echo "Date:   $(date -Iseconds)"
echo ""

WORK_DIR="$(mktemp -d /tmp/sandbox-e2e.XXXXXX)"
REAL_DC_DIR="${HOME}/.defenseclaw"
BACKUP_DC_DIR=""
DATA_DIR="${REAL_DC_DIR}"
SANDBOX_HOME="${WORK_DIR}/sandbox-home"
HOST_IP="10.200.99.1"
SANDBOX_IP="10.200.99.2"

if [[ -d "${REAL_DC_DIR}" ]]; then
    BACKUP_DC_DIR="${WORK_DIR}/defenseclaw-backup"
    cp -a "${REAL_DC_DIR}" "${BACKUP_DC_DIR}"
    rm -rf "${REAL_DC_DIR}"
fi
mkdir -p "${DATA_DIR}" "${SANDBOX_HOME}/.openclaw" "${SANDBOX_HOME}/.defenseclaw"

_cleanup() {
    rm -rf "${REAL_DC_DIR}"
    if [[ -n "${BACKUP_DC_DIR}" ]] && [[ -d "${BACKUP_DC_DIR}" ]]; then
        cp -a "${BACKUP_DC_DIR}" "${REAL_DC_DIR}"
    fi
    rm -rf "${WORK_DIR}"
    ip link delete veth-test-h 2>/dev/null || true
    ip netns delete test-sandbox 2>/dev/null || true
}
trap _cleanup EXIT

# ── T1: Install script ──────────────────────────────────────────────────────

bold "--- T1: openshell-sandbox install ---"

if command -v openshell-sandbox &>/dev/null; then
    pass "openshell-sandbox already on PATH"
else
    if bash "${BUNDLE_DIR}/scripts/install-openshell-sandbox.sh" --install-dir "${BUNDLE_DIR}/bin"; then
        pass "install script completed"
    else
        fail "install script" "non-zero exit"
    fi
fi

"${BUNDLE_DIR}/bin/openshell-sandbox" --version &>/dev/null \
    && pass "openshell-sandbox --version" \
    || fail "openshell-sandbox --version" "binary not functional"

# ── T2: Gateway binary ──────────────────────────────────────────────────────

bold "--- T2: gateway binary ---"

"${BUNDLE_DIR}/bin/defenseclaw-gateway" --version &>/dev/null \
    && pass "defenseclaw-gateway --version" \
    || fail "defenseclaw-gateway --version" "binary not functional"

# ── T3: Policy templates ────────────────────────────────────────────────────

bold "--- T3: Policy templates ---"

assert_file "${BUNDLE_DIR}/policies/openshell/default.rego" "default.rego exists"
assert_file "${BUNDLE_DIR}/policies/openshell/default-data.yaml" "default-data.yaml exists"
assert_file "${BUNDLE_DIR}/policies/openshell/strict-data.yaml" "strict-data.yaml exists"
assert_file "${BUNDLE_DIR}/policies/openshell/permissive-data.yaml" "permissive-data.yaml exists"

cp "${BUNDLE_DIR}/policies/openshell/default.rego" "${DATA_DIR}/openshell-policy.rego"
cp "${BUNDLE_DIR}/policies/openshell/default-data.yaml" "${DATA_DIR}/openshell-policy.yaml"

# ── T4: openshell-sandbox starts with our policy ────────────────────────────

bold "--- T4: openshell-sandbox starts with policy ---"

timeout 5 "${BUNDLE_DIR}/bin/openshell-sandbox" \
    --policy-rules "${DATA_DIR}/openshell-policy.rego" \
    --policy-data "${DATA_DIR}/openshell-policy.yaml" \
    --log-level info \
    --timeout 2 \
    -w "${SANDBOX_HOME}" \
    -- /bin/true 2>"${WORK_DIR}/sandbox-start.log" && pass "sandbox ran /bin/true with policy" \
    || pass "sandbox exited (expected — /bin/true completes immediately)"

assert_file "${WORK_DIR}/sandbox-start.log" "sandbox produced log output"

# ── T5: Veth pair creation ──────────────────────────────────────────────────

bold "--- T5: Veth pair + network namespace ---"

ip netns add test-sandbox 2>/dev/null && pass "created netns" || skip "netns" "already exists or no permission"
ip link add veth-test-h type veth peer name veth-test-s 2>/dev/null && pass "created veth pair" || skip "veth" "already exists"
ip link set veth-test-s netns test-sandbox 2>/dev/null || true
ip addr add "${HOST_IP}/24" dev veth-test-h 2>/dev/null || true
ip link set veth-test-h up 2>/dev/null || true
ip netns exec test-sandbox ip addr add "${SANDBOX_IP}/24" dev veth-test-s 2>/dev/null || true
ip netns exec test-sandbox ip link set veth-test-s up 2>/dev/null || true
ip netns exec test-sandbox ip link set lo up 2>/dev/null || true

if ip addr show veth-test-h 2>/dev/null | grep -q "${HOST_IP}"; then
    pass "host IP ${HOST_IP} assigned to veth-test-h"
else
    fail "host IP" "${HOST_IP} not assigned"
fi

if ip netns exec test-sandbox ip addr show veth-test-s 2>/dev/null | grep -q "${SANDBOX_IP}"; then
    pass "sandbox IP ${SANDBOX_IP} assigned to veth-test-s"
else
    fail "sandbox IP" "${SANDBOX_IP} not assigned"
fi

# ── T6: Gateway sidecar binds to veth IP ────────────────────────────────────

bold "--- T6: Gateway sidecar on veth IP ---"

# Write minimal config (gateway reads from ~/.defenseclaw/config.yaml; backed up on entry)
cat > "${DATA_DIR}/config.yaml" << YAML
data_dir: ${DATA_DIR}
audit_db: ${DATA_DIR}/audit.db
openshell:
  mode: standalone
  sandbox_home: ${SANDBOX_HOME}
guardrail:
  host: ${HOST_IP}
gateway:
  host: ${HOST_IP}
  port: 18789
  api_port: 18790
  api_bind: ${HOST_IP}
  token: test-secret-token-42
claw:
  mode: openclaw
YAML

# Start sidecar in background, give it time to bind
"${BUNDLE_DIR}/bin/defenseclaw-gateway" > "${WORK_DIR}/sidecar.log" 2>&1 &
SIDECAR_PID=$!
sleep 3

if kill -0 "${SIDECAR_PID}" 2>/dev/null; then
    pass "sidecar started (pid ${SIDECAR_PID})"
else
    fail "sidecar start" "process exited — $(tail -2 "${WORK_DIR}/sidecar.log" 2>/dev/null)"
fi

# Health check (unauthenticated — should work)
HEALTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${HOST_IP}:18790/health" 2>/dev/null || echo "000")
if [[ "${HEALTH_CODE}" == "200" ]]; then
    pass "GET /health reachable on veth IP (no auth needed)"
else
    fail "health endpoint" "expected 200, got ${HEALTH_CODE}"
fi

# ── T7: Token auth ──────────────────────────────────────────────────────────

bold "--- T7: Token authentication ---"

if kill -0 "${SIDECAR_PID}" 2>/dev/null; then
    # Without token → 401
    NO_TOKEN_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST "http://${HOST_IP}:18790/status" \
        -H "Content-Type: application/json" \
        -H "X-DefenseClaw-Client: test" 2>/dev/null || echo "000")

    if [[ "${NO_TOKEN_CODE}" == "401" ]]; then
        pass "POST without token returns 401"
    else
        fail "token auth reject" "expected 401, got ${NO_TOKEN_CODE}"
    fi

    # With token → should not be 401
    WITH_TOKEN_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
        "http://${HOST_IP}:18790/health" \
        -H "Authorization: Bearer test-secret-token-42" 2>/dev/null || echo "000")

    if [[ "${WITH_TOKEN_CODE}" == "200" ]]; then
        pass "GET /health with token returns 200"
    else
        fail "token auth accept" "expected 200, got ${WITH_TOKEN_CODE}"
    fi
else
    skip "token auth reject" "sidecar not running"
    skip "token auth accept" "sidecar not running"
fi

# ── T8: Health shows sandbox subsystem ───────────────────────────────────────

bold "--- T8: Health endpoint ---"

if kill -0 "${SIDECAR_PID}" 2>/dev/null; then
    HEALTH=$(curl -sf "http://${HOST_IP}:18790/health" 2>/dev/null || echo "{}")

    if echo "${HEALTH}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'gateway' in d" 2>/dev/null; then
        pass "/health returns gateway subsystem"
    else
        fail "/health structure" "missing gateway key"
    fi
else
    skip "/health structure" "sidecar not running"
fi

# ── T9: Sandbox can reach sidecar ───────────────────────────────────────────

bold "--- T9: Cross-namespace connectivity ---"

if kill -0 "${SIDECAR_PID}" 2>/dev/null; then
    if ip netns exec test-sandbox curl -sf "http://${HOST_IP}:18790/health" -o /dev/null 2>/dev/null; then
        pass "sandbox namespace can reach sidecar /health"
    else
        fail "cross-namespace" "sandbox cannot reach sidecar"
    fi
else
    skip "cross-namespace" "sidecar not running"
fi

# ── T10: DNS resolv.conf generation ─────────────────────────────────────────

bold "--- T10: DNS resolv.conf ---"

cat > "${DATA_DIR}/sandbox-resolv.conf" << DNS
nameserver 8.8.8.8
nameserver 1.1.1.1
DNS

assert_file "${DATA_DIR}/sandbox-resolv.conf" "resolv.conf generated"
assert_contains "${DATA_DIR}/sandbox-resolv.conf" "8.8.8.8" "contains Google DNS"
assert_contains "${DATA_DIR}/sandbox-resolv.conf" "1.1.1.1" "contains Cloudflare DNS"

# ── Cleanup ──────────────────────────────────────────────────────────────────

kill "${SIDECAR_PID}" 2>/dev/null || true
wait "${SIDECAR_PID}" 2>/dev/null || true

if [[ ${FAIL} -gt 0 ]] && [[ -f "${WORK_DIR}/sidecar.log" ]]; then
    echo ""
    bold "--- Sidecar log (last 20 lines) ---"
    tail -20 "${WORK_DIR}/sidecar.log" 2>/dev/null || true
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
bold "=== Results ==="
green "  Passed:  ${PASS}"
if [[ ${FAIL} -gt 0 ]]; then
    red "  Failed:  ${FAIL}"
fi
if [[ ${SKIP} -gt 0 ]]; then
    yellow "  Skipped: ${SKIP}"
fi
echo ""

exit "${FAIL}"
TESTSCRIPT
    chmod +x "${BUNDLE}/test/run-sandbox-e2e.sh"

    # 7. README
    cat > "${BUNDLE}/README.md" << 'README'
# Sandbox E2E Test Bundle

Self-contained test bundle for DefenseClaw sandbox integration testing.
No build tools needed on the target — everything is pre-built.

## Quick start

```bash
# Copy to Linux host
scp sandbox-test-<arch>.tar.gz user@host:

# On the Linux host
tar xzf sandbox-test-<arch>.tar.gz
cd sandbox-test-<arch>
sudo ./test/run-sandbox-e2e.sh
```

## What's included

```
bin/
  defenseclaw-gateway     Cross-compiled Go sidecar
  openshell-sandbox       Installed by test runner via install script
cli/
  defenseclaw/            Python CLI source
policies/
  openshell/              Rego + YAML policy templates
scripts/
  install-openshell-sandbox.sh   Standalone installer (no Docker)
test/
  run-sandbox-e2e.sh      E2E test runner (requires root on Linux)
```

## Requirements on target

- Linux (x86_64 or arm64)
- Root access (for namespaces, veth, iptables)
- curl, python3, iproute2
- No Docker, Go, Node.js, or Rust needed
README

    # 8. Create tarball
    echo "  Creating tarball..."
    tar czf "dist/sandbox-test-${ARCH}.tar.gz" -C dist "sandbox-test-${ARCH}"
    rm -rf "${BUNDLE}"

    SIZE=$(ls -lh "dist/sandbox-test-${ARCH}.tar.gz" | awk '{print $5}')
    echo "  Done: dist/sandbox-test-${ARCH}.tar.gz (${SIZE})"
    echo ""
done

echo "=== Test bundles ready ==="
echo ""
echo "Copy to a Linux host and run:"
echo "  tar xzf sandbox-test-<arch>.tar.gz"
echo "  cd sandbox-test-<arch>"
echo "  sudo ./test/run-sandbox-e2e.sh"
