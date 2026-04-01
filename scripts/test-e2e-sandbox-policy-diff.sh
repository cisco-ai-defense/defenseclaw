#!/usr/bin/env bash
# test-e2e-sandbox-policy-diff.sh — E2E test for sandbox policy diff + mutation
#
# Exercises the "defenseclaw-gateway sandbox policy" command which compares
# the active openshell-sandbox network policy against endpoints required
# by the OpenClaw configuration (channels + model providers).
#
# No real sandbox is needed — this only tests DefenseClaw's own policy
# parsing, endpoint discovery, and diff logic running through the real
# binaries against real config files on disk.
#
# Flow:
#   1. defenseclaw init
#   2. Patch config.yaml for standalone mode
#   3. Write an openshell-policy.yaml with partial coverage
#   4. Write an openclaw.json with channels + providers
#   5. Run policy diff — expect MISSING endpoints
#   6. Patch policy to add the missing endpoints
#   7. Run policy diff — expect all covered
#   8. Remove an endpoint from the policy
#   9. Run policy diff — expect it reported as MISSING again
#
# Requirements: curl, jq, defenseclaw (Python CLI), defenseclaw-gateway (Go)

set -euo pipefail

GATEWAY="./defenseclaw-gateway"
DC="defenseclaw"
DC_DIR="${HOME}/.defenseclaw"
OC_DIR="${HOME}/.openclaw"
CONFIG_FILE="${DC_DIR}/config.yaml"
POLICY_FILE="${DC_DIR}/openshell-policy.yaml"
OC_CONFIG="${OC_DIR}/openclaw.json"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

pass()  { echo "  ✓  $*"; }
fail()  { echo "  ✗  $*" >&2; exit 1; }
step()  { echo; echo "=== $* ==="; }
info()  { echo "  →  $*"; }

cleanup() {
    :
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Prereq checks
# --------------------------------------------------------------------------

step "Prereq checks"
[ -f "${GATEWAY}" ]                    || fail "Gateway binary not found at ${GATEWAY} — run 'make gateway' first."
command -v "${DC}" >/dev/null 2>&1     || fail "'${DC}' CLI not found — run 'make install' or 'make dev-install' first."
command -v jq >/dev/null 2>&1          || fail "jq is required"
pass "all prereqs met"

# --------------------------------------------------------------------------
# Step 1 — Init
# --------------------------------------------------------------------------

step "Step 1 — Clean init"
rm -rf "${DC_DIR}"
${DC} init
[ -f "${CONFIG_FILE}" ] || fail "config.yaml not created by init"
pass "defenseclaw initialized"

# --------------------------------------------------------------------------
# Step 2 — Patch config for standalone mode
# --------------------------------------------------------------------------

step "Step 2 — Enable standalone sandbox mode in config"

python3 -c "
import yaml, sys
with open('${CONFIG_FILE}') as f:
    cfg = yaml.safe_load(f) or {}
cfg.setdefault('openshell', {})['mode'] = 'standalone'
cfg.setdefault('claw', {})['home_dir'] = '${OC_DIR}'
cfg.setdefault('claw', {})['config_file'] = '${OC_CONFIG}'
with open('${CONFIG_FILE}', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
"

info "openshell.mode set to 'standalone'"
info "claw.home_dir set to '${OC_DIR}'"
pass "config patched"

# --------------------------------------------------------------------------
# Step 3 — Write a PARTIAL openshell-policy.yaml
#           Cover telegram + slack, but NOT discord or anthropic.
# --------------------------------------------------------------------------

step "Step 3 — Write partial openshell-policy.yaml"

cat > "${POLICY_FILE}" << 'POLICY_EOF'
version: "1.0"
network_policies:
  - name: defenseclaw-sidecar
    endpoints:
      - host: "10.200.0.1"
        port: 18970
    binaries:
      - path: /**
  - name: telegram
    endpoints:
      - host: "**.telegram.org"
        port: 443
    binaries:
      - path: /**
  - name: slack
    endpoints:
      - host: "**.slack.com"
        port: 443
      - host: "hooks.slack.com"
        port: 443
    binaries:
      - path: /**
POLICY_EOF

info "policy covers: telegram, slack"
info "policy missing: discord, anthropic"
pass "partial policy written"

# --------------------------------------------------------------------------
# Step 4 — Write openclaw.json with channels + providers
# --------------------------------------------------------------------------

step "Step 4 — Write openclaw.json"
mkdir -p "${OC_DIR}"

cat > "${OC_CONFIG}" << 'OC_EOF'
{
  "channels": {
    "telegram": {},
    "slack": {},
    "discord": {}
  },
  "models": {
    "providers": {
      "anthropic": {
        "baseUrl": "https://api.anthropic.com/v1"
      },
      "litellm": {
        "baseUrl": "http://127.0.0.1:4000"
      }
    }
  }
}
OC_EOF

info "channels: telegram, slack, discord"
info "providers: anthropic (litellm skipped)"
pass "openclaw.json written"

# --------------------------------------------------------------------------
# Step 5 — Run policy diff — expect MISSING endpoints
# --------------------------------------------------------------------------

step "Step 5 — Policy diff (expect missing endpoints)"

DIFF_OUT=$("${GATEWAY}" sandbox policy diff 2>&1) || true

echo "${DIFF_OUT}"

if echo "${DIFF_OUT}" | grep -q "MISSING"; then
    pass "diff correctly reports MISSING endpoints"
else
    fail "diff should have reported MISSING endpoints"
fi

if echo "${DIFF_OUT}" | grep -q "**.discord.com"; then
    pass "discord endpoint flagged as MISSING"
else
    fail "**.discord.com should be in the diff output"
fi

if echo "${DIFF_OUT}" | grep -q "api.anthropic.com"; then
    pass "anthropic endpoint flagged as MISSING"
else
    fail "api.anthropic.com should be in the diff output"
fi

# Telegram and slack should be covered
if echo "${DIFF_OUT}" | grep "**.telegram.org" | grep -q "covered"; then
    pass "telegram endpoint is covered"
else
    fail "**.telegram.org should be covered"
fi

if echo "${DIFF_OUT}" | grep "**.slack.com" | grep -q "covered"; then
    pass "slack endpoint is covered"
else
    fail "**.slack.com should be covered"
fi

MISSING_COUNT=$(echo "${DIFF_OUT}" | grep -c "MISSING" || true)
info "${MISSING_COUNT} endpoint(s) reported as MISSING"

# --------------------------------------------------------------------------
# Step 6 — Add the missing endpoints to the policy
# --------------------------------------------------------------------------

step "Step 6 — Patch policy to add missing endpoints"

cat > "${POLICY_FILE}" << 'POLICY_EOF'
version: "1.0"
network_policies:
  - name: defenseclaw-sidecar
    endpoints:
      - host: "10.200.0.1"
        port: 18970
    binaries:
      - path: /**
  - name: telegram
    endpoints:
      - host: "**.telegram.org"
        port: 443
    binaries:
      - path: /**
  - name: slack
    endpoints:
      - host: "**.slack.com"
        port: 443
      - host: "hooks.slack.com"
        port: 443
    binaries:
      - path: /**
  - name: discord
    endpoints:
      - host: "**.discord.com"
        port: 443
      - host: "gateway.discord.gg"
        port: 443
    binaries:
      - path: /**
  - name: anthropic
    endpoints:
      - host: "api.anthropic.com"
        port: 443
    binaries:
      - path: /**
POLICY_EOF

info "added discord + anthropic endpoints"
pass "policy updated"

# --------------------------------------------------------------------------
# Step 7 — Run policy diff — expect all covered
# --------------------------------------------------------------------------

step "Step 7 — Policy diff (expect all covered)"

DIFF_OUT=$("${GATEWAY}" sandbox policy diff 2>&1) || true

echo "${DIFF_OUT}"

if echo "${DIFF_OUT}" | grep -q "MISSING"; then
    fail "all endpoints should be covered but diff still reports MISSING"
fi

if echo "${DIFF_OUT}" | grep -q "All discovered endpoints are covered"; then
    pass "all endpoints covered"
else
    fail "expected 'All discovered endpoints are covered' message"
fi

# --------------------------------------------------------------------------
# Step 8 — Remove an endpoint (simulate drift / manual edit)
# --------------------------------------------------------------------------

step "Step 8 — Remove anthropic endpoint from policy"

python3 -c "
import yaml
with open('${POLICY_FILE}') as f:
    pol = yaml.safe_load(f)
pol['network_policies'] = [
    e for e in pol['network_policies']
    if e.get('name') != 'anthropic'
]
with open('${POLICY_FILE}', 'w') as f:
    yaml.dump(pol, f, default_flow_style=False)
"

info "removed anthropic entry from policy"
pass "policy mutated"

# --------------------------------------------------------------------------
# Step 9 — Run policy diff — expect anthropic MISSING again
# --------------------------------------------------------------------------

step "Step 9 — Policy diff (expect anthropic missing)"

DIFF_OUT=$("${GATEWAY}" sandbox policy diff 2>&1) || true

echo "${DIFF_OUT}"

if echo "${DIFF_OUT}" | grep "api.anthropic.com" | grep -q "MISSING"; then
    pass "anthropic correctly reported as MISSING after removal"
else
    fail "api.anthropic.com should be MISSING after removal"
fi

# discord should still be covered
if echo "${DIFF_OUT}" | grep "**.discord.com" | grep -q "covered"; then
    pass "discord still covered (unaffected by anthropic removal)"
else
    fail "discord should still be covered"
fi

# --------------------------------------------------------------------------
# Step 10 — Edge case: empty channels / no providers
# --------------------------------------------------------------------------

step "Step 10 — Edge case: no channels or providers in openclaw.json"

cat > "${OC_CONFIG}" << 'OC_EOF'
{
  "agents": {
    "defaults": {
      "model": { "primary": "litellm/claude-sonnet" }
    }
  }
}
OC_EOF

DIFF_OUT=$("${GATEWAY}" sandbox policy diff 2>&1) || true

echo "${DIFF_OUT}"

if echo "${DIFF_OUT}" | grep -q "No required endpoints discovered"; then
    pass "empty config correctly reports no required endpoints"
else
    fail "expected 'No required endpoints discovered' for minimal openclaw.json"
fi

# --------------------------------------------------------------------------
# Step 11 — Edge case: missing openclaw.json
# --------------------------------------------------------------------------

step "Step 11 — Edge case: missing openclaw.json"

rm -f "${OC_CONFIG}"

DIFF_OUT=$("${GATEWAY}" sandbox policy diff 2>&1) || true

echo "${DIFF_OUT}"

if echo "${DIFF_OUT}" | grep -q "No required endpoints discovered"; then
    pass "missing openclaw.json correctly reports no required endpoints"
else
    fail "expected 'No required endpoints discovered' when openclaw.json is absent"
fi

# --------------------------------------------------------------------------
# Step 12 — Edge case: mode is NOT standalone
# --------------------------------------------------------------------------

step "Step 12 — Edge case: mode is not standalone"

python3 -c "
import yaml
with open('${CONFIG_FILE}') as f:
    cfg = yaml.safe_load(f)
cfg['openshell']['mode'] = ''
with open('${CONFIG_FILE}', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
"

if "${GATEWAY}" sandbox policy diff 2>&1; then
    fail "policy diff should fail when mode is not standalone"
else
    pass "policy diff correctly rejects non-standalone mode"
fi

# --------------------------------------------------------------------------
# Done
# --------------------------------------------------------------------------

echo
echo "=== All sandbox policy diff E2E tests passed ==="
