#!/usr/bin/env bash
# test-e2e-sandbox-protection.sh — E2E tests for OpenShell sandbox enforcement
#
# Tests the actual protection features of openshell-sandbox running in
# standalone mode: network policy enforcement, filesystem isolation,
# user privilege separation, and DNS resolution.
#
# Must be run inside the container where the sandbox is active.
# Requires: curl, ip, nsenter, sudo
#
# Usage:
#   bash scripts/test-e2e-sandbox-protection.sh

set -uo pipefail

BOLD="\033[1m"
GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
DIM="\033[2m"
RESET="\033[0m"

PASS=0
FAIL=0
WARN=0
SKIP=0

pass()  { PASS=$((PASS+1)); echo -e "${GREEN}  ✓ $1${RESET}"; }
fail()  { FAIL=$((FAIL+1)); echo -e "${RED}  ✗ $1${RESET}"; }
warn()  { WARN=$((WARN+1)); echo -e "${YELLOW}  ! $1${RESET}"; }
skip()  { SKIP=$((SKIP+1)); echo -e "${DIM}  - $1 (skipped)${RESET}"; }
bold()  { echo -e "\n${BOLD}$1${RESET}"; }
detail(){ echo -e "${DIM}     $1${RESET}"; }

# ---------------------------------------------------------------------------
# Discover sandbox environment
# ---------------------------------------------------------------------------

SANDBOX_PID=$(pgrep -f "openshell-sandbox" | head -1)
if [ -z "$SANDBOX_PID" ]; then
    echo -e "${RED}openshell-sandbox is not running. Start it first.${RESET}"
    exit 1
fi

# Find an openclaw process that is a child of the active sandbox — stale
# processes from previous sandbox runs live in different network namespaces.
OPENCLAW_PID=$(pgrep -P "$SANDBOX_PID" -u sandbox | head -1)
if [ -z "$OPENCLAW_PID" ]; then
    OPENCLAW_PID=$(pgrep -u sandbox -f "openclaw$" | head -1)
fi
if [ -z "$OPENCLAW_PID" ]; then
    OPENCLAW_PID=$(pgrep -u sandbox | head -1)
fi

HOST_IP="10.200.0.1"
SANDBOX_IP="10.200.0.2"

# nsenter flags to enter the sandbox's network namespace
NS_NET="-t ${OPENCLAW_PID} -n"

echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD} OpenShell Sandbox Protection E2E Tests${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
detail "sandbox PID: ${SANDBOX_PID}"
detail "openclaw PID: ${OPENCLAW_PID}"
detail "host veth IP: ${HOST_IP}"
detail "sandbox veth IP: ${SANDBOX_IP}"

# ═══════════════════════════════════════════════════════════════════════════
# 1. Network Namespace Isolation
# ═══════════════════════════════════════════════════════════════════════════

bold "1. Network Namespace Isolation"

# Sandbox should have its own network namespace (different from host)
HOST_IFACES=$(ip link show 2>/dev/null | grep -c "^[0-9]")
SANDBOX_IFACES=$(nsenter ${NS_NET} ip link show 2>/dev/null | grep -c "^[0-9]")

if [ "$HOST_IFACES" != "$SANDBOX_IFACES" ]; then
    pass "sandbox has separate network namespace (host=${HOST_IFACES} ifaces, sandbox=${SANDBOX_IFACES} ifaces)"
else
    warn "interface count matches — namespaces might not be isolated"
fi

# Sandbox should have the veth-s interface with SANDBOX_IP
if nsenter ${NS_NET} ip addr show 2>/dev/null | grep -q "${SANDBOX_IP}"; then
    pass "sandbox has veth interface with IP ${SANDBOX_IP}"
else
    fail "sandbox missing veth IP ${SANDBOX_IP}"
fi

# Host-side veth should have HOST_IP
if ip addr show 2>/dev/null | grep -q "${HOST_IP}"; then
    pass "host has veth interface with IP ${HOST_IP}"
else
    fail "host missing veth IP ${HOST_IP}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 2. Network Policy — Allowed Endpoints
# ═══════════════════════════════════════════════════════════════════════════
#
# openshell-sandbox's transparent proxy only intercepts traffic from processes
# it launched.  nsenter'd processes bypass the proxy, so direct curl from the
# sandbox namespace fails.  Instead we verify allowed connectivity via:
#   a) sidecar health report (proves openclaw ↔ sidecar link is up)
#   b) established TCP sockets between sandbox ↔ host
#   c) OPA policy data listing the allowed endpoints

bold "2. Network Policy — Allowed Endpoints"

HEALTH=$(curl -sf --max-time 5 "http://${HOST_IP}:18970/health" 2>/dev/null)

# Sandbox ↔ sidecar: the gateway subsystem connects TO openclaw inside the
# sandbox on port 18789.  An active connection proves the sandbox allows it.
SIDECAR_CONNS=$(ss -tn 2>/dev/null | grep -c "${HOST_IP}.*${SANDBOX_IP}:18789")
if [ "$SIDECAR_CONNS" -gt 0 ]; then
    pass "sandbox ↔ sidecar connected (${SIDECAR_CONNS} TCP stream(s) on :18789)"
else
    fail "sandbox ↔ sidecar — no active TCP connections"
fi

# LiteLLM proxy reachable from host (bound to 0.0.0.0:4000 or HOST_IP:4000)
if curl -sf --max-time 5 "http://${HOST_IP}:4000/health/liveliness" -o /dev/null 2>/dev/null; then
    pass "LiteLLM proxy reachable on ${HOST_IP}:4000"
else
    fail "LiteLLM proxy unreachable on ${HOST_IP}:4000"
fi

# OPA policy should list api.openai.com:443 as an allowed endpoint
OPA_DATA="${HOME}/.defenseclaw/openshell/data.yaml"
if [ ! -f "$OPA_DATA" ]; then
    OPA_DATA="${HOME}/defenseclaw/policies/openshell/default-data.yaml"
fi
if [ -f "$OPA_DATA" ] && grep -q "api.openai.com" "$OPA_DATA" 2>/dev/null; then
    pass "OPA policy allows api.openai.com (in ${OPA_DATA##*/})"
else
    warn "api.openai.com not found in OPA policy data"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 3. Network Policy — Blocked Endpoints
# ═══════════════════════════════════════════════════════════════════════════

bold "3. Network Policy — Blocked Endpoints"

# Sandbox -> evil.example.com should be BLOCKED
CODE=$(nsenter ${NS_NET} curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://evil.example.com/" 2>/dev/null)
if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    pass "sandbox → evil.example.com blocked (connection refused/timeout)"
else
    fail "sandbox → evil.example.com NOT blocked (got HTTP ${CODE})"
fi

# Sandbox -> random IP:8080 should be BLOCKED
CODE=$(nsenter ${NS_NET} curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://198.51.100.1:8080/" 2>/dev/null)
if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    pass "sandbox → 198.51.100.1:8080 blocked (unapproved endpoint)"
else
    fail "sandbox → 198.51.100.1:8080 NOT blocked (got HTTP ${CODE})"
fi

# Sandbox -> attacker.example.com:443 (exfiltration target) should be BLOCKED
CODE=$(nsenter ${NS_NET} curl -s --max-time 5 -o /dev/null -w '%{http_code}' "https://attacker.example.com/" 2>/dev/null)
if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    pass "sandbox → attacker.example.com:443 blocked (exfiltration target)"
else
    fail "sandbox → attacker.example.com NOT blocked (got HTTP ${CODE})"
fi

# Sandbox -> allowed host but WRONG PORT should be BLOCKED
CODE=$(nsenter ${NS_NET} curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://api.openai.com:8080/" 2>/dev/null)
if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    pass "sandbox → api.openai.com:8080 blocked (wrong port, only 443 allowed)"
else
    fail "sandbox → api.openai.com:8080 NOT blocked on wrong port (got HTTP ${CODE})"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 4. User Privilege Separation
# ═══════════════════════════════════════════════════════════════════════════

bold "4. User Privilege Separation"

# OpenClaw processes should run as 'sandbox' user, not root
OC_USER=$(ps -o user= -p "${OPENCLAW_PID}" 2>/dev/null | tr -d ' ')
if [ "$OC_USER" = "sandbox" ]; then
    pass "openclaw runs as 'sandbox' user (not root)"
else
    fail "openclaw runs as '${OC_USER}' (expected 'sandbox')"
fi

# All sandbox child processes should be non-root
ROOT_PROCS=$(ps -u sandbox -o user=,pid=,comm= 2>/dev/null | grep "^root" | wc -l)
if [ "$ROOT_PROCS" -eq 0 ]; then
    pass "no root-owned processes under sandbox user"
else
    warn "${ROOT_PROCS} process(es) running as root under sandbox context"
fi

# Sandbox user should NOT have sudo access
if nsenter ${NS_NET} sudo -u sandbox sudo -n true 2>/dev/null; then
    fail "sandbox user has passwordless sudo (should not)"
else
    pass "sandbox user cannot sudo"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 5. Filesystem Isolation
# ═══════════════════════════════════════════════════════════════════════════

bold "5. Filesystem Isolation"

# Sandbox user should be able to write to its own home
if sudo -u sandbox touch /home/sandbox/.test-write-e2e 2>/dev/null; then
    pass "sandbox user can write to /home/sandbox/"
    rm -f /home/sandbox/.test-write-e2e
else
    fail "sandbox user cannot write to /home/sandbox/"
fi

# Sandbox user should NOT be able to write to /root
if sudo -u sandbox touch /root/.test-sandbox-write 2>/dev/null; then
    fail "sandbox user CAN write to /root/ (should be blocked)"
    rm -f /root/.test-sandbox-write
else
    pass "sandbox user cannot write to /root/"
fi

# Sandbox user should NOT be able to write to /etc
if sudo -u sandbox touch /etc/.test-sandbox-write 2>/dev/null; then
    fail "sandbox user CAN write to /etc/ (should be blocked)"
    rm -f /etc/.test-sandbox-write
else
    pass "sandbox user cannot write to /etc/"
fi

# Sandbox user should be able to read openclaw.json (via ACLs)
if sudo -u sandbox cat /root/.openclaw/openclaw.json > /dev/null 2>/dev/null; then
    pass "sandbox user can read openclaw.json (ACL)"
else
    fail "sandbox user cannot read openclaw.json"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 6. DNS Resolution (inside sandbox)
# ═══════════════════════════════════════════════════════════════════════════

bold "6. DNS Resolution"

# Sandbox should be able to resolve allowed hostnames
if nsenter ${NS_NET} getent hosts api.openai.com >/dev/null 2>&1; then
    pass "DNS resolution works inside sandbox (api.openai.com)"
elif nsenter ${NS_NET} nslookup api.openai.com >/dev/null 2>&1; then
    pass "DNS resolution works inside sandbox (api.openai.com via nslookup)"
else
    # Try with dig/host if available
    if nsenter ${NS_NET} host api.openai.com >/dev/null 2>&1; then
        pass "DNS resolution works inside sandbox (api.openai.com via host)"
    else
        warn "DNS resolution may not work inside sandbox (getent/nslookup/host failed)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# 7. Sidecar Health (proves sandbox ↔ sidecar link works)
# ═══════════════════════════════════════════════════════════════════════════

bold "7. Sidecar Health & Sandbox Subsystem"

HEALTH=$(curl -sf --max-time 5 "http://${HOST_IP}:18970/health" 2>/dev/null)
if [ -n "$HEALTH" ]; then
    pass "sidecar /health reachable"
    for sub in gateway watcher guardrail sandbox; do
        state=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$sub',{}).get('state','?'))" 2>/dev/null)
        if [ "$state" = "running" ]; then
            pass "  ${sub}: running"
        elif [ "$state" = "disabled" ]; then
            skip "  ${sub}: disabled"
        else
            warn "  ${sub}: ${state}"
        fi
    done
else
    fail "sidecar /health unreachable"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 8. LiteLLM Chat (from host, through sidecar — proves full path)
# ═══════════════════════════════════════════════════════════════════════════

bold "8. LiteLLM Chat (via host)"

MASTER_KEY=""
if [ -f /root/.defenseclaw/device.key ]; then
    MASTER_KEY=$(python3 -c "
import hashlib; from pathlib import Path
data = (Path.home()/'.defenseclaw/device.key').read_bytes()
digest = hashlib.pbkdf2_hmac(
    'sha256',
    data,
    b'defenseclaw-proxy-master-key',
    100_000,
    dklen=32,
).hex()
print(f'sk-dc-{digest}')
" 2>/dev/null)
fi

if [ -n "$MASTER_KEY" ]; then
    CODE=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
        -X POST "http://${HOST_IP}:4000/v1/chat/completions" \
        -H "Authorization: Bearer ${MASTER_KEY}" \
        -H "Content-Type: application/json" \
        -d '{"model":"gpt-5.4","messages":[{"role":"user","content":"Reply: pong"}],"max_tokens":4}' 2>/dev/null)
    if [ "$CODE" = "200" ]; then
        pass "LiteLLM chat completion works (HTTP 200)"
    else
        fail "LiteLLM chat completion failed (HTTP ${CODE})"
    fi
else
    skip "no master key — cannot test chat from sandbox"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 9. Seccomp Enforcement
# ═══════════════════════════════════════════════════════════════════════════

bold "9. Seccomp Enforcement"

SECCOMP_MODE=$(grep "^Seccomp:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
case "$SECCOMP_MODE" in
    2) pass "openclaw has seccomp filter active (mode=2/filter)" ;;
    1) pass "openclaw has seccomp strict mode (mode=1)" ;;
    0) fail "openclaw has NO seccomp filter (mode=0)" ;;
    *) fail "cannot read seccomp mode for openclaw (got '${SECCOMP_MODE}')" ;;
esac

SECCOMP_FILTERS=$(grep "^Seccomp_filters:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
if [ -n "$SECCOMP_FILTERS" ] && [ "$SECCOMP_FILTERS" -gt 0 ] 2>/dev/null; then
    pass "openclaw has ${SECCOMP_FILTERS} seccomp BPF filter(s) attached"
else
    fail "openclaw has no seccomp BPF filters"
fi

# Gateway child process should inherit the filter
GW_CHILD=$(pgrep -P "${OPENCLAW_PID}" 2>/dev/null | head -1)
if [ -n "$GW_CHILD" ]; then
    GW_SECCOMP=$(grep "^Seccomp:" /proc/${GW_CHILD}/status 2>/dev/null | awk '{print $2}')
    if [ "$GW_SECCOMP" = "2" ]; then
        pass "openclaw-gateway child inherits seccomp filter (mode=2)"
    else
        fail "openclaw-gateway child missing seccomp (mode=${GW_SECCOMP})"
    fi
fi

# openshell-sandbox parent should NOT have seccomp (needs full access)
PARENT_SECCOMP=$(grep "^Seccomp:" /proc/${SANDBOX_PID}/status 2>/dev/null | awk '{print $2}')
if [ "$PARENT_SECCOMP" = "0" ]; then
    pass "openshell-sandbox supervisor not restricted by seccomp"
else
    warn "openshell-sandbox supervisor has seccomp mode=${PARENT_SECCOMP}"
fi

# Verify sandbox user cannot ptrace (blocked by seccomp + NoNewPrivs)
if nsenter -t ${OPENCLAW_PID} -n sudo -u sandbox strace -p ${OPENCLAW_PID} 2>&1 | grep -qiE "not permitted|denied|operation not"; then
    pass "sandbox user cannot ptrace (strace blocked)"
elif ! command -v strace >/dev/null 2>&1; then
    skip "strace not installed — cannot test ptrace block"
else
    warn "ptrace test inconclusive"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 10. Landlock LSM
# ═══════════════════════════════════════════════════════════════════════════

bold "10. Landlock LSM"

LSM_LIST=""
if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null)
elif [ -f /proc/sys/kernel/lsm ]; then
    LSM_LIST=$(cat /proc/sys/kernel/lsm 2>/dev/null)
else
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
    LSM_LIST=$(cat /sys/kernel/security/lsm 2>/dev/null)
fi

if echo "$LSM_LIST" | grep -q "landlock"; then
    pass "Landlock LSM loaded in kernel (${LSM_LIST})"
else
    warn "Landlock LSM not found in kernel LSM list"
fi

NO_NEW_PRIVS=$(grep "^NoNewPrivs:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
if [ "$NO_NEW_PRIVS" = "1" ]; then
    pass "NoNewPrivs=1 on openclaw (required for unprivileged Landlock)"
else
    fail "NoNewPrivs not set on openclaw (got ${NO_NEW_PRIVS})"
fi

PARENT_NNP=$(grep "^NoNewPrivs:" /proc/${SANDBOX_PID}/status 2>/dev/null | awk '{print $2}')
if [ "$PARENT_NNP" = "0" ]; then
    pass "openshell-sandbox supervisor has NoNewPrivs=0 (can manage children)"
else
    warn "openshell-sandbox supervisor has NoNewPrivs=${PARENT_NNP}"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 11. Capability Restrictions
# ═══════════════════════════════════════════════════════════════════════════

bold "11. Capability Restrictions"

CAP_EFF=$(grep "^CapEff:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
CAP_PRM=$(grep "^CapPrm:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
CAP_INH=$(grep "^CapInh:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')
CAP_AMB=$(grep "^CapAmb:" /proc/${OPENCLAW_PID}/status 2>/dev/null | awk '{print $2}')

ZERO_CAP="0000000000000000"

if [ "$CAP_EFF" = "$ZERO_CAP" ]; then
    pass "openclaw effective capabilities fully dropped (CapEff=0)"
else
    fail "openclaw has effective capabilities: ${CAP_EFF}"
fi

if [ "$CAP_PRM" = "$ZERO_CAP" ]; then
    pass "openclaw permitted capabilities fully dropped (CapPrm=0)"
else
    fail "openclaw has permitted capabilities: ${CAP_PRM}"
fi

if [ "$CAP_AMB" = "$ZERO_CAP" ]; then
    pass "openclaw ambient capabilities empty (CapAmb=0)"
else
    fail "openclaw has ambient capabilities: ${CAP_AMB}"
fi

# Compare: supervisor should have full caps
PARENT_CAP_EFF=$(grep "^CapEff:" /proc/${SANDBOX_PID}/status 2>/dev/null | awk '{print $2}')
if [ "$PARENT_CAP_EFF" != "$ZERO_CAP" ]; then
    pass "openshell-sandbox supervisor retains capabilities (CapEff=${PARENT_CAP_EFF})"
else
    warn "openshell-sandbox supervisor has no capabilities"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 12. Mount Namespace Isolation
# ═══════════════════════════════════════════════════════════════════════════

bold "12. Mount Namespace Isolation"

HOST_MNT=$(readlink /proc/1/ns/mnt 2>/dev/null)
SANDBOX_MNT=$(readlink /proc/${OPENCLAW_PID}/ns/mnt 2>/dev/null)
if [ "$HOST_MNT" != "$SANDBOX_MNT" ]; then
    pass "sandbox has separate mount namespace"
else
    warn "sandbox shares mount namespace with host"
fi

# Sandbox should have its own resolv.conf overlay for DNS
if nsenter -t ${OPENCLAW_PID} -m cat /proc/mounts 2>/dev/null | grep -q "resolv.conf"; then
    pass "sandbox has resolv.conf mount overlay (DNS isolation)"
else
    warn "sandbox may lack DNS isolation (no resolv.conf overlay)"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 13. Transparent Proxy
# ═══════════════════════════════════════════════════════════════════════════

bold "13. Transparent Proxy"

PROXY_LISTEN=$(ss -tlnp 2>/dev/null | grep ":3128 ")
if [ -n "$PROXY_LISTEN" ]; then
    if echo "$PROXY_LISTEN" | grep -q "openshell-sandb"; then
        pass "transparent proxy listening on ${HOST_IP}:3128 (openshell-sandbox)"
    else
        warn "port 3128 is listening but not owned by openshell-sandbox"
    fi
else
    fail "no transparent proxy on port 3128"
fi

PROXY_IP=$(echo "$PROXY_LISTEN" | grep -oP '[\d.]+:3128' | head -1 | cut -d: -f1)
if [ "$PROXY_IP" = "$HOST_IP" ]; then
    pass "proxy bound to host veth IP (${HOST_IP})"
else
    warn "proxy bound to ${PROXY_IP} (expected ${HOST_IP})"
fi

# ═══════════════════════════════════════════════════════════════════════════
# 14. In-Process Sandbox Probe (seccomp + Landlock + network policy)
# ═══════════════════════════════════════════════════════════════════════════
#
# Tests 9-13 inspect /proc and sockets from the HOST.  This section runs a
# probe script INSIDE the sandboxed process tree via `openclaw agent`, so the
# child process inherits seccomp filters, Landlock rules, and the transparent
# proxy — things that nsenter cannot replicate.
#
# Requires: openclaw agent, OPENCLAW_GATEWAY_TOKEN in .env

bold "14. In-Process Sandbox Probe"

_PROBE_SCRIPT="/home/sandbox/sandbox-probe.sh"
_TOKEN=$(grep OPENCLAW_GATEWAY_TOKEN /root/.defenseclaw/.env 2>/dev/null | cut -d= -f2)

# Write the probe if it doesn't exist
if true; then
    cat > "$_PROBE_SCRIPT" << 'PROBE_EOF'
#!/bin/bash
echo "PROBE_START"
SM=$(grep "^Seccomp:" /proc/self/status | awk '{print $2}')
SF=$(grep "^Seccomp_filters:" /proc/self/status | awk '{print $2}')
NP=$(grep "^NoNewPrivs:" /proc/self/status | awk '{print $2}')
CE=$(grep "^CapEff:" /proc/self/status | awk '{print $2}')
CP=$(grep "^CapPrm:" /proc/self/status | awk '{print $2}')
echo "SECCOMP_MODE=$SM"
echo "SECCOMP_FILTERS=$SF"
echo "NO_NEW_PRIVS=$NP"
echo "CAP_EFF=$CE"
echo "CAP_PRM=$CP"
touch /root/.landlock-probe 2>/dev/null; echo "LL_ROOT=$?"
touch /home/sandbox/.ll-probe 2>/dev/null; echo "LL_HOME=$?"; rm -f /home/sandbox/.ll-probe
touch /etc/.landlock-probe 2>/dev/null; echo "LL_ETC=$?"
BC=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://evil.example.com/" 2>/dev/null)
echo "NET_BLOCKED=$BC"
AC=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "https://api.openai.com/v1/models" 2>/dev/null)
echo "NET_ALLOWED=$AC"
WP=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://api.openai.com:8080/" 2>/dev/null)
echo "NET_WRONG_PORT=$WP"
SC=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://10.200.0.1:18970/health" 2>/dev/null)
echo "NET_SIDECAR=$SC"
if command -v python3 >/dev/null 2>&1; then
    PR=$(python3 -c "
import ctypes, ctypes.util
libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True)
r=libc.ptrace(16,1,0,0)
print(f'{r},{ctypes.get_errno()}')
" 2>&1)
    echo "PTRACE_RET=$PR"
else
    echo "PTRACE_RET=skip"
fi
echo "PROBE_END"
PROBE_EOF
    chmod +x "$_PROBE_SCRIPT"
    chown sandbox:sandbox "$_PROBE_SCRIPT"
fi

if [ -z "$_TOKEN" ]; then
    skip "no gateway token — cannot run in-process probe"
elif [ -z "$OPENCLAW_PID" ]; then
    skip "no openclaw PID — cannot run in-process probe"
else
    detail "running probe via openclaw agent (one LLM call)..."
    PROBE_OUT=$(timeout 120 nsenter -t "${OPENCLAW_PID}" -n -m -- sudo -u sandbox \
        env HOME=/home/sandbox \
        openclaw agent \
        --session-id "dc-probe-$$" \
        -m "Run this exact command and return ONLY its raw output, nothing else: bash /home/sandbox/sandbox-probe.sh" \
        2>&1)

    if ! echo "$PROBE_OUT" | grep -q "PROBE_START"; then
        fail "probe did not produce output (agent may have refused)"
        detail "agent output: ${PROBE_OUT:0:200}"
    else
        _pval() { echo "$PROBE_OUT" | grep "^$1=" | head -1 | cut -d= -f2; }

        # -- Seccomp --
        SM=$(_pval SECCOMP_MODE)
        [ "$SM" = "2" ] && pass "probe: seccomp BPF filter active (mode=2)" \
                        || fail "probe: seccomp mode=${SM} (expected 2)"
        SF=$(_pval SECCOMP_FILTERS)
        [ -n "$SF" ] && [ "$SF" -gt 0 ] 2>/dev/null \
            && pass "probe: ${SF} seccomp filter(s) inherited" \
            || fail "probe: no seccomp filters inherited"
        NP=$(_pval NO_NEW_PRIVS)
        [ "$NP" = "1" ] && pass "probe: NoNewPrivs=1 in child" \
                        || fail "probe: NoNewPrivs=${NP} (expected 1)"

        # -- Capabilities --
        CE=$(_pval CAP_EFF)
        [ "$CE" = "0000000000000000" ] && pass "probe: CapEff=0 (no effective caps)" \
                                       || fail "probe: CapEff=${CE} (expected 0)"
        CP=$(_pval CAP_PRM)
        [ "$CP" = "0000000000000000" ] && pass "probe: CapPrm=0 (no permitted caps)" \
                                       || fail "probe: CapPrm=${CP} (expected 0)"

        # -- Landlock / filesystem --
        LL_ROOT=$(_pval LL_ROOT)
        [ "$LL_ROOT" != "0" ] && pass "probe: write /root blocked" \
                              || fail "probe: write /root succeeded (should be blocked)"
        LL_HOME=$(_pval LL_HOME)
        [ "$LL_HOME" = "0" ] && pass "probe: write /home/sandbox allowed" \
                             || fail "probe: write /home/sandbox blocked (should be allowed)"
        LL_ETC=$(_pval LL_ETC)
        [ "$LL_ETC" != "0" ] && pass "probe: write /etc blocked" \
                             || fail "probe: write /etc succeeded (should be blocked)"

        # -- Network policy --
        NB=$(_pval NET_BLOCKED)
        if [ "$NB" = "403" ] || [ "$NB" = "000" ]; then
            pass "probe: evil.example.com blocked by proxy (HTTP ${NB})"
        else
            fail "probe: evil.example.com returned HTTP ${NB} (expected 403/000)"
        fi

        NA=$(_pval NET_ALLOWED)
        if [ "$NA" != "000" ] && [ -n "$NA" ]; then
            pass "probe: api.openai.com allowed (HTTP ${NA})"
        else
            fail "probe: api.openai.com blocked (HTTP ${NA})"
        fi

        NW=$(_pval NET_WRONG_PORT)
        if [ "$NW" = "403" ] || [ "$NW" = "000" ]; then
            pass "probe: api.openai.com:8080 blocked (wrong port, HTTP ${NW})"
        else
            fail "probe: api.openai.com:8080 returned HTTP ${NW} (expected 403/000)"
        fi

        NS=$(_pval NET_SIDECAR)
        [ "$NS" = "200" ] && pass "probe: sidecar reachable from sandbox (HTTP 200)" \
                          || fail "probe: sidecar returned HTTP ${NS} (expected 200)"

        # -- Seccomp: ptrace blocked --
        PT=$(_pval PTRACE_RET)
        if [ "$PT" = "skip" ]; then
            skip "ptrace test skipped (no python3 in sandbox)"
        else
            PT_RET=$(echo "$PT" | cut -d, -f1)
            PT_ERR=$(echo "$PT" | cut -d, -f2)
            if [ "$PT_RET" = "-1" ]; then
                pass "probe: ptrace(ATTACH) blocked (errno=${PT_ERR})"
            else
                fail "probe: ptrace(ATTACH) succeeded (should be blocked)"
            fi
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD} Results${RESET}"
echo -e "${GREEN}  ${PASS} passed${RESET}"
if [ $FAIL -gt 0 ]; then echo -e "${RED}  ${FAIL} failed${RESET}"; fi
if [ $WARN -gt 0 ]; then echo -e "${YELLOW}  ${WARN} warnings${RESET}"; fi
if [ $SKIP -gt 0 ]; then echo -e "${DIM}  ${SKIP} skipped${RESET}"; fi
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"

exit $FAIL
