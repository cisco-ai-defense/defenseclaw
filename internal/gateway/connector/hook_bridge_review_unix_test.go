// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeBridgeReviewHelper(t *testing.T, dir string) string {
	t.Helper()
	body, err := hookFS.ReadFile("hooks/_hardening.sh")
	if baseline := os.Getenv("DC_REVIEW_BASE_HARDENING"); baseline != "" {
		body, err = os.ReadFile(baseline)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A long-lived gateway leaves thousands of TIME_WAIT rows in /proc/net/tcp.
// The ownership probe must not spend a tool-call deadline parsing them in Bash.
func TestShellListenerProbeStaysFastWithExpiredConnections(t *testing.T) {
	dir := t.TempDir()
	netDir := filepath.Join(dir, "net")
	if err := os.Mkdir(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	old := "   0: 0100007F:4A10 00000000:0000 06 00000000:00000000 00:00000000 00000000 1000 0 4242\n"
	listener := "   0: 0100007F:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 " +
		strconv.Itoa(os.Getuid()) + " 0 4243\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(header+strings.Repeat(old, 500_000)+listener), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", `set -euo pipefail; . "$1"; status=0
defenseclaw_api_listener_unproven 127.0.0.1:18960 "$2" || status=$?
printf '%s\n' "$status"`, "bash", helper, netDir)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("listener probe missed its three-second budget: output=%q error=%v context=%v", out, err, ctx.Err())
	}
}

// The tier can change as the audit row is written. All parts of one hook
// delivery must use the same resolved call-time decision.
func TestShellOutageLogAndVerdictUseOneTierSnapshot(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mode := filepath.Join(dir, "tier")
	if err := os.WriteFile(mode, []byte("open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then cat \"$DC_MODE_FILE\"; printf 'closed\\n' >\"$DC_MODE_FILE\"; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(filepath.Join(binDir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; DEFENSECLAW_HOME="$3"
DEFENSECLAW_HOOK_CONNECTOR=codex; _DC_TRANSPORT_STATUS=7; FAIL_MODE=closed
defenseclaw_log_hook_delivery_failure codex codex-hook "gateway unreachable" transport closed
if defenseclaw_should_fail_closed_on_unreachable; then printf 'block\n'; else printf 'allow\n'; fi`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir, dataDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DC_MODE_FILE="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "allow" {
		t.Fatalf("tier changed within one failure decision: output=%q err=%v", out, err)
	}
	rows := hookFailureRecords(t, dataDir)
	if len(rows) != 1 || rows[0]["outcome"] != "fail_open" || rows[0]["fail_mode"] != "open" {
		t.Fatalf("audit did not match allowed call: %+v", rows)
	}
}

func TestShellOutageWarningIsOncePerSessionAcrossHookProcesses(t *testing.T) {
	dir := t.TempDir()
	hookDir := filepath.Join(dir, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; DEFENSECLAW_HOME="$3"
DEFENSECLAW_HOOK_CONNECTOR=hermes; _DC_TRANSPORT_STATUS=7; _DC_CONFIG_OUTAGE_MODE=open; FAIL_MODE=closed
PAYLOAD='{"session_id":"same-session","tool_call_id":"call"}'
defenseclaw_emit_unreachable_stderr tool "gateway unreachable"`
	for i := 0; i < 2; i++ {
		cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir, filepath.Dir(hookDir))
		cmd.Env = append(sanitizedTestEnv(), "HOME="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("call %d: %v: %s", i, err, out)
		}
		warned := strings.Contains(string(out), "fail mode open for an outage")
		if warned != (i == 0) {
			t.Fatalf("call %d warned=%v: %q", i, warned, out)
		}
	}
}

func TestShellFailureAuditKeepsSessionAndCall(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; DEFENSECLAW_HOME="$2"
PAYLOAD='{"sessionId":"session-1","callID":"call-1"}'
defenseclaw_log_hook_failure codex codex-hook 'gateway unreachable' transport open fail_open`
	cmd := exec.Command("bash", "-c", script, "bash", helper, dataDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failure logger: %v: %s", err, out)
	}
	rows := hookFailureRecords(t, dataDir)
	if len(rows) != 1 || rows[0]["session_id"] != "session-1" || rows[0]["call_id"] != "call-1" {
		t.Fatalf("audit correlation missing: %+v", rows)
	}
}

func writeBridgeReviewBinary(t *testing.T, home, action string) {
	t.Helper()
	dir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\ncat >/dev/null\nprintf '{\"action\":\"" + action + "\"}\\n200'\n"
	if action == "exit1" {
		body = "#!/bin/sh\ncat >/dev/null\nexit 1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "defenseclaw-gateway"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	hooks := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".gateway-helper"), []byte(filepath.Join(dir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The agent's inherited HOME cannot select the executable that receives the
// bearer. The hook's installed directory identifies the account instead.
func TestShellBridgeIgnoresAgentHomeForPostHelper(t *testing.T) {
	dir := t.TempDir()
	trusted, attacker := filepath.Join(dir, "account"), filepath.Join(dir, "agent-home")
	writeBridgeReviewBinary(t, trusted, "block")
	writeBridgeReviewBinary(t, attacker, "allow")
	// The hook data directory is writable by this account. A planted helper
	// beneath it is not the account's installed ~/.local/bin helper either.
	writeBridgeReviewBinary(t, filepath.Join(trusted, ".defenseclaw"), "allow")
	hookDir := filepath.Join(trusted, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' -H 'Authorization: Bearer example'`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+attacker, "DEFENSECLAW_AGENT_HOME="+attacker)
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "{\"action\":\"block\"}\n200" {
		t.Fatalf("bridge selected an untrusted helper: output=%q err=%v", out, err)
	}
}

// A valid-looking account binary cannot become the hook's helper unless
// setup recorded its absolute path next to the installed hook. The record
// also has to be private and point at a private regular executable.
func TestShellBridgeRequiresPrivateInstalledHelperRecord(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	writeBridgeReviewBinary(t, home, "block")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	record := filepath.Join(hookDir, ".gateway-helper")
	bin := filepath.Join(home, ".local", "bin", "defenseclaw-gateway")
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	probe := func() (string, error) {
		cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' -H 'Authorization: Bearer example'`, "bash", helper, hookDir)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := probe(); err == nil || strings.Contains(out, `"action":"block"`) {
		t.Fatalf("missing install record executed a helper: out=%q err=%v", out, err)
	}
	if err := os.WriteFile(record, []byte(bin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := probe(); err != nil || out != "{\"action\":\"block\"}\n200" {
		t.Fatalf("private installed helper was not used: out=%q err=%v", out, err)
	}
	if err := os.Chmod(record, 0o666); err != nil {
		t.Fatal(err)
	}
	if out, err := probe(); err == nil || strings.Contains(out, `"action":"block"`) {
		t.Fatalf("writable install record executed a helper: out=%q err=%v", out, err)
	}
}

// A cut-off answer has already been classified by hook-post. A later port
// probe cannot turn its non-outage failure into status 7.
func TestShellBridgeKeepsClassifiedHelperFailure(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	writeBridgeReviewBinary(t, home, "exit1")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
probe=0
defenseclaw_api_listener_unproven() { probe=$((probe + 1)); if [ "$probe" -eq 1 ]; then return 1; fi; return 2; }
status=0; defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' -H 'Authorization: Bearer example' >/dev/null || status=$?
printf '%s\n' "$status"`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("classified helper failure changed to outage: output=%q err=%v", out, err)
	}
}

// The number of headers must not multiply shell process launches. This
// counts the external encoders and metadata probes added to the POST path.
func TestShellBridgeHeaderCountDoesNotForkPerField(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	writeBridgeReviewBinary(t, home, "allow")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	wrapperDir := filepath.Join(dir, "wrappers")
	for _, path := range []string{hookDir, wrapperDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "processes")
	for _, name := range []string{"sed", "tr", "stat"} {
		actual, err := exec.LookPath(name)
		if err != nil {
			t.Skip(name + " unavailable")
		}
		wrapper := "#!/bin/sh\nprintf '%s\\n' " + name + " >>\"$DC_PROCESS_MARKER\"\nexec '" + actual + "' \"$@\"\n"
		if err := os.WriteFile(filepath.Join(wrapperDir, name), []byte(wrapper), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' \
  -H 'Content-Type: application/json' -H 'X-First: one' -H 'X-Second: two' \
  -H 'X-Third: three' -H 'X-Fourth: four' -H 'X-Fifth: five' \
  -H 'Authorization: Bearer example' >/dev/null`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home,
		"PATH="+wrapperDir+":"+os.Getenv("PATH"), "DC_PROCESS_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bridge failed: %v\n%s", err, out)
	}
	launches, err := os.ReadFile(marker)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if n := len(strings.Fields(string(launches))); n > 3 {
		t.Fatalf("bridge launched %d tr/sed/stat processes for one call: %s", n, launches)
	}
}

// GNU stat takes -c and BSD stat (macOS) takes -f. The hooks learn the
// spelling once per process: a stat that refuses -c costs one failed launch,
// not one per check (GAP-1755). The fake stat below behaves like BSD stat on
// any runner, so the class is proven on Linux as well as macOS.
func TestShellStatSpellingIsLearnedOncePerCall(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	writeBridgeReviewBinary(t, home, "allow")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	wrapperDir := filepath.Join(dir, "wrappers")
	for _, path := range []string{hookDir, wrapperDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := exec.LookPath("stat")
	if err != nil {
		t.Skip("stat unavailable")
	}
	marker := filepath.Join(dir, "spellings")
	wrapper := `#!/bin/bash
real='` + actual + `'
case "$1" in
  -c) printf 'c\n' >>"$DC_PROCESS_MARKER"; echo "stat: illegal option -- c" >&2; exit 1 ;;
  -f) printf 'f\n' >>"$DC_PROCESS_MARKER"; fmt="$2"; shift 2
      if "$real" --version >/dev/null 2>&1; then
        fmt="${fmt//%Lp/%a}"; fmt="${fmt//%m/%Y}"; exec "$real" -c "$fmt" "$@"
      fi
      exec "$real" -f "$fmt" "$@" ;;
esac
exec "$real" "$@"
`
	if err := os.WriteFile(filepath.Join(wrapperDir, "stat"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer example' >/dev/null`
	cmd := exec.Command("bash", "-c", script, "bash", helper, hookDir)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home,
		"PATH="+wrapperDir+":"+os.Getenv("PATH"), "DC_PROCESS_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bridge failed: %v\n%s", err, out)
	}
	launches, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("no stat ran: %v", err)
	}
	fields := strings.Fields(string(launches))
	refused := 0
	for _, f := range fields {
		if f == "c" {
			refused++
		}
	}
	if refused > 1 || len(fields) > 3 {
		t.Fatalf("stat ran %d times (%d refused -c) for one call, want the spelling learned once: %v", len(fields), refused, fields)
	}
}

// A ten-per-second stream must start just one bounded POST helper per hook
// process. No retry or header creates an accumulating bridge child.
func TestShellBridgeTenHertzHasOneHelperPerHookProcess(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "account")
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	binDir := filepath.Join(home, ".local", "bin")
	for _, path := range []string{hookDir, binDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "helper-pids")
	bin := "#!/bin/sh\nprintf '%s\\n' \"$$\" >>\"$DC_PROCESS_MARKER\"\nsleep 0.05\nprintf '{\\\"action\\\":\\\"allow\\\"}\\n200\\n'\n"
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(binary, []byte(bin), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(binary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := writeBridgeReviewHelper(t, dir)
	script := `set -euo pipefail; . "$1"; HOOK_DIR="$2"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{}' -H 'Authorization: Bearer example' >/dev/null`
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, "bash", "-c", script, "bash", helper, hookDir)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DC_PROCESS_MARKER="+marker)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("call %d: %v: %s", i, err, out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	pids, err := os.ReadFile(marker)
	if err != nil || len(strings.Fields(string(pids))) != 20 {
		t.Fatalf("bridge launches=%d, want 20 (one per call): %v", len(strings.Fields(string(pids))), err)
	}
}
