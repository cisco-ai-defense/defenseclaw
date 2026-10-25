// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-1260: while this account's gateway is not running, a hook sends no token
// to a loopback listener of another account on its API port.
func TestHookAPIListenerForeignNamesAnotherAccountsListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	row := func(addr string, uid int) string {
		return fmt.Sprintf("   0: %s:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 4242 1 0 100 0 0 10 0\n", addr, uid)
	}
	own := os.Getuid()
	for _, test := range []struct {
		name, host, tcp, tcp6 string
		running               bool
		want                  string
	}{
		{name: "another account on 127.0.0.1", tcp: row("0100007F", own+4242), want: "foreign"},
		{name: "another account on ::1 cannot serve IPv4", tcp6: row("00000000000000000000000001000000", own+4242), want: "free"},
		{name: "this account", tcp: row("0100007F", own), want: "send"},
		{name: "foreign peer on another loopback address cannot override own gateway", tcp: row("0100007F", own) + row("0200007F", own+4242), want: "send"},
		{name: "foreign peer on another loopback address cannot occupy free endpoint", tcp: row("0200007F", own+4242), want: "free"},
		{name: "another account on configured 127.0.0.2", host: "127.0.0.2", tcp: row("0200007F", own+4242), want: "foreign"},
		{name: "this account on configured 127.0.0.2", host: "127.0.0.2", tcp: row("0200007F", own), want: "send"},
		{name: "other loopback address cannot override configured 127.0.0.2", host: "127.0.0.2", tcp: row("0100007F", own+4242) + row("0200007F", own), want: "send"},
		{name: "foreign IPv4 wildcard", tcp: row("00000000", own+4242), want: "foreign"},
		{name: "own IPv4 wildcard", tcp: row("00000000", own), want: "send"},
		{name: "own IPv4 wildcard takes precedence over foreign IPv6-only wildcard", tcp: row("00000000", own), tcp6: row("00000000000000000000000000000000", own+4242), want: "send"},
		{name: "exact own IPv4 listener takes precedence over IPv6-only wildcard", tcp: row("0100007F", own), tcp6: row("00000000000000000000000000000000", own+4242), want: "send"},
		{name: "exact foreign IPv4 listener takes precedence over own wildcard", tcp: row("0100007F", own+4242) + row("00000000", own), want: "foreign"},
		{name: "foreign mapped configured address", tcp6: row("0000000000000000FFFF00000100007F", own+4242), want: "foreign"},
		{name: "foreign mapped other address", tcp6: row("0000000000000000FFFF00000200007F", own+4242), want: "free"},
		{name: "another address only", tcp: row("0500000A", own+4242), want: "free"},
		{name: "free port", want: "free"},
		{name: "own gateway running but listener foreign", tcp: row("0100007F", own+4242), running: true, want: "foreign"},
	} {
		t.Run(test.name, func(t *testing.T) {
			net := filepath.Join(t.TempDir(), "net")
			if err := os.Mkdir(net, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"tcp": header + test.tcp, "tcp6": header + test.tcp6} {
				if err := os.WriteFile(filepath.Join(net, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stopped := "return 0"
			if test.running {
				stopped = "return 1"
			}
			host := test.host
			if host == "" {
				host = "127.0.0.1"
			}
			script := `set -euo pipefail; . "$1"; defenseclaw_own_gateway_stopped() { ` + stopped + `; }
status=0; defenseclaw_api_listener_unproven "$3:18960" "$2" "$4" || status=$?
case "$status" in 0) echo foreign ;; 1) echo send ;; 2) echo free ;; *) echo unexpected ;; esac`
			out, err := exec.Command("bash", "-c", script, "bash", helper, net, host, filepath.Join(dir, "absent-lsof")).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != test.want {
				t.Fatalf("defenseclaw_api_listener_unproven = %q, want %q", got, test.want)
			}
		})
	}
}

// Every host hook checks the listener before its gateway request.
func TestHostHookGatewayPostNeverFallsBackToCurlForAForeignListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail; . "$1"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 0; }
curl() { echo leaked; }
if defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 'secret payload' -H 'Authorization: Bearer secret'; then echo sent; else echo blocked; fi`
	out, err := exec.Command("bash", "-c", script, "bash", helper).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "blocked" {
		t.Fatalf("gateway post = %q, want no curl invocation", got)
	}
}

func TestHostHookDoesNotSendAfterASeparatePeerCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	marker := filepath.Join(dir, "native-args")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$DC_NATIVE_MARKER\"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The earlier listener check passes, then that listener vanishes. The
	// native post refuses its newly connected peer; curl must never run.
	script := `set -euo pipefail; . "$1"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
curl() { echo leaked; }
if defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 'secret payload' -H 'Authorization: Bearer secret'; then echo sent; else echo blocked; fi`
	cmd := exec.Command("bash", "-c", script, "bash", helper)
	cmd.Env = append(os.Environ(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home, "DC_NATIVE_MARKER="+marker)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "blocked" {
		t.Fatalf("separate preflight leaked through curl: %q", got)
	}
	if args, err := os.ReadFile(marker); err != nil ||
		(string(args) != "hook-post --api-addr 127.0.0.1:18960 --max-time 1 --curl-output\n" &&
			string(args) != "hook-post --api-addr 127.0.0.1:18960 --max-time 2 --curl-output\n") {
		t.Fatalf("native post was not invoked without credentials on argv: %q, %v", args, err)
	}
}

func TestHostHookNativePostCarriesHeadersAndBodyOnStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "home")
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(dir, "native-input.json")
	binary := filepath.Join(binDir, "defenseclaw-gateway")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat > \"$DC_NATIVE_INPUT\"\nprintf '{\"action\":\"allow\"}\\n200'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail; . "$1"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 1; }
curl() { echo leaked; }
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 '{"private":"tool event"}' \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer private-token'`
	cmd := exec.Command("bash", "-c", script, "bash", helper)
	cmd.Env = append(os.Environ(), "HOME="+home, "DEFENSECLAW_AGENT_HOME="+home, "DC_NATIVE_INPUT="+inputPath)
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "{\"action\":\"allow\"}\n200" {
		t.Fatalf("native shell post = %q, error=%v", out, err)
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal(data, &input); err != nil || input.Path != "/api/v1/codex/hook" ||
		input.Headers["Authorization"] != "Bearer private-token" || input.Body != `{"private":"tool event"}` {
		t.Fatalf("native hook stdin = %+v, parse error=%v", input, err)
	}
}

func TestPerUserHookIgnoresInheritedManagedSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail; DEFENSECLAW_HOOK_SOCKET=/run/foreign.sock; unset DEFENSECLAW_MANAGED_HOOK
. "$1"; defenseclaw_harden_env; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 0; }
curl() { echo leaked; }
if defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 'secret payload' -H 'Authorization: Bearer secret'; then echo sent; else echo blocked; fi`
	// An empty home: no installed helper of the account running the test
	// may receive the call.
	cmd := exec.Command("bash", "-c", script, "bash", helper)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "blocked" {
		t.Fatalf("inherited managed socket bypassed ownership check: %q", got)
	}
}

func TestHostHookGatewayPostTreatsAFreePortAsColdStartWithoutSending(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail; . "$1"; API_ADDR=127.0.0.1:18960
defenseclaw_api_listener_unproven() { return 2; }
curl() { echo leaked; }
status=0; defenseclaw_gateway_post "http://${API_ADDR}/api/v1/codex/hook" 2 'secret payload' -H 'Authorization: Bearer secret' || status=$?
echo "status=$status"`
	out, err := exec.Command("bash", "-c", script, "bash", helper).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "status=7" {
		t.Fatalf("gateway post = %q, want curl refusal for cold start without sending", got)
	}
}

func TestMacHookDoesNotTreatAnotherOwnAddressAsGatewayOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	lsof := filepath.Join(dir, "lsof")
	// The account owns this port on another address, while the configured
	// 127.0.0.1 endpoint is free. A broad port-only lsof query is not proof.
	if err := os.WriteFile(lsof, []byte("#!/bin/sh\ncase \"$*\" in *'-iTCP:18960'*) exit 0;; esac\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail; . "$1"; status=0
defenseclaw_api_listener_unproven 127.0.0.1:18960 "$2" "$3" || status=$?
echo "$status"`
	out, err := exec.Command("bash", "-c", script, "bash", helper, filepath.Join(dir, "absent-net"), lsof).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "2" {
		t.Fatalf("different-address listener was trusted: status=%q, want free-port status 2", got)
	}
}
