// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A shell hook's stdout is the agent's block message. Stderr alone does not
// give the user the reason for a stopped gateway.
func TestShellHookOutageDenyReasonsNameTheGatewayAndNextStep(t *testing.T) {
	requireShellHookToolsForTest(t)
	for _, connector := range []string{"antigravity", "copilot", "cursor", "devin"} {
		t.Run(connector+"/managed", func(t *testing.T) {
			f := newHookSocketFixture(t, "dcux", nil)
			if err := os.Remove(f.socket); err != nil {
				t.Fatal(err)
			}
			conn, ok := NewDefaultRegistry().Get(connector)
			if !ok {
				t.Fatalf("missing %s connector", connector)
			}
			call := hookArgvConnectorCase(t, connector)
			code, stdout, stderr := runStandaloneShellHook(t, f, conn, call.script, call.args, call.stdin)
			wantCode := 2
			if connector == "antigravity" || connector == "copilot" {
				wantCode = 0
			}
			fragments := []string{
				"the DefenseClaw gateway service is not running on this computer",
				"Try again in a moment",
				"enterprise_managed_gateway_not_running",
			}
			if connector == "antigravity" && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
				platform := "linux"
				if runtime.GOOS == "darwin" {
					platform = "macos"
				}
				fragments = append(fragments, "ask your administrator to check DefenseClaw", "enterprise "+platform+" status")
			} else {
				fragments = append(fragments, "ask your administrator to start the DefenseClaw gateway service")
			}
			checkOutageDenyReason(t, connector, code, wantCode, stdout, stderr,
				fragments...)
		})
		t.Run(connector+"/per-user", func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, dataDir, outageStrictTierConfig)
			if err := os.WriteFile(filepath.Join(dataDir, "gateway.stopped"), []byte("stopped\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			conn, ok := NewDefaultRegistry().Get(connector)
			if !ok {
				t.Fatalf("missing %s connector", connector)
			}
			call := hookArgvConnectorCase(t, connector)
			opts := SetupOpts{DataDir: dataDir, APIAddr: freeLoopbackAddrForOutageTest(t), HookAPIToken: "outage-test-token", HookFailMode: "closed", GuardrailMode: "action"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dataDir, "hooks"), opts, conn); err != nil {
				t.Fatal(err)
			}
			stdout, stderr, code := runPerUserHookIn(t, dataDir, []string{"HOME=" + home, "DEFENSECLAW_GATEWAY_AUTOSTART=0"}, filepath.Join(dataDir, "hooks", call.script), call.stdin, call.args...)
			wantCode := 2
			if connector == "antigravity" || connector == "copilot" {
				wantCode = 0
			}
			checkOutageDenyReason(t, connector, code, wantCode, stdout, stderr,
				"gateway was stopped with", "defenseclaw-gateway start", "defenseclaw-gateway status")
		})
	}
}

func TestGAP0494ManagedMacAntigravityOutageRenderAndBenignTwin(t *testing.T) {
	requireShellHookToolsForTest(t)
	f := newHookSocketFixture(t, "dc494", nil)
	home := filepath.Join(f.root, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	conn := NewAntigravityConnector()
	opts := SetupOpts{
		DataDir: dataDir, APIAddr: f.held.Addr().String(),
		HookAPIToken: "fixture-token", HookAPITokenScoped: true,
		ManagedEnterprise: true, HookFailMode: "closed", GuardrailMode: "observe",
		ManagedHookSocket: f.socket, ManagedServiceUID: os.Getuid(),
	}
	render := resolveConnectorHookRender(opts, conn)
	linux := shellHookSocketTransport(f.socket, os.Getuid(), managedSessionFactsBinary(opts), render.foreignGuard, conn.Name(), "linux")
	mac := shellHookSocketTransport(f.socket, os.Getuid(), managedSessionFactsBinary(opts), render.foreignGuard, conn.Name(), "darwin")
	if strings.Count(linux, "enterprise linux status") != 1 ||
		strings.Contains(linux, "enterprise macos status") ||
		strings.Contains(shellHookSocketTransport(f.socket, os.Getuid(), "", "", "copilot", "darwin"), "enterprise macos status") {
		t.Fatal("the Linux Antigravity or other connector stopped-service render has the wrong status instruction")
	}
	if (runtime.GOOS == "darwin" && render.socketTransport != mac) ||
		(runtime.GOOS == "linux" && render.socketTransport != linux) {
		t.Fatal("the installed transport does not match the host platform")
	}
	if strings.Count(mac, "enterprise macos status") != 1 ||
		strings.Contains(mac, "ask your administrator to start the DefenseClaw gateway service") {
		t.Fatal("the macOS Antigravity transport lacks the managed status instruction")
	}
	if err := writeHookScriptsCommonWithTransport(hookDir, opts.APIAddr, render.token, render.failMode,
		render.failModeSource, render.extras, true, conn.Name(), render.scopedToken, mac,
		render.foreignGuard, false, false); err != nil {
		t.Fatal(err)
	}
	call := hookArgvConnectorCase(t, "antigravity")
	hookPath := filepath.Join(hookDir, call.script)
	if curlPath, err := exec.LookPath("curl"); err == nil {
		bakeHookPathForTest(t, hookPath, filepath.Dir(curlPath)+":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	}
	run := func() (int, string, string) {
		stdout, stderr, code := runPerUserHookIn(t, dataDir, []string{"HOME=" + home}, hookPath, call.stdin, call.args...)
		return code, stdout, stderr
	}
	code, stdout, stderr := run()
	var answer struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil || code != 0 || answer.Decision != "allow" {
		t.Fatalf("ordinary managed call: code=%d stdout=%q stderr=%q parse=%v", code, stdout, stderr, err)
	}
	if err := os.Remove(f.socket); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run()
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil || code != 0 || answer.Decision != "deny" ||
		strings.Count(stdout, "\n") != 1 ||
		!strings.Contains(answer.Reason, "gateway service is not running") ||
		!strings.Contains(answer.Reason, "ask your administrator") ||
		!strings.Contains(answer.Reason, "enterprise macos status") ||
		!strings.Contains(answer.Reason, "enterprise_managed_gateway_not_running") ||
		strings.Contains(stderr, "event-specific failure") {
		t.Fatalf("managed macOS outage: code=%d stdout=%q stderr=%q parse=%v", code, stdout, stderr, err)
	}
}

func TestGAP0494ManagedLinuxAntigravityInstalledShellAndBenignTwin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux installed shell check")
	}
	requireShellHookToolsForTest(t)
	f := newHookSocketFixture(t, "dc49l", nil)
	call := hookArgvConnectorCase(t, "antigravity")
	run := func() (int, string, string) {
		return runStandaloneShellHook(t, f, NewAntigravityConnector(), call.script, call.args, call.stdin)
	}
	code, stdout, stderr := run()
	var answer struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(stdout), &answer); err != nil || code != 0 || answer.Decision != "allow" {
		t.Fatalf("ordinary managed call: code=%d stdout=%q stderr=%q parse=%v", code, stdout, stderr, err)
	}
	if err := os.Remove(f.socket); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run()
	checkOutageDenyReason(t, "antigravity", code, 0, stdout, stderr,
		"the DefenseClaw gateway service is not running on this computer",
		"Try again in a moment",
		"enterprise linux status",
		"enterprise_managed_gateway_not_running")
}

func checkOutageDenyReason(t *testing.T, connector string, code, wantCode int, stdout, stderr string, fragments ...string) {
	t.Helper()
	if code != wantCode {
		t.Fatalf("exit %d, want %d: stdout=%q stderr=%q", code, wantCode, stdout, stderr)
	}
	var reason string
	if connector == "devin" {
		reason = strings.TrimSpace(stdout)
	} else {
		var answer map[string]any
		if err := json.Unmarshal([]byte(stdout), &answer); err != nil {
			t.Fatalf("invalid hook JSON %q: %v (stderr %q)", stdout, err, stderr)
		}
		switch connector {
		case "antigravity":
			reason, _ = answer["reason"].(string)
			if answer["decision"] != "deny" {
				t.Fatalf("Antigravity decision = %v, want deny", answer)
			}
		case "copilot":
			reason, _ = answer["permissionDecisionReason"].(string)
			if answer["permissionDecision"] != "deny" {
				t.Fatalf("Copilot decision = %v, want deny", answer)
			}
		case "cursor":
			if answer["permission"] != "deny" || answer["agent_message"] != answer["user_message"] {
				t.Fatalf("Cursor deny fields = %v", answer)
			}
			reason, _ = answer["user_message"].(string)
		}
	}
	for _, fragment := range fragments {
		if !strings.Contains(reason, fragment) {
			t.Errorf("block reason %q does not contain %q (stderr %q)", reason, fragment, stderr)
		}
	}
}
