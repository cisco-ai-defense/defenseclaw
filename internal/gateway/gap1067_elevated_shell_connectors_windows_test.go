// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestGAP1067ShellConnectorsNeverWeakerThanClaudeCodePowerShellOnWindows
// (rel-1-0-10:GAP-1067): on an elevated Windows host (Administrator, temp
// host dc-s7-win), six shell connectors answered allow where Claude Code's
// PowerShell tool alerted for the fixture rows gap/p0-round_GAP-1536/012 and
// /013 (opencode shell, openclaw exec, devin exec, hermes terminal, kiro v3
// execute_pwsh, antigravity run_command). This pins each of those routes to
// at least Claude Code PowerShell's verdict for the same command, in every
// tier, in the home and outside it; the native leg runs it under the
// elevated token as well as the limited one. No repro of the defect exists on
// the current pool hosts, at the 1.0.10 base or at the train head.
func TestGAP1067ShellConnectorsNeverWeakerThanClaudeCodePowerShellOnWindows(t *testing.T) {
	fixture := map[string]string{}
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/p0-round_GAP-1536/012" || c.id == "gap/p0-round_GAP-1536/013" {
			fixture[c.id], _ = c.args["command"].(string)
		}
	}
	if len(fixture) != 2 || fixture["gap/p0-round_GAP-1536/012"] == "" || fixture["gap/p0-round_GAP-1536/013"] == "" {
		t.Fatalf("fixture rows: %v", fixture)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "work")
	inside := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), outside, inside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	routes := map[string]bool{
		"opencode/shell": true, "openclaw/exec": true, "devin/exec": true,
		"hermes/terminal": true, "kiro/v3-execute_pwsh": true, "antigravity/run_command": true,
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		// The routes as the native-shape parity tests serve them (OpenClaw
		// asks the inspect route, not a hook route).
		handlers := shapeParityHandlers(t, p)
		handler := func(conn string) http.HandlerFunc { return handlers[conn] }
		for id, command := range fixture {
			args := map[string]any{"command": command}
			for _, cwd := range []string{outside, inside} {
				claude := shapeParityHook(t, handler("claudecode"), shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode",
					event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell", args)}, p.managed)
				seen := map[string]bool{}
				for _, call := range append(shapeParityNative("Bash", args, cwd), shapeParityNativeMore("Bash", args, cwd)...) {
					if !routes[call.name] {
						continue
					}
					seen[call.name] = true
					got := shapeParityHook(t, handler(call.conn), call, p.managed)
					if shapeParityRank[got] < shapeParityRank[claude] {
						t.Errorf("%s %s cwd %s: %s %q weaker than Claude Code PowerShell %q", p.name, id, cwd, call.name, got, claude)
					}
				}
				for name := range routes {
					if !seen[name] {
						t.Errorf("%s: route %s not rendered by shapeParityNative or shapeParityNativeMore; the pin no longer covers it", p.name, name)
					}
				}
			}
		}
	})
}
