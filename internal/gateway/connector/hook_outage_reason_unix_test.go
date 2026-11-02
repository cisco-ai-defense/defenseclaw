// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
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
			checkOutageDenyReason(t, connector, code, wantCode, stdout, stderr,
				"the DefenseClaw gateway service is not running on this computer",
				"Try again in a moment",
				"ask your administrator to start the DefenseClaw gateway service",
				"enterprise_managed_gateway_not_running")
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
			opts := SetupOpts{DataDir: dataDir, APIAddr: closedLoopbackAddrForTest(t), HookAPIToken: "outage-test-token", HookFailMode: "closed", GuardrailMode: "action"}
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
