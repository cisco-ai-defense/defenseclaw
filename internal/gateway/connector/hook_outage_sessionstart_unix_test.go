// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0040: only Claude Code's interactive terminal shows a
// SessionStart systemMessage; Claude Cowork, the IDE extensions and claude -p
// (the Agent SDK stream) drop it. The per-user Claude Code shell hook took the
// once-per-session outage warning on SessionStart, so a Cowork task that ran
// a command while the gateway was stopped showed no warning. The session
// start now allows silently and keeps the marker; the first prompt carries
// the warning as its systemMessage, and the tool call after it allows
// silently. Every call still fails open.
func TestPerUserClaudeShellHookOutageWarningSkipsSessionStart(t *testing.T) {
	conn := NewClaudeCodeConnector()
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	writeOutageTierConfig(t, home, outageDefaultTierConfig)
	hookDir := filepath.Join(home, "hooks")
	opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	const warning = "DefenseClaw is not checking this session"
	for _, call := range []struct {
		event, stdin string
		warn         bool
	}{
		{"SessionStart", `{"hook_event_name":"SessionStart","session_id":"cw1","source":"startup"}`, false},
		{"UserPromptSubmit", `{"hook_event_name":"UserPromptSubmit","session_id":"cw1","prompt":"run echo failopen-check"}`, true},
		{"PreToolUse", `{"hook_event_name":"PreToolUse","session_id":"cw1","tool_name":"Bash","tool_input":{"command":"echo failopen-check"}}`, false},
	} {
		cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
		cmd.Stdin = strings.NewReader(call.stdin)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
		var stdout strings.Builder
		cmd.Stdout = &stdout
		err := cmd.Run()
		if err != nil {
			t.Fatalf("%s exit %v, want a fail-open allow (exit 0); stdout:\n%s", call.event, err, stdout.String())
		}
		out := strings.TrimSpace(stdout.String())
		if warned := strings.Contains(out, warning); warned != call.warn {
			t.Fatalf("%s warned=%v, want %v; stdout:\n%s", call.event, warned, call.warn, out)
		}
		if !call.warn {
			if out != "" {
				t.Fatalf("%s printed %q, want a silent allow", call.event, out)
			}
			continue
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(out), &body); err != nil {
			t.Fatalf("%s stdout %q is not one hook result: %v", call.event, out, err)
		}
		if len(body) != 1 || !strings.HasPrefix(body["systemMessage"].(string), warning) {
			t.Fatalf("%s result %v, want only a systemMessage warning (no decision)", call.event, body)
		}
	}
	if rows := hookFailureRecords(t, home); len(rows) != 3 {
		t.Fatalf("hook-failures.jsonl has %d rows, want one fail_open row per call: %+v", len(rows), rows)
	}
}
