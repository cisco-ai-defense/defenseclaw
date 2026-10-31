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

// GAP-1350, GAP-1352: the Codex shell hook cleared PAYLOAD before
// fail_unreachable, so during an outage its hook-failures.jsonl rows had no
// session id and the once-per-session warning marker had no session to key
// on: Codex warned on every call. Every per-user hook keeps the event until
// the outage is recorded: each row names the session, and two outage calls
// of one session give one warning.
func TestPerUserShellHookOutageRowsKeepTheSessionAndWarnOnce(t *testing.T) {
	for _, conn := range []Connector{NewClaudeCodeConnector(), NewCodexConnector(), NewCopilotConnector()} {
		conn := conn
		t.Run(conn.Name(), func(t *testing.T) {
			t.Parallel()
			invoke := hookArgvConnectorCase(t, conn.Name())
			if conn.Name() == "copilot" {
				// Copilot's once-per-session warning is the postToolUse
				// notice (rel-1-0-4 GAP-1320).
				invoke.args = []string{"--event", "postToolUse"}
			}
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			warning := outageOpenWarningForTest(conn.Name())
			if conn.Name() == "copilot" {
				warning = "DefenseClaw is not checking this session"
			}
			for call := 0; call < 2; call++ {
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, invoke.script)}, invoke.args...)...)
				cmd.Stdin = strings.NewReader(invoke.stdin)
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
				output, err := cmd.CombinedOutput()
				if hookCallBlocked(err, string(output)) {
					t.Fatalf("call %d blocked during an outage in the default tier (exit %v):\n%s", call, err, output)
				}
				if warned := strings.Contains(string(output), warning); warned != (call == 0) {
					t.Fatalf("call %d warned=%v, want one warning per session:\n%s", call, warned, output)
				}
			}
			records := hookFailureRecords(t, home)
			if len(records) != 2 {
				t.Fatalf("hook-failures.jsonl has %d rows, want one per outage call: %+v", len(records), records)
			}
			for _, row := range records {
				if row["session_id"] != "s1" {
					t.Fatalf("outage row without its session: %+v", row)
				}
			}
		})
	}
}

// rel-1-0-4 GAP-1320: Copilot CLI shows nothing a hook prints on an allow
// except a postToolUse additionalContext. During a per-user outage the
// preToolUse allow prints nothing and keeps the session's warning marker;
// the first postToolUse carries the cause-and-recovery notice as
// additionalContext; the next one of the session prints nothing.
func TestPerUserCopilotOutageNoticeIsPostToolUseAdditionalContext(t *testing.T) {
	conn := NewCopilotConnector()
	invoke := hookArgvConnectorCase(t, conn.Name())
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	writeOutageTierConfig(t, home, outageDefaultTierConfig)
	hookDir := filepath.Join(home, "hooks")
	opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
		t.Fatal(err)
	}
	run := func(event string) (string, string) {
		cmd := exec.Command("bash", filepath.Join(hookDir, invoke.script), "--event", event)
		cmd.Stdin = strings.NewReader(invoke.stdin)
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s exit %v: %s %s", event, err, stdout.String(), stderr.String())
		}
		return stdout.String(), stderr.String()
	}
	if out, _ := run("preToolUse"); strings.TrimSpace(out) != "" {
		t.Fatalf("preToolUse outage allow printed %q, want nothing", out)
	}
	out, _ := run("postToolUse")
	var notice map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &notice); err != nil {
		t.Fatalf("postToolUse printed %q, want one JSON result: %v", out, err)
	}
	text := notice["additionalContext"]
	for _, want := range []string{"DefenseClaw is not checking this session", "defenseclaw-gateway start", "defenseclaw doctor"} {
		if !strings.Contains(text, want) {
			t.Fatalf("additionalContext %q does not name %q", text, want)
		}
	}
	if out, _ := run("postToolUse"); strings.TrimSpace(out) != "" {
		t.Fatalf("second postToolUse of the session printed %q, want the warning once", out)
	}
}
