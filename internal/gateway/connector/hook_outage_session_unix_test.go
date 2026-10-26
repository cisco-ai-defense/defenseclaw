// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
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
			home := t.TempDir()
			installNativeGatewayForHookTest(t, home)
			writeOutageTierConfig(t, home, outageDefaultTierConfig)
			hookDir := filepath.Join(home, "hooks")
			opts := SetupOpts{DataDir: home, APIAddr: freeLoopbackAddrForOutageTest(t), APIToken: "scoped-test-token", HookFailMode: "open"}
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, conn); err != nil {
				t.Fatal(err)
			}
			warning := outageOpenWarningForTest(conn.Name())
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
