// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0271: a call the shell hook blocks itself names the agent's tool call
// id (Claude Code tool_use_id) as its call_id and tool_id, so the gateway
// records the block under the tool id of its own decision row. Before, a
// Claude Code line had a random call id, which matched no audit row.
func TestShellHookBlockedCallRecordNamesTheToolUseID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	opts := SetupOpts{DataDir: home, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	installOutageOpenRuntimeForHookTest(t, home, home)
	cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
	cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"s-0271","tool_name":"Bash","tool_use_id":"toolu_0271_shell","tool_input":{"command":"ls"}}`)
	cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "DEFENSECLAW_HOME="+home, "DEFENSECLAW_GATEWAY_AUTOSTART=0")
	output, err := cmd.CombinedOutput()
	if !hookCallBlocked(err, string(output)) {
		t.Fatalf("a malformed answer was not blocked:\n%s", output)
	}
	records := hookFailureRecords(t, home)
	if len(records) == 0 {
		t.Fatalf("no hook-failures.jsonl record:\n%s", output)
	}
	last := records[len(records)-1]
	if last["outcome"] != "fail_closed" || last["session_id"] != "s-0271" ||
		last["call_id"] != "toolu_0271_shell" || last["tool_id"] != "toolu_0271_shell" {
		t.Fatalf("record %+v, want fail_closed under session s-0271 and tool id toolu_0271_shell", last)
	}
}
