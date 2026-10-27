// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0315 review: a per-user hook installed open exits before it sources
// _hardening.sh when its DEFENSECLAW_HOME is missing or disabled. That early
// exit follows the installed mode, with strict availability closing it as it
// closes every later outage, and answers with the connector's own block.
// DEFENSECLAW_FAIL_MODE is not read (1.0.4 lead directive).
func TestPerUserHookHomeUnavailableFollowsTheInstalledMode(t *testing.T) {
	for _, agent := range []struct {
		conn   Connector
		script string
		args   []string
	}{
		{NewCodexConnector(), "codex-hook.sh", []string{"--event", "PreToolUse", "--hook-contract", "codex-hooks-v1"}},
		{NewClaudeCodeConnector(), "claude-code-hook.sh", nil},
		{NewCursorConnector(), "cursor-hook.sh", nil},
		{NewDevinConnector(), "devin-hook.sh", nil},
		{NewHermesConnector(), "hermes-hook.sh", nil},
		{NewKiroConnector(), "kiro-hook.sh", nil},
		{NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}},
		{NewCodexConnector(), "inspect-tool.sh", nil},
	} {
		home := t.TempDir()
		hookDir := filepath.Join(home, "hooks")
		// A DEFENSECLAW_HOME that names no folder no longer takes this exit
		// (GAP-1256, TestPerUserHookKeepsItsFolderWhenTheInheritedHomeIsMissing):
		// a disabled one does.
		retired := filepath.Join(home, "retired")
		if err := os.MkdirAll(retired, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(retired, ".disabled"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: "open"}
		if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, agent.conn); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name      string
			env       []string
			wantBlock bool
		}{
			{"no-env", nil, true},
			{"env-closed", []string{"DEFENSECLAW_FAIL_MODE=Closed"}, true},
			{"strict", []string{"DEFENSECLAW_STRICT_AVAILABILITY=yes"}, true},
			{"env-open", []string{"DEFENSECLAW_FAIL_MODE=open"}, true},
		} {
			t.Run(agent.script+"/"+tc.name, func(t *testing.T) {
				cmd := exec.Command("bash", append([]string{filepath.Join(hookDir, agent.script)}, agent.args...)...)
				cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
				cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + home,
					"DEFENSECLAW_HOME=" + retired, "DEFENSECLAW_GATEWAY_AUTOSTART=0"}, tc.env...)
				out, err := cmd.CombinedOutput()
				text := string(out)
				blocked := err != nil || strings.Contains(text, `"decision":"deny"`) || strings.Contains(text, `"permissionDecision":"deny"`) ||
					strings.Contains(text, `"action":"block"`) || strings.Contains(text, `"permission":"deny"`)
				if blocked != tc.wantBlock {
					t.Fatalf("blocked=%v want %v err=%v\n%s", blocked, tc.wantBlock, err, text)
				}
				if tc.wantBlock && !strings.Contains(text, "hook home unavailable") {
					t.Fatalf("the block did not come from the unavailable-home exit:\n%s", text)
				}
			})
		}
	}
}
