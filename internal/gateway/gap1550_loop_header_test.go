// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

// A PowerShell command evaluated inside a foreach header must receive the
// same hook verdict as that command alone. The matching ordinary directory
// enumeration remains allowed.
func TestGAP1550ForeachHeaderPipelineHookVerdict(t *testing.T) {
	prior := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prior })
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	judge := func(t *testing.T, command string) string {
		t.Helper()
		server := gap0437Server(t, gap0437Packs[0], "claudecode", "action")
		r := server.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "PowerShell",
			CWD: home + `\proj`, ToolInput: map[string]interface{}{"command": command},
		})
		return r.Action + " " + r.Severity
	}
	alone := judge(t, `Get-Content $HOME\.aws\credentials`)
	if alone == "allow NONE" {
		t.Fatal("standalone credential read has no finding")
	}
	nested := judge(t, `foreach ($f in (Get-Content $HOME\.aws\credentials)) { }`)
	if nested != alone {
		t.Fatalf("foreach header verdict %q, standalone %q", nested, alone)
	}
	benign := judge(t, `foreach ($f in (Get-ChildItem .)) { }`)
	if benign != "allow NONE" {
		t.Fatalf("benign foreach header verdict %q, want allow NONE", benign)
	}
}
