// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP2204SessionCallKeepsTheDispatchMemo: a hook call with a session id
// holds a pending alias change (aliasPending), which turns the dispatch memo
// off. Only the call's own reading holds it: its twins and simple-command
// passes are judged through the memo as a call with no session is
// (rel-1-0-10:GAP-1472). Red at 5d24837ef9: the repeated statement
// sudo tee F <<< W; sudo tee F <<< W ran 43 dispatches with a session and
// 26 without. Same verdict either way.
func TestGAP2204SessionCallKeepsTheDispatchMemo(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	prev := trustedDispatchRunHook
	t.Cleanup(func() { trustedDispatchRunHook = prev })
	commands := []string{
		"sudo tee /etc/cron.d/x <<< W; sudo tee /etc/cron.d/x <<< W",
		"cat README.md | grep x; cat README.md | grep x",
		"git status && git status",
	}
	for _, connector := range []string{"claudecode", "codex"} {
		api := gap0589TierAPI(t, connector, "default", false, bounded.TierDefault)
		judge := func(session, command string) (int, string) {
			runs := 0
			trustedDispatchRunHook = func(trustedActionRequest) { runs++ }
			defer func() { trustedDispatchRunHook = prev }()
			if connector == "claudecode" {
				resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{HookEventName: "PreToolUse",
					SessionID: session, CWD: cwd, ToolName: "Bash", ToolInput: map[string]interface{}{"command": command}})
				return runs, resp.Action + " " + resp.Severity
			}
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{HookEventName: "PreToolUse",
				SessionID: session, ToolName: "shell", CWD: cwd, ToolInput: map[string]interface{}{"command": command}})
			return runs, resp.Action + " " + resp.Severity
		}
		for _, command := range commands {
			plainRuns, plainVerdict := judge("", command)
			sessionRuns, sessionVerdict := judge("gap2204-session", command)
			if sessionRuns != plainRuns || sessionVerdict != plainVerdict {
				t.Errorf("%s %q: with a session %d dispatches (%s), without %d (%s); want the memo's count and the same verdict",
					connector, command, sessionRuns, sessionVerdict, plainRuns, plainVerdict)
			}
		}
	}
}
