// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1388 live shape: real Codex sends a shell call PreToolUse with the
// session cwd and tool_input {"command": ...} only; the call workdir is in
// the session rollout under the call id. A pre-existing AGENTS.md in the
// workdir folder stays protected in action mode (the first folder has no
// AGENTS.md), a file the session creates there stays its own, and an
// ordinary file there stays writable.
func TestR105GAP1388CodexWorkdirFromTheRollout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	first := filepath.Join(home, "ip7-wa")
	second := filepath.Join(home, "ip7-wb")
	third := filepath.Join(home, "ip7-wc")
	sessions := filepath.Join(home, ".codex", "sessions", "2026", "10", "29")
	for _, dir := range []string{first, second, third, sessions} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeActiveAgentTestFile(t, second, "AGENTS.md")
	rollout := filepath.Join(sessions, "rollout-2026-10-29T00-00-00-live.jsonl")
	if err := os.WriteFile(rollout, []byte(`{"type":"session_meta","payload":{"cwd":"x"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	appendCall := func(id, workdir, cmd string) {
		t.Helper()
		args, _ := json.Marshal(map[string]interface{}{"cmd": cmd, "workdir": workdir, "login": false})
		line, _ := json.Marshal(map[string]interface{}{
			"type": "response_item",
			"payload": map[string]interface{}{
				"type": "function_call", "name": "exec_command", "arguments": string(args), "call_id": id,
			},
		})
		f, err := os.OpenFile(rollout, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(append(line, 10)); err != nil {
			t.Fatal(err)
		}
	}
	appendTo := func(name string) string {
		if runtime.GOOS == "windows" {
			return "Add-Content -LiteralPath " + name + " -Value ip7"
		}
		return "printf ip7 >> " + name
	}
	for _, mode := range []string{"action", "observe"} {
		t.Run(mode, func(t *testing.T) {
			api := instructionProtectionTestAPI(t, "codex", mode, "HIGH")
			api.scannerCfg.DataDir = t.TempDir()
			auth := withAuthenticatedHookConnector(t.Context(), "codex")
			session := "live-" + mode
			api.evaluateCodexHook(auth, codexHookRequest{HookEventName: "SessionStart", SessionID: session, CWD: first, Source: "startup"})
			call := func(id, workdir, cmd string) codexHookResponse {
				t.Helper()
				appendCall(id, workdir, cmd)
				input := map[string]interface{}{"command": cmd}
				ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, first, "Bash", input), "codex")
				return api.evaluateCodexHook(ctx, codexHookRequest{
					HookEventName: "PreToolUse", SessionID: session, CWD: first, ToolName: "Bash",
					ToolUseID: id, TranscriptPath: rollout, ToolInput: input,
				})
			}
			got := call("call_"+mode+"_1", second, appendTo("AGENTS.md"))
			if !cogBlocked(got.Action, got.WouldBlock, got.Findings) || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("pre-existing AGENTS.md in the call workdir was writable: %+v", got)
			}
			if mode == "observe" && got.Action == guardrailActionBlock {
				t.Fatalf("observe mode blocked: %+v", got)
			}
			if got := call("call_"+mode+"_2", second, appendTo("notes.txt")); got.Action == guardrailActionBlock {
				t.Fatalf("ordinary file in the call workdir blocked: %+v", got)
			}
			if got := call("call_"+mode+"_3", third, appendTo("AGENTS.md")); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating AGENTS.md in a new workdir: %+v", got)
			}
			if err := os.WriteFile(filepath.Join(third, "AGENTS.md"), []byte("ip7\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := call("call_"+mode+"_4", third, appendTo("AGENTS.md")); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("editing the AGENTS.md this session created: %+v", got)
			}
			if err := os.Remove(filepath.Join(third, "AGENTS.md")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
