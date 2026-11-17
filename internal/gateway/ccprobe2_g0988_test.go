// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0988: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 7a9ae8c2e5 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCCP2G0988_GAP0988PowerShellArgumentStatements(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	var f12 string
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/p0-round_GAP-1536/012" {
			f12, _ = c.args["command"].(string)
		}
	}
	at := strings.LastIndex(f12, " > ")
	if at < 0 {
		t.Fatal("fixture 012 missing redirect")
	}
	tarPart, target := f12[:at], f12[at+3:]
	root := t.TempDir()
	home, outside := filepath.Join(root, "home"), filepath.Join(root, "work")
	inside := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), outside, inside} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct{ id, command string }{
		{"fixture-012", f12},
		{"after-extraction", tarPart + "; echo hi > " + target},
		{"sub-dq", `echo "$(` + tarPart + `)" > ` + target},
		{"sub-bare", "echo $(" + tarPart + ") > " + target},
		{"sub-append", "echo $(" + tarPart + ") >> " + target},
		{"ps-sub", "$(" + tarPart + ") > " + target},
		{"ps-paren", "(" + tarPart + ") > " + target},
		{"ps-echo-paren", "echo (" + tarPart + ") > " + target},
		{"ps-here-outfile", "@\"\n$(" + tarPart + ")\n\"@ | Out-File " + target},
		{"procsub", "cat <(" + tarPart + ") > " + target},
		{"ps-echo-at", "echo @(" + tarPart + ") > " + target},
		{"ps-at", "@(" + tarPart + ") > " + target},
		{"ps-amp-block", "& { " + tarPart + " } > " + target},
		{"ps-dot-block", ". { " + tarPart + " } > " + target},
		{"ps-echo-amp-block", "echo (& { " + tarPart + " }) > " + target},
		{"ps-wo-paren", "Write-Output (" + tarPart + ") > " + target},
		{"ps-echo-paren-append", "echo (" + tarPart + ") >> " + target},
		{"ps-echo-paren-all", "echo (" + tarPart + ") *> " + target},
		{"ps-echo-paren-2", "echo (" + tarPart + ") 2> " + target},
		{"ps-outfile-inputobject", "Out-File -FilePath " + target + " -InputObject (" + tarPart + ")"},
		{"ps-echo-paren-then", "echo (" + tarPart + "); echo hi > " + target},
		{"ps-redirect-then-echo-paren", "echo hi > " + target + "; echo (" + tarPart + ")"},
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		for _, where := range []struct{ name, cwd string }{{"outside", outside}, {"inside", inside}} {
			for _, r := range rows {
				t.Run(where.name+"/"+r.id, func(t *testing.T) {
					args := map[string]any{"command": r.command}
					cc := ccp2g0988_shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
						body: shapeParityEnvelope("PreToolUse", where.cwd, "PowerShell", args)}
					calls := append([]ccp2g0988_shapeParityCall{cc}, ccp2g0988_shapeParityNative("Bash", args, where.cwd)...)
					for _, call := range calls {
						got := ccp2g0988_shapeParityHook(t, handlers[call.conn], call, p.managed)
						fmt.Printf("G88\t%s\t%s\t%s\t%s\t%s\n", p.name, where.name, r.id, call.name, got)
						// Each row is judged against the same commands spelled as
						// plain statements in the order PowerShell runs them: an
						// argument command (a paren, subexpression, array,
						// string or here-string expansion) runs before its
						// parent opens a redirect target, while an invoked block
						// runs after its own redirect opened (fixture 012,
						// GAP-0946). Where that spelling blocks, the row blocks.
						// No partial-reading floor raises a read call (GAP-1015).
						normalText := tarPart + "; echo hi > " + target
						switch r.id {
						case "fixture-012", "ps-amp-block", "ps-dot-block":
							normalText = f12
						case "ps-redirect-then-echo-paren":
							normalText = "echo hi > " + target + "; " + tarPart
						case "ps-outfile-inputobject":
							normalText = tarPart + "; Out-File -FilePath " + target + " -InputObject 0"
						case "ps-here-outfile":
							normalText = tarPart + "; 0 | Out-File " + target
						}
						normalArgs := map[string]any{"command": normalText}
						normal := ccp2g0988_shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode", event: "PreToolUse",
							body: shapeParityEnvelope("PreToolUse", where.cwd, "PowerShell", normalArgs)}
						if call.conn == "antigravity" {
							normal = ccp2g0988_shapeParityNative("Bash", normalArgs, where.cwd)[0]
						}
						control := ccp2g0988_shapeParityHook(t, handlers[normal.conn], normal, p.managed)
						fmt.Printf("G88C\t%s\t%s\t%s\t%s\t%s\n", p.name, where.name, r.id, call.name, control)
						if control == "block" && got != "block" {
							t.Errorf("%s: got %s, want block (the plain statements block)", call.name, got)
						}
					}
				})
			}
		}
	})
}

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector's hook.
type ccp2g0988_shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// shapeParityHook answers one hook call through the connector's handler.
func ccp2g0988_shapeParityHook(t *testing.T, h http.HandlerFunc, call ccp2g0988_shapeParityCall, managedTier bool) string {
	t.Helper()
	raw, _ := json.Marshal(call.body)
	route := call.route
	if route == "" {
		route = "/api/v1/" + call.conn + "/hook"
	}
	req := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range call.headers {
		req.Header.Set(key, value)
	}
	// The inspect route's caller (OpenClaw's plugin) sends no hook
	// evidence header.
	if managedTier && call.route == "" {
		if ev := hookpaths.ResolveConnector(call.conn, "", call.event, raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: http %d", call.name, w.Code)
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: answer is not JSON", call.name)
	}
	return resp.Action
}

// shapeParityNative renders a Claude Code call (tool Bash, Write, Edit or
// Read) as the native shapes the train maps.
func ccp2g0988_shapeParityNative(tool string, args map[string]any, cwd string) []ccp2g0988_shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	agy := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	var out []ccp2g0988_shapeParityCall
	switch tool {
	case "Bash":
		out = append(out, ccp2g0988_shapeParityCall{name: "antigravity/run_command", conn: "antigravity", event: "PreToolUse", headers: agy,
			body: func() map[string]any {
				m := shapeParityAntigravity("run_command", map[string]any{"Cwd": cwd, "CommandLine": str("command"), "WaitMsBeforeAsync": 5000})
				m["workspacePaths"] = []string{cwd}
				return m
			}()})
	case "Write":
		out = append(out,
			ccp2g0988_shapeParityCall{name: "antigravity/write_to_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("write_to_file", map[string]any{"TargetFile": str("file_path"), "CodeContent": str("content")})},
			ccp2g0988_shapeParityCall{name: "codex/apply_patch-add", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " +
					str("file_path") + "\n+" + strings.ReplaceAll(str("content"), "\n", "\n+") + "\n*** End Patch"})},
		)
	case "Edit":
		out = append(out,
			ccp2g0988_shapeParityCall{name: "antigravity/replace_file_content", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("replace_file_content", map[string]any{"TargetFile": str("file_path"),
					"TargetContent": str("old_string"), "ReplacementContent": str("new_string")})},
			ccp2g0988_shapeParityCall{name: "amp/edit_file", conn: "amp", event: "tool.call",
				body: shapeParityEnvelope("tool.call", cwd, "edit_file", map[string]any{"path": str("file_path"),
					"old_str": str("old_string"), "new_str": str("new_string")})},
			// The Update File of the same edit (rel-1-0-10:GAP-0947).
			ccp2g0988_shapeParityCall{name: "codex/apply_patch-update", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": ccp2g0988_shapeParityUpdatePatch(
					str("file_path"), str("old_string"), str("new_string"))})},
		)
	case "Read":
		copilotArgs, _ := json.Marshal(map[string]any{"path": str("file_path")})
		sid := fmt.Sprintf("sp-%d", shapeParitySeq.Add(1))
		out = append(out,
			ccp2g0988_shapeParityCall{name: "antigravity/view_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("view_file", map[string]any{"AbsolutePath": str("file_path")})},
			ccp2g0988_shapeParityCall{name: "copilot/view", conn: "copilot", event: "preToolUse",
				headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				body:    map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(copilotArgs)}},
			ccp2g0988_shapeParityCall{name: "cursor/beforeReadFile", conn: "cursor", event: "beforeReadFile",
				body: map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
					"session_id": sid, "cwd": cwd, "file_path": str("file_path"), "content": ""}},
		)
	}
	return out
}

func ccp2g0988_shapeParityUpdatePatch(path, oldText, newText string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-" + strings.ReplaceAll(oldText, "\n", "\n-") +
		"\n+" + strings.ReplaceAll(newText, "\n", "\n+") + "\n*** End Patch"
}
