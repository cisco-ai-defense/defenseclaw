// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0946: the rel hook-route tests of the fix,
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
	"runtime"
	"strings"
	"testing"
)

// TestPowerShellRedirectBeforeExtractionKeepsItsProof (rel-1-0-10:GAP-0946):
// a redirect that opens before the tar extraction of its call or of a later
// statement (fixture rows gap/p0-round_GAP-1536/012 and 013) is judged once,
// with that proof, in the Claude Code PowerShell reading as in agy's
// run_command, inside and outside the home, as on Linux. The PowerShell
// path fact spells the redirect C:/dir/file where the shell operand is
// C:\dir\file; judged again under that spelling it lost the proof, so the
// PowerShell reading warned or blocked and agy, where only its PowerShell
// reading saw the second spelling, was "weaker" (CI TEMP on its own volume).
//
// The negative controls are the same fixture commands with a write the
// proof must still hold, in every pack: the key file written after the
// extraction, a redirect after the extraction into the folder it extracts
// into (inside the home), and an append through a link the command makes
// earlier to the key file.
func TestCCP2G0946_PowerShellRedirectBeforeExtractionKeepsItsProof(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the PowerShell reading of a Windows host")
	}
	fixture := map[string]string{}
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/p0-round_GAP-1536/012" || c.id == "gap/p0-round_GAP-1536/013" {
			fixture[c.id], _ = c.args["command"].(string)
		}
	}
	if len(fixture) != 2 || fixture["gap/p0-round_GAP-1536/012"] == "" || fixture["gap/p0-round_GAP-1536/013"] == "" {
		t.Fatalf("fixture rows: %v", fixture)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "work")
	inside := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), outside, inside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	keys := filepath.Join(home, ".ssh", hookpaths.AuthorizedKeysFiles[0])
	extract := fixture["gap/p0-round_GAP-1536/013"][strings.LastIndex(fixture["gap/p0-round_GAP-1536/013"], ";")+1:]
	extract = strings.TrimSpace(extract)
	type row struct {
		id, command string
		block       bool
		dirs        []string
	}
	rows := []row{
		{"gap/p0-round_GAP-1536/012", fixture["gap/p0-round_GAP-1536/012"], false, []string{outside, inside}},
		{"gap/p0-round_GAP-1536/013", fixture["gap/p0-round_GAP-1536/013"], false, []string{outside, inside}},
		{"control/key-write-after-extraction", extract + "; cat x > " + keys, true, []string{outside, inside}},
		{"control/redirect-into-scope-after-extraction", extract + "; echo hi > out.txt", true, []string{inside}},
		{"control/append-through-earlier-link-posix", "ln -s " + keys + " k; " + extract + "; echo x >> k", true, []string{outside, inside}},
		{"control/append-through-earlier-link-powershell", "New-Item -ItemType SymbolicLink -Path k -Target " + keys + "; " + extract + "; echo x >> k", true, []string{outside, inside}},
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		for _, r := range rows {
			args := map[string]any{"command": r.command}
			for _, cwd := range r.dirs {
				where := "outside the home"
				if strings.HasPrefix(cwd, home) {
					where = "inside the home"
				}
				claude := ccp2g0946_shapeParityHook(t, handlers["claudecode"], ccp2g0946_shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode",
					event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell", args)}, p.managed)
				for _, call := range ccp2g0946_shapeParityNative("Bash", args, cwd) {
					agy := ccp2g0946_shapeParityHook(t, handlers[call.conn], call, p.managed)
					switch {
					case r.block && (claude != "block" || agy != "block"):
						t.Errorf("%s %s %s: Claude Code PowerShell %s, %s %s, want block", p.name, r.id, where, claude, call.name, agy)
					case !r.block && (claude != "allow" || agy != "allow"):
						t.Errorf("%s %s %s: Claude Code PowerShell %s, %s %s, want allow (the redirect opens before tar runs)", p.name, r.id, where, claude, call.name, agy)
					}
				}
			}
		}
	})
}

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector's hook.
type ccp2g0946_shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// shapeParityHook answers one hook call through the connector's handler.
func ccp2g0946_shapeParityHook(t *testing.T, h http.HandlerFunc, call ccp2g0946_shapeParityCall, managedTier bool) string {
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
func ccp2g0946_shapeParityNative(tool string, args map[string]any, cwd string) []ccp2g0946_shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	agy := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	var out []ccp2g0946_shapeParityCall
	switch tool {
	case "Bash":
		out = append(out, ccp2g0946_shapeParityCall{name: "antigravity/run_command", conn: "antigravity", event: "PreToolUse", headers: agy,
			body: func() map[string]any {
				m := shapeParityAntigravity("run_command", map[string]any{"Cwd": cwd, "CommandLine": str("command"), "WaitMsBeforeAsync": 5000})
				m["workspacePaths"] = []string{cwd}
				return m
			}()})
	case "Write":
		out = append(out,
			ccp2g0946_shapeParityCall{name: "antigravity/write_to_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("write_to_file", map[string]any{"TargetFile": str("file_path"), "CodeContent": str("content")})},
			ccp2g0946_shapeParityCall{name: "codex/apply_patch-add", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " +
					str("file_path") + "\n+" + strings.ReplaceAll(str("content"), "\n", "\n+") + "\n*** End Patch"})},
		)
	case "Edit":
		out = append(out,
			ccp2g0946_shapeParityCall{name: "antigravity/replace_file_content", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("replace_file_content", map[string]any{"TargetFile": str("file_path"),
					"TargetContent": str("old_string"), "ReplacementContent": str("new_string")})},
			ccp2g0946_shapeParityCall{name: "amp/edit_file", conn: "amp", event: "tool.call",
				body: shapeParityEnvelope("tool.call", cwd, "edit_file", map[string]any{"path": str("file_path"),
					"old_str": str("old_string"), "new_str": str("new_string")})},
			// The Update File of the same edit (rel-1-0-10:GAP-0947).
			ccp2g0946_shapeParityCall{name: "codex/apply_patch-update", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": ccp2g0946_shapeParityUpdatePatch(
					str("file_path"), str("old_string"), str("new_string"))})},
		)
	case "Read":
		copilotArgs, _ := json.Marshal(map[string]any{"path": str("file_path")})
		sid := fmt.Sprintf("sp-%d", shapeParitySeq.Add(1))
		out = append(out,
			ccp2g0946_shapeParityCall{name: "antigravity/view_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("view_file", map[string]any{"AbsolutePath": str("file_path")})},
			ccp2g0946_shapeParityCall{name: "copilot/view", conn: "copilot", event: "preToolUse",
				headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				body:    map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(copilotArgs)}},
			ccp2g0946_shapeParityCall{name: "cursor/beforeReadFile", conn: "cursor", event: "beforeReadFile",
				body: map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
					"session_id": sid, "cwd": cwd, "file_path": str("file_path"), "content": ""}},
		)
	}
	return out
}

func ccp2g0946_shapeParityUpdatePatch(path, oldText, newText string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-" + strings.ReplaceAll(oldText, "\n", "\n-") +
		"\n+" + strings.ReplaceAll(newText, "\n", "\n+") + "\n*** End Patch"
}
