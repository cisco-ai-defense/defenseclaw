// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

func acpIDOnlyPermission(t *testing.T) []byte {
	return acpFrameJSON(t, 1, "session/request_permission",
		map[string]any{"sessionId": "s", "options": []any{}, "toolCall": map[string]any{"toolCallId": "t", "title": "Run"}})
}

// TestACPPermissionAfterABlockedReportIsNeverBelowTheBlock: the fixtures' shell
// commands the hook blocks, padded so that the finding is past the prefix the
// guard keeps. The gateway judges the whole report a block (an alert that would
// have blocked); the guard keeps that mark with the call, so the permission that
// names only the call's id is a block too, in every pack, where the cut state
// alone was only the unknown tier. A dropped call keeps the mark the same way
// (ACP review round 4, P3-1).
//
// Case GAP-0462/F3 (ACP review round 5): a small first report (`ls`), then an
// update with the padded command and a title equal to it, as claude-code-acp
// titles a shell call. The guard cuts the title as it cuts the input and keeps
// the update's mark, never the stale `ls` state: the permission is a block
// wherever the update was judged one, and at least the unknown tier otherwise.
func TestACPPermissionAfterABlockedReportIsNeverBelowTheBlock(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			permission := func(state json.RawMessage) acp.Verdict {
				env.toolCallState = state
				defer func() { env.toolCallState = nil }()
				return env.evaluate(t, acp.AgentToClient, acpIDOnlyPermission(t))
			}
			var tried, reportBlocks, permissionBlocks, f3Blocks, f3UpdateBlocks int
			example, f3Example := "", ""
			for _, pair := range pairs {
				if pair.method != "terminal/create" || pair.noCWD {
					continue
				}
				command, _ := pair.hookInput["command"].(string)
				if hook, _ := env.kiroHook(t, pair.hookTool, pair.hookInput, true); !acpBlocked(hook) || len(command) > 4<<10 {
					continue
				}
				tried++
				padded := "# " + strings.Repeat("x", 9<<10) + "\n" + command + "\n# " + strings.Repeat("y", acp.MaxToolCallStateBytes)
				report := acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
					"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": "Run", "rawInput": map[string]any{"command": padded}}})
				// GAP-0462/F3, through the guard's own flow (Peek, evaluate, Commit).
				{
					var tracker acp.ToolCallTracker
					forward := func(frame []byte) acp.Verdict {
						msg := acpParsedFrame(t, frame)
						env.toolCallState = tracker.Peek(msg)
						defer func() { env.toolCallState = nil }()
						verdict := env.evaluate(t, acp.AgentToClient, frame)
						tracker.Commit(msg, verdict.JudgedBlock())
						return verdict
					}
					forward(acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
						"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "title": "Run", "rawInput": map[string]any{"command": "ls"}}}))
					updateJudged := forward(acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
						"sessionUpdate": "tool_call_update", "toolCallId": "t", "title": "`" + padded + "`", "rawInput": map[string]any{"command": padded}}}))
					state := tracker.Peek(acpParsedFrame(t, acpIDOnlyPermission(t)))
					if !strings.Contains(string(state), `"truncated":true`) || strings.Contains(string(state), `"command":"ls"`) {
						t.Fatalf("GAP-0462/F3 %s: the oversized update was not kept cut: %.200s", pair.id, state)
					}
					got := permission(state)
					if updateJudged.JudgedBlock() {
						f3UpdateBlocks++
					}
					switch {
					case acpBlocked(got.RawAction):
						f3Blocks++
					case updateJudged.JudgedBlock() || got.RawAction != "alert" || pack == "strict":
						t.Errorf("GAP-0462/F3 %s: %s %s after an update judged a block %v, want a block (or the unknown tier when it was not)",
							pair.id, got.RawAction, got.Severity, updateJudged.JudgedBlock())
					case f3Example == "":
						f3Example = fmt.Sprintf("%s: %s %s", pair.id, got.RawAction, got.Severity)
					}
				}
				judged := env.evaluate(t, acp.AgentToClient, report)
				if !judged.JudgedBlock() {
					continue
				}
				reportBlocks++
				var tracker acp.ToolCallTracker
				tracker.Commit(acpParsedFrame(t, report), judged.JudgedBlock())
				state := tracker.Peek(acpParsedFrame(t, acpIDOnlyPermission(t)))
				if !strings.Contains(string(state), `"truncated":true`) {
					t.Fatalf("%s: the padded command was not cut (%d bytes of state)", pair.id, len(state))
				}
				if got := permission(state); acpBlocked(got.RawAction) {
					permissionBlocks++
				} else if example == "" {
					example = fmt.Sprintf("%s: %s %s", pair.id, got.RawAction, got.Severity)
				}
			}
			t.Logf("%s: %d padded commands, %d reports judged a block, %d id-only permissions blocked", pack, tried, reportBlocks, permissionBlocks)
			t.Logf("%s: GAP-0462/F3: %d of %d id-only permissions blocked after an oversized update with a padded title (%d updates judged a block; e.g. %s)",
				pack, f3Blocks, tried, f3UpdateBlocks, f3Example)
			if f3UpdateBlocks < tried-2 || f3Blocks < f3UpdateBlocks || pack == "strict" && f3Blocks != tried {
				t.Errorf("GAP-0462/F3: %d of %d blocked, %d updates judged a block", f3Blocks, tried, f3UpdateBlocks)
			}
			if tried < 25 || reportBlocks < tried-2 || permissionBlocks != reportBlocks {
				t.Errorf("%d of %d permissions after a report judged a block are blocked (e.g. %s)", permissionBlocks, reportBlocks, example)
			}
			// A dropped call keeps the mark; without it a dropped call is still the unknown tier.
			if got := permission(json.RawMessage(`{"dropped":true,"flagged":true}`)); !acpBlocked(got.RawAction) {
				t.Errorf("a dropped call whose report was judged a block: %+v, want a block", got)
			}
			got := permission(json.RawMessage(`{"dropped":true}`))
			if pack == "strict" && !acpBlocked(got.RawAction) || pack != "strict" && got.RawAction != "alert" {
				t.Errorf("a dropped call: %+v, want the unknown tier", got)
			}
			// The mark decides on its own: the kept call may show nothing else.
			if got := permission(json.RawMessage(`{"kind":"execute","rawInput":{"command":"ls"},"flagged":true}`)); !acpBlocked(got.RawAction) {
				t.Errorf("a permission for a call whose report was judged a block: %+v", got)
			}
		})
	}
}

// TestACPOversizedStateKeepsItsFirstLocations: a tool_call whose locations
// alone pass the guard's state bound, the fixtures' Write target first and
// 1,200 workspace files after it. The guard keeps the first locations, so the
// permission that names only the id is judged on them: a block, as with 70
// locations (ACP review round 4, P3-2).
func TestACPOversizedStateKeepsItsFirstLocations(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	env.sessionCWD = ""
	var tried, blocked int
	example := ""
	for _, pair := range pairs {
		if pair.method != "fs/write_text_file" {
			continue
		}
		path, _ := pair.hookInput["path"].(string)
		if hook, _ := env.kiroHook(t, pair.hookTool, pair.hookInput, false); !acpBlocked(hook) {
			continue
		}
		tried++
		locations := []any{map[string]any{"path": path}}
		for i := 0; i < 1200; i++ {
			locations = append(locations, map[string]any{"path": filepath.Join(env.project, fmt.Sprintf("src/pkg%04d/file_with_a_long_name_%04d.go", i, i))})
		}
		var tracker acp.ToolCallTracker
		tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
			"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "edit", "title": "Edit files", "locations": locations}})), false)
		env.toolCallState = tracker.Peek(acpParsedFrame(t, acpIDOnlyPermission(t)))
		got := env.evaluate(t, acp.AgentToClient, acpIDOnlyPermission(t))
		env.toolCallState = nil
		if acpBlocked(got.RawAction) {
			blocked++
		} else if example == "" {
			example = fmt.Sprintf("%s: %s %s", pair.id, got.RawAction, got.Severity)
		}
	}
	t.Logf("%d of %d id-only permissions for an oversized edit whose first location the hook blocks are blocked", blocked, tried)
	if tried < 50 || blocked != tried {
		t.Errorf("%d of %d are not blocked (e.g. %s)", tried-blocked, tried, example)
	}
}

// TestACPKindlessCommandWithTextToWriteIsAlsoTheWrite: Kiro's write tools name
// their operation in command (create, str_replace). A permission that leaves out
// the kind is then a shell call and also the write of its path, and the
// stronger verdict decides: the fixtures' Write targets the hook blocks are
// blocked, where the shell call alone was only the unknown tier, and a
// workspace file written this way is clean (ACP review round 4, P3-3).
func TestACPKindlessCommandWithTextToWriteIsAlsoTheWrite(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			permission := func(input map[string]any) acp.Verdict {
				return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission",
					map[string]any{"sessionId": "s", "options": []any{}, "toolCall": map[string]any{"toolCallId": "t", "title": "Write", "rawInput": input}}))
			}
			env.sessionCWD = ""
			var tried, blocked int
			example := ""
			for _, pair := range pairs {
				if pair.method != "fs/write_text_file" {
					continue
				}
				path, _ := pair.hookInput["path"].(string)
				content, _ := pair.hookInput["content"].(string)
				if hook, _ := env.kiroHook(t, pair.hookTool, pair.hookInput, false); !acpBlocked(hook) {
					continue
				}
				tried++
				if got := permission(map[string]any{"command": "create", "path": path, "file_text": content}); acpBlocked(got.RawAction) {
					blocked++
				} else if example == "" {
					example = fmt.Sprintf("%s: %s %s", pair.id, got.RawAction, got.Severity)
				}
			}
			t.Logf("%s: %d of %d kind-less Kiro creates the hook blocks are blocked", pack, blocked, tried)
			if tried < 50 || blocked != tried {
				t.Errorf("%d of %d are not blocked (e.g. %s)", tried-blocked, tried, example)
			}
			// A workspace file written this way is clean where the session directory is known.
			env.sessionCWD = env.project
			if got := permission(map[string]any{"command": "create", "path": filepath.Join(env.project, "notes.txt"), "file_text": "hello"}); got.Action != "allow" || got.RawAction != "allow" {
				t.Errorf("a kind-less create of a workspace file: %+v, want a plain allow", got)
			}
		})
	}
}

// TestACPKiroNewStrWriteIsJudgedByItsText: Kiro's append, insert and create
// with a null file_text write their new_str, and the hook judges that text with
// the write check, as the content of the write_file it projects
// (connector.kiroRequiredWriteFileView). The ACP permission for the same call,
// with or without the kind, judges it too: for every text the hook's write
// check finds something in, a workspace file, the permission has a finding and
// is never below the hook's verdict (ACP review round 5, P4-1). Cases by id;
// the texts are secret-shaped values and the fixtures' written contents and
// shell commands.
func TestACPKiroNewStrWriteIsJudgedByItsText(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	texts := []string{"aws_access_key_id = AKIA7G4N2K9Q6M8R3T5V\n", "token: ghp_A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5\n"}
	for _, pair := range pairs {
		switch pair.method {
		case "fs/write_text_file":
			if content, _ := pair.hookInput["content"].(string); content != "" {
				texts = append(texts, content)
			}
		case "terminal/create":
			if command, _ := pair.hookInput["command"].(string); command != "" {
				texts = append(texts, command)
			}
		}
	}
	shapes := []struct {
		id, kind string
		input    func(path, text string) map[string]any
	}{
		{"P4-1/K1 kind-less append", "", func(p, c string) map[string]any { return map[string]any{"command": "append", "path": p, "new_str": c} }},
		{"P4-1/K2 edit append", "edit", func(p, c string) map[string]any { return map[string]any{"command": "append", "path": p, "new_str": c} }},
		{"P4-1/K3 kind-less insert", "", func(p, c string) map[string]any {
			return map[string]any{"command": "insert", "path": p, "insert_line": 1, "new_str": c}
		}},
		{"P4-1/K4 kind-less create, null file_text", "", func(p, c string) map[string]any {
			return map[string]any{"command": "create", "path": p, "file_text": nil, "new_str": c}
		}},
		{"P4-1/K5 edit create, null file_text", "edit", func(p, c string) map[string]any {
			return map[string]any{"command": "create", "path": p, "file_text": nil, "new_str": c}
		}},
	}
	rank := func(action string) int {
		switch {
		case acpBlocked(action):
			return 2
		case action == "alert":
			return 1
		}
		return 0
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			path := filepath.Join(env.project, "notes.txt")
			permission := func(kind string, input map[string]any) acp.Verdict {
				toolCall := map[string]any{"toolCallId": "t", "title": "Write", "rawInput": input}
				if kind != "" {
					toolCall["kind"] = kind
				}
				return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission",
					map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall}))
			}
			for _, shape := range shapes {
				var found, judged int
				example := ""
				for i, text := range texts {
					// The hook's write check on this text: the write_file it projects.
					check, rules := env.kiroHook(t, "fs_write", map[string]any{"command": "create", "path": path, "file_text": text}, true)
					if len(rules) == 0 {
						continue
					}
					found++
					got := permission(shape.kind, shape.input(path, text))
					if got.Severity != "" && got.Severity != "NONE" && rank(got.RawAction) >= rank(check) {
						judged++
					} else if example == "" {
						example = fmt.Sprintf("text %d: %s %s, the write check %s %v", i, got.RawAction, got.Severity, check, rules)
					}
				}
				t.Logf("%s: %s: %d of %d workspace writes the hook's write check finds something in are judged on their text", pack, shape.id, judged, found)
				if found == 0 || judged != found {
					t.Errorf("%s: %d of %d are not (e.g. %s)", shape.id, found-judged, found, example)
				}
			}
			// The same shapes writing plain text to a workspace file are clean.
			for _, shape := range shapes {
				if pack != "default" {
					break
				}
				if got := permission(shape.kind, shape.input(path, "hello\n")); got.Action != "allow" || got.RawAction != "allow" {
					t.Errorf("%s writing plain text to a workspace file: %+v", shape.id, got)
				}
			}
		})
	}
}
