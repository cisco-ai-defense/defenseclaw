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
			var tried, reportBlocks, permissionBlocks int
			example := ""
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
