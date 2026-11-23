// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// This test lives apart from judge_ft07_test.go because it calls
// shadowLaneVerdict (gap1058_shadow_lanes_test.go) and uses POSIX home and
// dot-directory paths; both files are !windows.

// rel-1-0-10:GAP-1071: an MCP file read or write of a path relative to the
// session folder is judged as the native tool judges the same file.
func TestFT07MCPRelativePathIsJudgedLikeTheNativeTool(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		n := 0
		verdict := func(tool string, input map[string]any) string {
			n++
			id := "ft07-1071-" + p.name + "-" + strconv.Itoa(n)
			return shadowLaneVerdict(gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": id, "cwd": ssh,
				"tool_name": tool, "tool_use_id": "tu-" + id, "tool_input": input,
			}))
		}
		abs := filepath.Join(ssh, "id_rsa")
		nativeRead := verdict("Read", map[string]any{"file_path": abs})
		nativeWrite := verdict("Write", map[string]any{"file_path": abs, "content": "x"})
		for _, tc := range []struct {
			name, tool string
			input      map[string]any
			want       string
		}{
			{"read", "mcp__filesystem__read_file", map[string]any{"path": "id_rsa"}, nativeRead},
			{"read ./", "mcp__filesystem__read_file", map[string]any{"path": "./id_rsa"}, nativeRead},
			{"read up", "mcp__filesystem__read_file", map[string]any{"path": "../.ssh/id_rsa"}, nativeRead},
			{"write", "mcp__filesystem__write_file", map[string]any{"path": "id_rsa", "content": "x"}, nativeWrite},
		} {
			if got := verdict(tc.tool, tc.input); got != tc.want {
				t.Errorf("%s %s: MCP relative path is %s, the native tool gives %s", p.name, tc.name, got, tc.want)
			}
		}
		if nativeRead[0] == 'A' && nativeWrite[0] == 'A' {
			t.Errorf("%s: setup: the native tool allows both (%s, %s)", p.name, nativeRead, nativeWrite)
		}
	}
}
