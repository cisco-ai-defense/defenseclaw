// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"testing"
)

func TestNativeFileToolViewMapsExactShapes(t *testing.T) {
	for _, tc := range []struct {
		name, tool, args string
		wantTool, want   string
		ok               bool
	}{
		{"agy write", "write_to_file", `{"TargetFile":"/p/a.txt","CodeContent":"x","EmptyFile":false}`, "Write", `{"content":"x","file_path":"/p/a.txt"}`, true},
		{"agy empty write", "write_to_file", `{"TargetFile":"/p/a.txt","EmptyFile":true,"toolAction":"Writing"}`, "Write", `{"content":"","file_path":"/p/a.txt"}`, true},
		{"agy edit", "replace_file_content", `{"TargetFile":"/p/a.txt","TargetContent":"o","ReplacementContent":"n","AllowMultiple":true}`, "Edit", `{"file_path":"/p/a.txt","new_string":"n","old_string":"o","replace_all":true}`, true},
		{"agy view", "view_file", `{"AbsolutePath":"/p/a.txt","StartLine":1,"EndLine":9}`, "Read", `{"file_path":"/p/a.txt"}`, true},
		{"amp edit", "edit_file", `{"path":"/p/a.txt","old_str":"o","new_str":"n"}`, "Edit", `{"file_path":"/p/a.txt","new_string":"n","old_string":"o"}`, true},
		{"copilot view", "view", `{"path":"/p/a.txt","view_range":[1,5]}`, "Read", `{"file_path":"/p/a.txt"}`, true},
		// Anything else leaves the call as it was.
		{"unknown key", "edit_file", `{"path":"/p/a.txt","old_str":"o","new_str":"n","mode":"x"}`, "edit_file", "", false},
		{"missing old", "edit_file", `{"path":"/p/a.txt","new_str":"n"}`, "edit_file", "", false},
		{"blank path", "view", `{"path":"  "}`, "view", "", false},
		{"duplicate key", "view", `{"path":"/a","path":"/b"}`, "view", "", false},
		{"no content", "write_to_file", `{"TargetFile":"/p/a.txt"}`, "write_to_file", "", false},
		{"typed wrong", "view_file", `{"AbsolutePath":7}`, "view_file", "", false},
		{"other tool", "Write", `{"file_path":"/p/a.txt","content":"x"}`, "Write", "", false},
	} {
		tool, out, ok := NativeFileToolView(tc.tool, json.RawMessage(tc.args))
		if ok != tc.ok || tool != tc.wantTool {
			t.Errorf("%s: got %s %v, want %s %v", tc.name, tool, ok, tc.wantTool, tc.ok)
			continue
		}
		if !ok {
			if string(out) != tc.args {
				t.Errorf("%s: arguments changed on refusal", tc.name)
			}
			continue
		}
		var got, want any
		_ = json.Unmarshal(out, &got)
		_ = json.Unmarshal([]byte(tc.want), &want)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if string(g) != string(w) {
			t.Errorf("%s: got %s, want %s", tc.name, g, w)
		}
	}
}

func TestCursorTrustedReadArgs(t *testing.T) {
	out, ok := CursorTrustedReadArgs("beforeReadFile", json.RawMessage(`{"hook_event_name":"beforeReadFile","file_path":"/p/a","content":"","conversation_id":"c"}`))
	if !ok || string(out) != `{"file_path":"/p/a"}` {
		t.Fatalf("got %s %v", out, ok)
	}
	for _, tc := range []struct{ event, payload string }{
		{"beforeShellExecution", `{"file_path":"/p/a"}`},
		{"beforeReadFile", `{"content":""}`},
		{"beforeReadFile", `{"file_path":""}`},
		{"beforeReadFile", `{"file_path":"/a","file_path":"/b"}`},
	} {
		if _, ok := CursorTrustedReadArgs(tc.event, json.RawMessage(tc.payload)); ok {
			t.Errorf("%s %s: projected", tc.event, tc.payload)
		}
	}
}
