// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1016 (requested by agent-hook): native Copilot CLI sends a model's
// parallel tool calls as one toolCalls envelope. The hook evidence read one
// call only and was incomplete for more, so a managed gateway that cannot
// traverse the private home had no client evidence for a parallel create.
// Each call is now described and the maps are merged.
func TestResolveConnectorDescribesParallelCopilotCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	a, b := filepath.Join(project, "a.txt"), filepath.Join(project, "b.txt")
	call := func(id, path string) map[string]any {
		return map[string]any{"id": id, "name": "create", "args": map[string]any{"path": path, "file_text": "x\n"}}
	}
	resolve := func(calls []any) map[string]string {
		payload, err := json.Marshal(map[string]any{"cwd": project, "toolCalls": calls})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("copilot", "", "preToolUse", payload))
		if !ok {
			t.Fatal("no decodable write evidence")
		}
		return targets
	}
	targets := resolve([]any{call("c1", a), call("c2", b)})
	if targets[TruncatedKey] != "" || targets[a] == "" || targets[b] == "" {
		t.Fatalf("two parallel creates: %v", targets)
	}
	// A call that is not one fully named call keeps the map incomplete.
	if got := resolve([]any{call("c1", a), map[string]any{"name": "create"}}); got[TruncatedKey] != "1" {
		t.Fatalf("malformed parallel call: %v", got)
	}
}
