// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// The write evidence lists the file a native write call writes when the
// call carries a field outside its reviewed schema: a Copilot CLI edit's
// description and create's mode (the gateway judges the call without
// them), and an unknown key beside a reviewed target key (the gateway
// judges that target, actionfacts.UnknownKeyWriteTargetViews). The
// evidence listed no target for these and carried no incomplete marker.
func TestWriteEvidenceListsTheTargetOfCallsWithExtraFields(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cwd, "deploy.cfg")
	body := func(v map[string]any) []byte {
		v["cwd"] = cwd
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	text := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, row := range []struct {
		name, connector string
		body            []byte
	}{
		{"copilot edit with a description", "copilot", body(map[string]any{"toolName": "edit",
			"toolArgs": text(map[string]any{"path": "deploy.cfg", "old_str": "a", "new_str": "b", "description": "d"})})},
		{"copilot create with a mode", "copilot", body(map[string]any{"toolName": "create",
			"toolArgs": map[string]any{"path": target, "file_text": "b", "mode": "0600"}})},
		{"claude code edit with an unknown key", "", body(map[string]any{"tool_name": "Edit",
			"tool_input": map[string]any{"file_path": target, "old_string": "a", "new_string": "b", "description": "d"}})},
		{"opencode write with an unknown key", "opencode", body(map[string]any{"tool_name": "write",
			"tool_input": map[string]any{"filePath": "deploy.cfg", "content": "b", "description": "d"}})},
	} {
		t.Run(row.name, func(t *testing.T) {
			targets, ok := Decode(ResolveConnector(row.connector, "", "preToolUse", row.body))
			if !ok {
				t.Fatal("evidence does not decode")
			}
			if resolved, listed := targets[target]; !listed || resolved == "" {
				t.Fatalf("evidence %v does not list %s", targets, target)
			}
		})
	}
}
