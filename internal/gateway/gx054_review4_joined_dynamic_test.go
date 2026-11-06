// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGX054JoinedArchiveNamedTargetWithDynamicPlacement(t *testing.T) {
	f := rv4oFixture(t)
	path := filepath.Join(f.project, "absolute.tar")
	r107WriteTar(t, path, false, tar.Header{Name: "p", Typeflag: tar.TypeSymlink, Linkname: f.keys})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "part-a"), data[:100], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "part-b"), data[100:], 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	t.Setenv("TMPDIR", filepath.Join(f.project, "d1"))
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	command := "cat part-a part-b | tar -xf - -C $TMPDIR && echo note >> $TMPDIR/p"
	for _, connector := range []string{"claudecode", "codex"} {
		for _, cell := range []struct {
			pack    string
			managed bool
		}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
			os.Chmod(f.homes, 0o700)
			id := fmt.Sprintf("joined-%s-%t", cell.pack, cell.managed)
			body := map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": command}}
			if connector == "codex" {
				body["turn_id"] = "t-" + id
			}
			payload := mustJSON(t, body)
			header := rv4Header(t, f, connector, payload)
			got := rv4oPost(t, f.homes, f.home, connector, cell.pack, payload, header, cell.managed)
			if got == "A" || len(got) == 0 || got[len(got)-1] != '+' {
				t.Errorf("%s managed=%t pack=%q got %s, want protected block", connector, cell.managed, cell.pack, got)
			}
		}
	}
}
