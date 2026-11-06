// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0488ArchiveNonExtractionMoveFourCell(t *testing.T) {
	f := gx054Fixture(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	for _, dir := range []string{"conf", "src", "app"} {
		if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"conf/config.sample", "rc.sample"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, command, want string }{
		{"create then ordinary move", "tar -czf out.tgz src && mv conf/config.sample conf/config", "allow"},
		{"list then ordinary move", "tar -tzf pkg.tgz && mv rc.sample rc", "allow"},
		{"ordinary move twin", "mv conf/config.sample conf/config", "allow"},
		{"create then protected move", "tar -czf out.tgz src && mv conf/config.sample ~/.ssh/authorized_keys", "protected"},
		{"create then protected link write", "tar -czf out.tgz src && echo k >> keylink", "protected"},
		{"extract then protected move", "tar -xzf missing.tgz -C app && mv app/authorized_keys app/out", "protected"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					if err := os.Chmod(f.homes, 0o700); err != nil {
						t.Fatal(err)
					}
					id := fmt.Sprintf("g488-archive-%s-%s-%s-%t", row.name, connector, cell.pack, cell.managed)
					payload := mustJSON(t, map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project,
						"permission_mode": "default", "tool_name": "Bash", "tool_use_id": id,
						"tool_input": map[string]any{"command": row.command, "description": "fixture"}})
					header := f.clientHeader(t, payload)
					if got := gx054Verdict(t, f, connector, cell.pack, payload, header, cell.managed); got != row.want {
						t.Errorf("%s pack=%q managed=%t: got %s, want %s", connector, cell.pack, cell.managed, got, row.want)
					}
				}
			}
		})
	}
}
