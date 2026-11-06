// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"fmt"
	"os"
	"testing"
)

func TestGX054ExtractedLinkAllWritersFourCell(t *testing.T) {
	rows := []struct{ name, command string }{
		{"cp", "tar -xf sshdir.tar -C d1 && cp a.txt d1/s/config"},
		{"install", "tar -xf sshdir.tar -C d1 && install -m 600 a.txt d1/s/rc"},
		{"rsync", "tar -xf sshdir.tar -C d1 && rsync a.txt d1/s/environment"},
		{"ditto", "tar -xf sshdir.tar -C d1 && ditto a.txt d1/s/config"},
		{"ln", "tar -xf sshdir.tar -C d1 && ln -s a.txt d1/s/rc"},
		{"tee", "tar -xf sshdir.tar -C d1 && tee d1/s/config < a.txt"},
		{"dd", "tar -xf sshdir.tar -C d1 && dd if=a.txt of=d1/s/rc"},
		{"redirect", "tar -xf sshdir.tar -C d1 && echo note > d1/s/environment"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := rv4oFixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			for _, connector := range []string{"claudecode", "codex"} {
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					os.Chmod(f.homes, 0o700)
					id := fmt.Sprintf("writer-%s-%s-%t", row.name, cell.pack, cell.managed)
					body := map[string]any{"session_id": id, "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default", "tool_name": "Bash", "tool_use_id": id, "tool_input": map[string]any{"command": row.command}}
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
		})
	}
}
