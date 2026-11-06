// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"fmt"
	"os"
	"testing"
)

func TestGX054UnfollowedArchiveProducerKeepsBaseDecision(t *testing.T) {
	for _, row := range []struct{ name, command string }{
		{"stream", "archive-reader link.tar | tar -xf - -C d1 && echo k >> d1/p"},
		{"earlier-write", "archive-reader link.tar > x.tar; tar -xf x.tar -C d1; echo k >> d1/p"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := rv4oFixture(t)
			t.Setenv("DEFENSECLAW_HOME", t.TempDir())
			for _, connector := range []string{"claudecode", "codex"} {
				for _, cell := range []struct {
					pack    string
					managed bool
				}{{"", false}, {"strict", false}, {"", true}, {"strict", true}} {
					id := fmt.Sprintf("fallback-%s-%s-%t", row.name, cell.pack, cell.managed)
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
					os.Chmod(f.homes, 0o700)
				}
			}
		})
	}
}
