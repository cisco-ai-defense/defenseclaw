// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// tdetectVerdict is the action the tool-inspect route answers for one shell
// command in one pack (rel-1-0-10 S7 train T-DETECT: the five tiers are the
// packs of gap0437Packs).
func tdetectVerdict(t *testing.T, a *APIServer, command string) (action string, raw map[string]any) {
	t.Helper()
	out := gap0437Inspect(t, a, t.TempDir(), command)
	action, _ = out["action"].(string)
	return action, out
}

// tdetectRow is one call and the verdict it must get in each of the five tiers
// (default, strict, permissive, managed, managed-strict: the order of
// gap0437Packs). "A" is allow, "L" alert, "B" block.
type tdetectRow struct {
	id      string
	command string
	want    string
}

func tdetectRunRows(t *testing.T, rows []tdetectRow) {
	t.Helper()
	letter := map[string]string{"allow": "A", "alert": "L", "block": "B"}
	for pi, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
			"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
		})
		for _, r := range rows {
			if len(r.want) != len(gap0437Packs) {
				t.Fatalf("%s: want %q needs %d letters", r.id, r.want, len(gap0437Packs))
			}
			action, out := tdetectVerdict(t, a, r.command)
			if got := letter[action]; got != r.want[pi:pi+1] {
				t.Errorf("%s %s: verdict %s (%s), want %s: %v", p.name, r.id, got, strings.TrimSpace(action), r.want[pi:pi+1], out)
			}
		}
	}
}
