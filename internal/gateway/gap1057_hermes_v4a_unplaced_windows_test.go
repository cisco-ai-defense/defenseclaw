// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestGAP1057HermesV4AUnplacedWindowsNameIsTheUnknownTier (rel-1-0-10:GAP-1057):
// a Hermes V4A patch whose header names its file by a Windows spelling no
// reader places (a drive-relative C:x, a device or namespace path) writes a
// file no path rule can name. Through Codex apply_patch and OpenCode patch the
// same envelope is judged at the unknown tier (GAP-1052); Hermes allowed it in
// every tier. Hermes is now never below Codex for the same envelope in any
// tier, and in the default tier an unplaced name is never a clean allow. The plain project file and a home form
// (which Hermes places in the home) keep their verdicts.
func TestGAP1057HermesV4AUnplacedWindowsNameIsTheUnknownTier(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	rows := []struct {
		id, env  string
		unplaced bool
	}{
		{"driverel", "*** Begin Patch\n*** Add File: C:decoy.txt\n+x\n*** End Patch", true},
		{"driverel-beside-plain", "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** Add File: C:decoy.txt\n+x\n*** End Patch", true},
		{"device", "*** Begin Patch\n*** Add File: \\\\.\\pipe\\decoy.txt\n+x\n*** End Patch", true},
		{"globalroot", "*** Begin Patch\n*** Delete File: \\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\decoy.txt\n*** End Patch", true},
		{"plain", "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch", false},
	}
	rank := map[string]int{"": 0, "allow": 0, "alert": 1, "confirm": 1, "block": 2}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"hermes", "codex"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		codexH := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
		for _, r := range rows {
			hermes := shapeParityHook(t, handlers["hermes"], shapeParityCall{name: "hermes/patch " + r.id, conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "patch", map[string]any{"mode": "patch", "patch": r.env})}, p.managed)
			codex := shapeParityHook(t, handlers["codex"], shapeParityCall{name: "codex/apply_patch " + r.id, conn: "codex", event: "PreToolUse",
				headers: codexH, body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": r.env})}, p.managed)
			switch {
			case r.unplaced && p.name == "default" && rank[hermes] == 0:
				t.Errorf("%s %s: hermes V4A %q, want the unknown tier at least (codex %q)", p.name, r.id, hermes, codex)
			case rank[hermes] < rank[codex]:
				t.Errorf("%s %s: hermes V4A %q weaker than codex apply_patch %q", p.name, r.id, hermes, codex)
			case !r.unplaced && hermes != "allow" && hermes != "":
				t.Errorf("%s %s: plain project patch %q, want allow", p.name, r.id, hermes)
			}
		}
	})
}
