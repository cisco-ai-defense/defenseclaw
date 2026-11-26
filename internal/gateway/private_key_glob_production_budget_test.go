// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestPrivateKeyGlobOfACallWithNoFolderAnswersInsideTheProductionBudgetInEveryPack
// is rel-1-0-10:GAP-2262: the answer of every rule pack is held to the
// production scan budget, the 200 ms deadline of the route.
//
// 1.0.10 ran each pack once on that deadline and failed on a 504. The
// private-key-glob bound test of rel then moved to the CPU time of the answers
// (GAP-0708: a wall-clock bar fails on a loaded shared box) and gave every pack
// a 30 s deadline, so a pack that waits without using the CPU (a lock, a sleep,
// a blocked read) passed it: its work never showed in the CPU time and its
// deadline never came. This test is that 1.0.10 check again: one run of each
// row per pack on the real deadline, and one retry when that run answered 504,
// so a pause of the box (the load of a shared runner) does not fail it and a
// pack that stalls does: the stall comes again in the retry.
//
// The rows are those of the CPU-bar test: an OpenClaw call with no folder,
// $PWD/<path>/*/* over 8 folders of 600 files, past the cap of the glob reader
// (the answer is the unknown tier of the pack with the cap named); the same
// folder with a link to a private key in its first folder, which the walk
// reaches before the cap (a block in every pack, so a stall on the path that
// finds a key is seen too); the two spellings of the home's .ssh key; and the
// four cells of the gap itself, on the host's /, which rel allows or the pack
// gives the unknown tier (they alone reach the walk of a folder it cannot read).
// Default is judged as well as the other packs: the CPU-bar test gives it a
// 30 s deadline too. Not under -race: the race build scales the deadline.
func TestPrivateKeyGlobOfACallWithNoFolderAnswersInsideTheProductionBudgetInEveryPack(t *testing.T) {
	if hookAnswerRaceBuild {
		t.Skip("the race build scales the scan deadline; the production budget is judged without it")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	wideFolder := func(name string) string {
		dir := filepath.Join(root, name)
		for folder := range 8 {
			sub := filepath.Join(dir, fmt.Sprintf("d%d", folder))
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			for file := range 600 {
				if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%03d", file)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	wide := wideFolder("wide")
	// The same folder with a link to the key in its first folder, which the
	// walk reads before the cap.
	linked := wideFolder("linked")
	if err := os.MkdirAll(filepath.Join(linked, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(linked, "a", "k")); err != nil {
		t.Fatal(err)
	}
	// $PWD is the empty folder: $PWD/<path> spells the absolute path.
	spell := func(head, dir, pattern string) string { return head + strings.TrimPrefix(dir, "/") + "/" + pattern }
	param, subst := "$"+"PWD/", "$("+"pwd)/"
	const unknown, block, atLeastUnknown, relOrUnknown = "unknown", "block", "at least unknown", "rel or unknown"
	rows := []struct{ command, want string }{
		{"cat " + spell(param, wide, "*/*"), unknown},
		{"cp " + spell(param, wide, "*/*") + " /tmp/staged", unknown},
		{"head -n1 " + spell(subst, wide, "[a-z]*/*"), unknown},
		{"grep -l k " + spell(subst, wide, "*/*"), unknown},
		{"cat " + spell(param, linked, "*/*"), block},
		{"head -n1 " + spell(subst, home, ".ssh/id_*"), block},
		{"cat " + spell(param, home, ".ssh/id_ed25519"), atLeastUnknown},
		// The gap's own cells, on the host's /: rel allows them, or the pack gives
		// the unknown tier. They alone reach the walk of a folder it cannot read.
		{"cat " + param + "*/*", relOrUnknown},
		{"cp " + param + "*/* /tmp/staged", relOrUnknown},
		{"head -n1 " + subst + "[a-z]*/*", relOrUnknown},
		{"grep -l k " + subst + "*/*", relOrUnknown},
	}
	capReason := bounded.ReasonCode + " cap=" + bounded.Paths.String()
	answer := func(a *APIServer, command string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": ""}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.handleInspectTool(rec, req)
		return rec
	}
	judged, warmed := 0, false
	for _, p := range gap0437Packs {
		// The production deadline, as gap0437Server sets it (inspectScanTimeout
		// scaled by raceScanBudgetScale, which is 1 here): nothing raises it.
		a := gap0437Server(t, p, "openclaw", "action")
		if a.inspectToolScanTimeout != inspectScanTimeout {
			t.Fatalf("%s: scan deadline %s, want the production %s", p.name, a.inspectToolScanTimeout, inspectScanTimeout)
		}
		if !warmed {
			// One untimed answer reads the first wide folder cold, so the one
			// retry below is left for a pause of the box.
			answer(a, rows[0].command)
			warmed = true
		}
		tier := "alert"
		if p.pack == "strict" {
			tier = "block"
		}
		for _, row := range rows {
			var rec *httptest.ResponseRecorder
			for attempt := 1; attempt <= 2; attempt++ {
				rec = answer(a, row.command)
				judged++
				if rec.Code != http.StatusGatewayTimeout {
					break
				}
			}
			if rec.Code != http.StatusOK {
				t.Errorf("%s %.60q: status %d after one retry on the production %s deadline, want 200 (a pack that stalls without CPU answers 504 both times): %s",
					p.name, row.command, rec.Code, inspectScanTimeout, rec.Body.String())
				continue
			}
			var out map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("%s %.60q: answer %q: %v", p.name, row.command, rec.Body.String(), err)
			}
			action, _ := out["action"].(string)
			if action == "" {
				action = "allow"
			}
			truncated := strings.Contains(rec.Body.String(), capReason)
			switch row.want {
			case unknown:
				if action != tier || !truncated {
					t.Errorf("%s %.60q: %s (truncated %v), want the unknown tier %s with %q", p.name, row.command, action, truncated, tier, capReason)
				}
			case block:
				if action != "block" {
					t.Errorf("%s %.60q: %s, want block", p.name, row.command, action)
				}
			case atLeastUnknown:
				if action != tier && action != "block" {
					t.Errorf("%s %.60q: %s, want at least the unknown tier %s", p.name, row.command, action, tier)
				}
			case relOrUnknown:
				if action != "allow" && (action != tier || !truncated) {
					t.Errorf("%s %.60q: %s (truncated %v), want rel's allow or the unknown tier %s", p.name, row.command, action, truncated, tier)
				}
			}
		}
	}
	if judged == 0 {
		t.Fatal("no cell judged")
	}
}
