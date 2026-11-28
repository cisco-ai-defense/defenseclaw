// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP1984EffectFoldNeverLowersTheCall (rel-1-0-10:GAP-1984; DET111
// ruling on the fold, owner R-NOLOSS 2026-11-23): the GAP-1199 reading of an
// -EncodedCommand body split by control blanks and the GAP-1550 reading of a
// foreach header let the 1.0.10 reader see the body, and its findings now
// stand beside the effect finding of the call. The ruling-A fold dropped the
// effect finding into any 1.0.10 finding naming its set, also one with no
// proof that authorizes its rule (the nested decoded persistence finding of
// gap-1576 f11/f12): the call fell from block to allow under a CRITICAL
// finding. Every attack row keeps at least its T20 (23ee0d55e2) cell
// (action, then severity) in every tier on the Claude Code hook, and no
// benign twin rises above its T20 cell. The findings of those two readings
// raise the call but take no effect finding (DET111 ruling 2): folded into
// the HIGH tamper.detector_state_write they make, the CRITICAL
// effect.protected_target_restricted fell to HIGH under the same action
// while the plain spelling kept CRITICAL.
func TestGAP1984EffectFoldNeverLowersTheCall(t *testing.T) {
	rows := gap1984Rows(t)
	actionRank := map[string]int{"allow": 0, "alert": 1, "confirm": 2, "block": 3}
	sevRank := map[string]int{"": 0, "NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
	cell := func(s string) (int, int) {
		action, sev, _ := strings.Cut(s, " ")
		a, ok := actionRank[action]
		if !ok {
			t.Fatalf("cell %q: unknown action", s)
		}
		return a, sevRank[strings.ToUpper(sev)]
	}
	for _, windows := range []bool{false, true} {
		home := "/home/alice"
		if windows {
			home = `C:\Users\alice`
		}
		for ti, p := range gap0437Packs {
			t.Run(p.name+map[bool]string{false: "/posix", true: "/windows"}[windows], func(t *testing.T) {
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				prevHost, prevHome := windowsHookHost, sameHostHomeForTest
				windowsHookHost = func() bool { return windows }
				sameHostHomeForTest = ""
				if windows {
					sameHostHomeForTest = home
				}
				t.Cleanup(func() { windowsHookHost, sameHostHomeForTest = prevHost, prevHome })
				srv := gap0437Server(t, p, "claudecode", "action")
				installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
				h := srv.handleAgentHook("claudecode")
				for _, r := range rows {
					if r.windows != windows {
						continue
					}
					got := gap1984Send(t, h, p.managed, shapeParityEnvelope("PreToolUse", r.cwd, r.tool, map[string]any{"command": r.command}))
					ga, gs := cell(got)
					wa, ws := cell(r.t20[ti])
					switch {
					case r.attack && (ga < wa || ga == wa && gs < ws):
						t.Errorf("attack %s: %s, below the T20 cell %s", r.key, got, r.t20[ti])
					case !r.attack && (ga > wa || ga == wa && gs > ws):
						t.Errorf("benign twin %s: %s, above the T20 cell %s", r.key, got, r.t20[ti])
					}
				}
			})
		}
	}
}

type gap1984Row struct {
	key, tool, cwd, command string
	attack, windows         bool
	t20                     [5]string
}

// gap1984Rows reads testdata/gap1984_noloss_rows.tsv: the 44 DET111 attack
// rows the fold lowered (families r1/encoded-tabs and r1/foreach-header) and
// their 42 benign twins, each with its T20 hook-cc cell per tier.
func gap1984Rows(t *testing.T) []gap1984Row {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "gap1984_noloss_rows.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	unesc := strings.NewReplacer(`\\`, `\`, `\t`, "\t", `\n`, "\n", `\r`, "\r")
	var rows []gap1984Row
	attacks := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 11 {
			t.Fatalf("row %q: %d columns, want 11", col[0], len(col))
		}
		r := gap1984Row{key: col[0], attack: col[1] == "variant", tool: col[2], windows: col[3] == "true",
			cwd: unesc.Replace(col[4]), command: unesc.Replace(col[5])}
		copy(r.t20[:], col[6:])
		if r.attack {
			attacks++
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if attacks != 44 || len(rows) != 86 {
		t.Fatalf("%d rows, %d attack rows; want 86 and 44", len(rows), attacks)
	}
	return rows
}

// gap1984Send posts one Claude Code hook call and returns "action SEVERITY".
// A managed tier carries the hook path header the installed hook sends.
func gap1984Send(t *testing.T, h http.HandlerFunc, managedTier bool, body map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if managedTier {
		if ev := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out struct{ Action, Severity string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Action == "" {
		out.Action = "allow"
	}
	return out.Action + " " + strings.ToUpper(out.Severity)
}
