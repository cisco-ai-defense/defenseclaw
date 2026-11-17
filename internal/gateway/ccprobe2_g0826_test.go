// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0826: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 48aed3d846 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// TestGAP0826AnalysisBoundRowsTakeTheUnknownTierOfThePack pins the five tiers
// of the GAP-0146 rows that are under the statement budget but past an
// action analysis bound (a 100-stage pipeline, 600 redirects of one echo).
// The bound is a bound-rule cap for any call (rel-1-0-10:GAP-0688, the one
// bound rule): with no proven finding the answer is the unknown tier of the
// pack, an alert in default, permissive and managed (default pack) and a
// block in strict and managed-strict, by ACTION-COMPOUND-LIMIT and never as
// an SSH keys mutation. A short echo list stays allowed (GAP-0826).
func TestCCP2G0826_GAP0826AnalysisBoundRowsTakeTheUnknownTierOfThePack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the rows are POSIX shell text")
	}
	cwd := t.TempDir()
	var redirects strings.Builder
	redirects.WriteString("echo hi")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&redirects, " > ordinary/r%d", i)
	}
	rows := []struct {
		name, command string
		bounded       bool
	}{
		{"echo_only n=100", gap0146Statements("echo_only", 100), false},
		{"pipeline n=100", gap0146Statements("pipeline", 100), true},
		{"600 redirects", redirects.String(), true},
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		for _, row := range rows {
			out := gap0437Hook(t, hook, cwd, p.name+row.name, row.command)
			raw, _ := json.Marshal(out)
			want := "allow"
			if row.bounded {
				want = "alert"
				if p.pack == "strict" {
					want = "block"
				}
			}
			limited := strings.Contains(string(raw), "ACTION-COMPOUND-LIMIT")
			if out["action"] != want || limited != row.bounded || strings.Contains(string(raw), "persistence.ssh_authorized_keys_command") {
				t.Errorf("%s %s: action %v (limit %t), want %s (limit %t): %.300s", p.name, row.name, out["action"], limited, want, row.bounded, raw)
			}
		}
	}
}
