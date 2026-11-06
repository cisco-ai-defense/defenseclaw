// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"os"
	"testing"
)

// GAP-0056 class guard: testdata/codeguard_exec_001.json holds every line
// the substring rule (base d37eafc351) reported as CG-EXEC-001 that runs a
// command or code string ("match": the fixer's positive corpus and the
// independent review's near variants) and the method, name, list-form and
// comment lines it reported wrongly ("no_match"). No true positive may be
// lost and no false positive may come back.
func TestCodeGuardExecClassCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/codeguard_exec_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Match   []struct{ Ext, Line string } `json:"match"`
		NoMatch []struct{ Ext, Line string } `json:"no_match"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Match) < 130 || len(corpus.NoMatch) < 75 {
		t.Fatalf("corpus has %d match and %d no_match rows, want the full guard", len(corpus.Match), len(corpus.NoMatch))
	}
	s := NewCodeGuardScanner("")
	has := func(ext, content string) bool {
		for _, f := range s.ScanContent("/src/app"+ext, content) {
			if f.ID == "CG-EXEC-001" {
				return true
			}
		}
		return false
	}
	for _, row := range corpus.Match {
		if !has(row.Ext, row.Line) {
			t.Errorf("%s %q: lost CG-EXEC-001 true positive", row.Ext, row.Line)
		}
	}
	for _, row := range corpus.NoMatch {
		if has(row.Ext, row.Line) {
			t.Errorf("%s %q: CG-EXEC-001 false positive", row.Ext, row.Line)
		}
	}
}
