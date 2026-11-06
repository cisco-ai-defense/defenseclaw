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
// command or code string, with the NFKC and heredoc forms the tightened rule
// adds ("match": the fixer's positive corpus and the independent review's
// near variants, rounds 1 to 7), and the method, name, list-form, Ruby
// block and comment lines it reported wrongly ("no_match"). No true positive may be
// lost and no false positive may come back. "reported_base_equal" are benign
// lines the base also reported that the round-7 subtraction cannot prove
// benign (an interpreter named in a non-program element, a runner with a
// run-time argument, an option it does not know): they stay reported until a
// precision pass proves them benign.
func TestCodeGuardExecClassCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/codeguard_exec_001.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Match   []struct{ Ext, Line string } `json:"match"`
		NoMatch []struct{ Ext, Line string } `json:"no_match"`
		Kept    []struct{ Ext, Line string } `json:"reported_base_equal"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Match) < 435 || len(corpus.NoMatch) < 185 {
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
	for _, row := range corpus.Kept {
		if !has(row.Ext, row.Line) {
			t.Errorf("%s %q: no longer reported; move it to no_match", row.Ext, row.Line)
		}
	}
	for _, row := range corpus.NoMatch {
		if has(row.Ext, row.Line) {
			t.Errorf("%s %q: CG-EXEC-001 false positive", row.Ext, row.Line)
		}
	}
}
