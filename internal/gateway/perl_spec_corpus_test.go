// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
)

type perlSpecCorpusRow struct {
	File string `json:"file"`
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Rel  string `json:"rel"`
	Spec string `json:"spec"`
}

var perlSpecCorpusOnce sync.Once
var perlSpecCorpusRows map[string]perlSpecCorpusRow
var perlSpecCorpusErr error

func perlSpecCorpus() (map[string]perlSpecCorpusRow, error) {
	perlSpecCorpusOnce.Do(func() {
		data, err := os.ReadFile("testdata/perl_spec_corpus.json")
		if err != nil {
			perlSpecCorpusErr = err
			return
		}
		var rows []perlSpecCorpusRow
		if err := json.Unmarshal(data, &rows); err != nil {
			perlSpecCorpusErr = err
			return
		}
		perlSpecCorpusRows = make(map[string]perlSpecCorpusRow, len(rows))
		for _, row := range rows {
			perlSpecCorpusRows[row.File+"|"+row.ID] = row
		}
	})
	return perlSpecCorpusRows, perlSpecCorpusErr
}

func perlSpecCorpusAssert(t *testing.T, file, id, kind, profile, got string) {
	t.Helper()
	rows, err := perlSpecCorpus()
	if err != nil {
		t.Fatal(err)
	}
	row, ok := rows[file+"|"+id]
	if !ok {
		t.Fatalf("§2.1 case missing: %s %s", file, id)
	}
	if row.Kind != kind {
		t.Fatalf("%s: kind %s, want %s", id, kind, row.Kind)
	}
	want := "allow"
	if row.Spec == "LB" {
		if profile == "strict" {
			want = "block"
		} else {
			want = "alert"
		}
	}
	if got != want {
		t.Errorf("%s/%s: action=%s, want=%s; rel=%s spec=%s", file, id, got, want, row.Rel, row.Spec)
	}
}

func TestPerlSpecCorpusTableCounts(t *testing.T) {
	rows, err := perlSpecCorpus()
	if err != nil {
		t.Fatal(err)
	}
	raise, equal, lower := 0, 0, 0
	for _, row := range rows {
		switch {
		case row.Rel == row.Spec:
			equal++
		case row.Rel == "AA" && row.Spec == "LB":
			raise++
		default:
			lower++
		}
	}
	if len(rows) != 190 || raise != 97 || equal != 93 || lower != 0 {
		t.Fatalf("ids=%d raise=%d equal=%d lower=%d", len(rows), raise, equal, lower)
	}
}

func TestPerlSpecFocusedP09RelInPlace(t *testing.T) {
	h := newGAP0048Home(t)
	cmd := `perl -i -pe 's/defenseclaw/x/' .claude/settings.json`
	for _, tc := range []struct{ profile, want string }{
		{"default", "alert"}, {"strict", "block"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			judge := newHookConfigJudge(t, "claudecode", tc.profile)
			got := hookConfigAction(judge(h.project, false, "Bash", map[string]any{"command": cmd}))
			if got != tc.want {
				t.Fatalf("P09 rel=%s spec=%s action=%s want=%s", "LB", "LB", got, tc.want)
			}
		})
	}
}
