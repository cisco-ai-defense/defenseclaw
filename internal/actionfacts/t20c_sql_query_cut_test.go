// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestT20COverLimitSQLQueryKeepsItsStatements (DET111 ruling on FIX-T20B):
// the inline query of a SQL client past the shell word bound is no plain
// data word with a stand-in query. The twin keeps the query with each long
// literal, quoted identifier and comment shortened, cut after its last
// complete statement within the bound, so the SQL readers see the
// statements. Red at a64bfdb931 (the query was a data word, twin "x").
func TestT20COverLimitSQLQueryKeepsItsStatements(t *testing.T) {
	big := strings.Repeat("a", 5000)
	many := strings.Repeat("SELECT 1; ", 600)
	rows := []struct {
		id, command string
		keep        []string // substrings of the twin
		drop        []string // not in the twin
	}{
		{"psql-c-long-identifier", `psql -d production -c "COPY \"` + big + `\" (c) TO PROGRAM 'id'"`,
			[]string{`COPY "x" (c) TO PROGRAM`, `-d production`}, nil},
		{"psql-c-statement-before-long-literal", `psql -d production -c "DROP TABLE users; SELECT '` + big + `'"`,
			[]string{`DROP TABLE users; SELECT`}, nil},
		{"psql-c-long-comment", `psql -c "/* ` + big + ` */ COPY t (c) TO PROGRAM 'id'"`,
			[]string{`COPY t (c) TO PROGRAM`}, []string{big[:100]}},
		{"psql-c-dollar-quote", `psql -c 'SELECT $$` + big + `$$; COPY t (c) TO PROGRAM $$id$$'`,
			[]string{`SELECT $$x$$; COPY t (c) TO PROGRAM $$id$$`}, nil},
		{"psql-command-glued", `psql -d production '--command=COPY "` + big + `" (c) TO PROGRAM id'`,
			[]string{`--command=COPY "x" (c) TO PROGRAM id`}, nil},
		{"mysql-e-load-file-before-literal", `mysql -h db -e "SELECT LOAD_FILE('/etc/shadow'); SELECT '` + big + `'"`,
			[]string{`SELECT LOAD_FILE(`}, nil},
		{"mysql-e-backslash-quote", `mysql -h db -e "SELECT 'a\\'` + big + `'; DROP DATABASE production"`,
			// The twin is single-quoted for the shell: a quote in it is '\''.
			[]string{`SELECT '\''x'\''; DROP DATABASE production`}, nil},
		{"sqlcmd-Q-bare-query", `sqlcmd -S db -Q '` + big + `'`, []string{`-Q 'x'`}, nil},
		{"psql-c-cut-after-statement", `psql -c "` + many + `COPY t (c) TO PROGRAM 'id'"`,
			[]string{`SELECT 1;`}, []string{`PROGRAM`}},
	}
	for _, r := range rows {
		split, ok := SplitOverLimitWords(r.command)
		if !ok || split.Code != 0 {
			t.Errorf("%s: split ok=%v code=%d why=%q, want a twin with the query read", r.id, ok, split.Code, split.Why)
			continue
		}
		for _, want := range r.keep {
			if !strings.Contains(split.Twin, want) {
				t.Errorf("%s: twin %q lacks %q", r.id, t20cCut(split.Twin), want)
			}
		}
		for _, unwanted := range r.drop {
			if strings.Contains(split.Twin, unwanted) {
				t.Errorf("%s: twin %q holds %q", r.id, t20cCut(split.Twin), unwanted)
			}
		}
		if len(split.Twin) > maxScalarBytes+64 {
			t.Errorf("%s: twin is %d bytes, want it within the word bound", r.id, len(split.Twin))
		}
	}
	// Plain data stays data with a stand-in: the database operand of psql,
	// an operand of a program that does not run it.
	for _, command := range []string{`psql -c 'SELECT 1' '` + big + `'`, `kubectl exec db-0 -- printf '` + big + `'`, `echo '` + big + `'`} {
		split, ok := SplitOverLimitWords(command)
		if !ok || split.Data != 1 || split.Code != 0 || strings.Contains(split.Twin, big[:100]) {
			t.Errorf("%q: split ok=%v data=%d code=%d, want one data word", t20cCut(command), ok, split.Data, split.Code)
		}
	}
}

func t20cCut(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}
