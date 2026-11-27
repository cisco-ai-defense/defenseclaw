// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestT20BSQLASTCapHitsAreRecorded (DET111 T20 review P3-1, ruled): a cap
// of the SQL facts reader (bytes, statements, tokens, depth) set the text
// unknown and dropped its SQLFact with no record. The hit is now in the
// call's private record (SQLASTCaps); a text within the caps records none.
func TestT20BSQLASTCapHitsAreRecorded(t *testing.T) {
	sqlQuery := func(query string) Input {
		args, _ := json.Marshal(map[string]string{
			"connection": "postgresql://db.invalid:5432/production", "database": "production", "query": query,
		})
		return Input{Tool: "sql_query", Args: args}
	}
	rows := []struct {
		id    string
		input Input
		cap   bounded.Cap
	}{
		{"statements", sqlQuery(strings.Repeat("SELECT 1;", maxSQLASTStatements+1)), bounded.Items},
		{"psql-statements", Input{Tool: "shell", Command: `psql -d production -c "` + strings.Repeat("SELECT 1;", maxSQLASTStatements+1) + `"`}, bounded.Items},
	}
	for _, r := range rows {
		facts := Analyze(r.input)
		if caps := facts.SQLASTCaps(); !caps.Has(r.cap) || len(facts.SQLFacts) != 0 {
			t.Errorf("%s: caps=%q sql_facts=%d, want %v recorded and no SQL fact", r.id, caps.Reason(), len(facts.SQLFacts), r.cap)
		}
	}
	if facts := Analyze(sqlQuery("SELECT 1; SELECT 2;")); facts.SQLASTCaps().Any() || len(facts.SQLFacts) != 1 {
		t.Errorf("small query: caps=%q sql_facts=%d, want none and one fact", facts.SQLASTCaps().Reason(), len(facts.SQLFacts))
	}
	deep := "SELECT 1"
	for range maxSQLASTDepth + 1 {
		deep = "DO '" + strings.ReplaceAll(deep, "'", "''") + "'"
	}
	if got := parseSQLAST(deep); !got.unknown || !got.caps.Has(bounded.Depth) {
		t.Errorf("deep DO nesting: unknown=%v caps=%q, want depth recorded", got.unknown, got.caps.Reason())
	}
}
