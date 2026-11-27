// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestT20DPostgreSQLStringConstantForms (GAP-1950): the server reads a
// dollar-quoted string and an escape string as the same text as a quoted
// string, so the COPY ... PROGRAM reader takes each form. Red at a64bfdb931
// and 279da61428 (only '...' was read).
func TestT20DPostgreSQLStringConstantForms(t *testing.T) {
	for _, query := range []string{
		`COPY t (c) TO PROGRAM 'id'`,
		`COPY t (c) TO PROGRAM $$id$$`,
		`COPY t (c) TO PROGRAM $run$id$run$;`,
		`COPY t (c) TO PROGRAM E'id'`,
		`copy t to program e'i\'d'`,
	} {
		if !exactPostgreSQLCopyProgramQuery(query) {
			t.Errorf("%q: not read as COPY ... PROGRAM", query)
		}
	}
	for _, query := range []string{
		`COPY t (c) TO PROGRAM $$id`,
		`COPY t (c) TO PROGRAM $1`,
		`COPY t (c) TO PROGRAM $$$$`,
		`COPY t (c) TO PROGRAM xE'id'`,
	} {
		if exactPostgreSQLCopyProgramQuery(query) {
			t.Errorf("%q: read as COPY ... PROGRAM, want no exact program", query)
		}
	}
	// The psql query admits the tags of a complete dollar quote only.
	for value, unresolved := range map[string]bool{
		`COPY t (c) TO PROGRAM $$id$$`:        false,
		`COPY t (c) TO PROGRAM $run$id$run$`:  false,
		`COPY t (c) TO PROGRAM $$id`:          true,
		`DELETE FROM t WHERE id = $1`:         true,
		`COPY t (c) TO PROGRAM $$$TABLE$$`:    true,
		`COPY t (c) TO PROGRAM $$ {{cmd}} $$`: true,
	} {
		if got := unresolvedSQLCLIValue("postgresql", "query", value); got != unresolved {
			t.Errorf("%q: unresolved=%v, want %v", value, got, unresolved)
		}
	}
	if !unresolvedSQLCLIValue("mysql", "query", `SELECT $$id$$`) {
		t.Errorf("a mysql query with $ must stay unresolved")
	}
}
