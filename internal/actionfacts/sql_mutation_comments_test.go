// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-1029: a SQL comment hid a destructive statement from the database
// destruction rules ("DELETE /* note */ FROM t", "DELETE FROM t; -- note").
// A comment is not what the statement does, so the destructive grammar reads
// the SQL with its comments removed: the comment form gives the same fact as
// the comment-free form, and a comment-free form that gives no fact still
// gives none.
func TestSQLCommentsDoNotHideDestructiveSQL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		command   string
		engine    string
		operation SQLMutationOperation
	}{
		{"block comment inside delete", "psql -c 'DELETE /* note */ FROM r25sa_records;'", "postgresql", SQLMutationDeleteUnbounded},
		{"trailing line comment", "psql -c 'DELETE FROM r25sa_records; -- note'", "postgresql", SQLMutationDeleteUnbounded},
		{"commented-out where clause", "psql -c 'DELETE FROM r25sa_records /* WHERE id=7 */;'", "postgresql", SQLMutationDeleteUnbounded},
		{"leading comment line", "psql -c '-- maintenance\nDELETE FROM customers'", "postgresql", SQLMutationDeleteUnbounded},
		{"explain analyze with comment", "psql -c 'EXPLAIN ANALYZE DELETE FROM customers -- execute'", "postgresql", SQLMutationDeleteUnbounded},
		{"mysql truncate with comment", "mysql -e 'TRUNCATE TABLE r25sa_records; -- note'", "mysql", SQLMutationTruncate},
		{"mysql comment between keywords", "mysql -e 'DELETE/**/FROM audit_log' app", "mysql", SQLMutationDeleteUnbounded},
		{"sql server drop database with comment", `sqlcmd -Q "DROP DATABASE production -- note"`, "sqlserver", SQLMutationDropDatabase},
		{"literal stdin with comments", "psql -d production <<'SQL'\n-- cleanup\nTRUNCATE TABLE scratch.events; /* done */\nSQL", "postgresql", SQLMutationTruncate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command})
			mutations := ExactSQLMutations(facts)
			if len(mutations) != 1 || mutations[0].Engine != tc.engine || mutations[0].Operation != tc.operation {
				t.Fatalf("mutations=%#v parse=%#v, want one %s %s", mutations, facts.Parse, tc.engine, tc.operation)
			}
		})
	}
	for _, tc := range []struct{ name, command string }{
		{"bounded delete with comment", "psql -c 'DELETE FROM customers /* nightly */ WHERE id = 7'"},
		{"delete only in a comment", "psql -c 'SELECT 1 /* DELETE FROM customers */'"},
		{"commented-out statement", "psql -c '/* DELETE FROM customers; */ SELECT 1'"},
		{"line comment only", "mysql -e '-- DELETE FROM customers'"},
		{"mysql executable comment", "mysql -e 'DELETE FROM customers /*! WHERE id = 7 */'"},
		{"mariadb executable comment", "mariadb -e 'DELETE FROM customers /*M! WHERE id = 7 */'"},
		{"mysql double dash without space", "mysql -e 'DELETE FROM customers --x'"},
		{"nested block comment", "psql -c 'DELETE FROM customers /* a /* b */ c */'"},
		{"unterminated block comment", "psql -c 'DELETE FROM customers /* open'"},
		{"stray comment close", "psql -c 'DELETE FROM customers */'"},
		{"rolled back with comment", "psql -c 'BEGIN; DELETE FROM customers; /* undo */ ROLLBACK;'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command})
			if mutations := ExactSQLMutations(facts); len(mutations) != 0 {
				t.Fatalf("mutations=%#v, want none", mutations)
			}
		})
	}
}
