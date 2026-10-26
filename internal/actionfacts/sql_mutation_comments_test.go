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
		{"explain analyze with comment", "psql -c 'EXPLAIN ANALYZE DELETE FROM customers -- execute'", "postgresql", SQLMutationDeleteUnbounded},
		{"mysql truncate with comment", "mysql -e 'TRUNCATE TABLE r25sa_records; -- note'", "mysql", SQLMutationTruncate},
		{"mysql comment between keywords", "mysql -e 'DELETE/**/FROM audit_log' app", "mysql", SQLMutationDeleteUnbounded},
		{"sql server drop database with comment", `sqlcmd -Q "DROP DATABASE production -- note"`, "sqlserver", SQLMutationDropDatabase},
		{"literal stdin with comments", "psql -d production <<'SQL'\n-- cleanup\nTRUNCATE TABLE scratch.events; -- done\nSQL", "postgresql", SQLMutationTruncate},
		// GAP-1769: PostgreSQL ends a -- comment at a bare carriage return.
		{"bare CR ends a postgres line comment", "psql -d production <<'SQL'\n-- cleanup\rTRUNCATE TABLE scratch.events;\nSQL", "postgresql", SQLMutationTruncate},
		{"bare CR ends a sql server line comment", "sqlcmd -d production <<'SQL'\n-- cleanup\rDROP DATABASE production\nSQL", "sqlserver", SQLMutationDropDatabase},
		// GAP-1936: a MySQL "#" comment and a balanced nested block comment
		// (PostgreSQL, SQL Server) do not hide the statement.
		{"mysql hash comment", "mysql -e 'DELETE FROM audit_log # cleanup'", "mysql", SQLMutationDeleteUnbounded},
		{"mysql hash comment after the statement", "mysql -e 'TRUNCATE TABLE events; # note'", "mysql", SQLMutationTruncate},
		{"postgres nested block comment", "psql -c 'DELETE /* a /* b */ c */ FROM t'", "postgresql", SQLMutationDeleteUnbounded},
		{"postgres trailing nested block comment", "psql -c 'DELETE FROM customers /* a /* b */ c */'", "postgresql", SQLMutationDeleteUnbounded},
		{"sql server nested block comment", `sqlcmd -Q "DROP DATABASE production /* a /* b */ */"`, "sqlserver", SQLMutationDropDatabase},
		{"mysql hash comment in stdin", "mysql app <<'SQL'\n# cleanup\nDELETE FROM audit_log;\nSQL", "mysql", SQLMutationDeleteUnbounded},
		// GAP-2010: MySQL does not nest block comments (the comment ends at
		// the first "*/") and runs the body of an executable comment.
		{"mysql comment holding an opener before the end", "mysql -e 'DELETE FROM customers /* a /* b */'", "mysql", SQLMutationDeleteUnbounded},
		{"mysql drop database after a comment holding an opener", "mysql -e 'DROP DATABASE production /* x /* y */'", "mysql", SQLMutationDropDatabase},
		{"mysql executable comment body", "mysql -e '/*! DROP DATABASE production */'", "mysql", SQLMutationDropDatabase},
		{"mysql versioned executable comment body", "mysql -e '/*!50000 DROP DATABASE production */'", "mysql", SQLMutationDropDatabase},
		{"mariadb executable comment body", "mariadb -e '/*M! TRUNCATE TABLE events */'", "mysql", SQLMutationTruncate},
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
		{"unbalanced nested block comment", "psql -c 'DELETE FROM customers /* a /* b */'"},
		{"mysql does not nest block comments", "mysql -e 'DELETE FROM customers /* a /* b */ c */'"},
		{"hash is not a postgres comment", "psql -c 'DELETE FROM customers # x'"},
		{"delete only in a mysql hash comment", "mysql -e 'SELECT 1 # DELETE FROM customers'"},
		{"mysql bounded delete with hash comment", "mysql -e 'DELETE FROM customers WHERE id = 7 # nightly'"},
		{"unterminated block comment", "psql -c 'DELETE FROM customers /* open'"},
		{"stray comment close", "psql -c 'DELETE FROM customers */'"},
		{"empty mysql executable comment", "mysql -e 'SELECT 1 /*! */'"},
		{"unterminated mysql executable comment", "mysql -e '/*! DROP DATABASE production'"},
		{"mysql executable comment in an executable comment", "mysql -e '/*! DROP DATABASE /*! x */ production */'"},
		{"executable comment is not a postgres form", "psql -c '/*! DROP DATABASE production */'"},
		// A multi-line -c value is not an exact argv scalar, with or without a
		// comment ("psql -c 'DELETE\nFROM customers'" gives no fact either).
		{"leading comment line in a multi-line argument", "psql -c '-- maintenance\nDELETE FROM customers'"},
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
