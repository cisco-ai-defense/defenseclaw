// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-1030: the database destruction pack lists snowsql, but its inline query
// gave no SQL mutation fact, so snowsql -q 'DROP SCHEMA s' was allowed where
// psql -c 'DROP SCHEMA s' blocks. snowsql -q/--query is now read by the same
// grammar; a query file and dynamic or unknown forms still give no fact.
func TestSnowSQLInlineQueryIsASQLClient(t *testing.T) {
	for _, tc := range []struct {
		name      string
		command   string
		operation SQLMutationOperation
	}{
		{"drop schema", "snowsql -q 'DROP SCHEMA r25sa_fixture;'", SQLMutationDropSchema},
		{"unbounded delete", "snowsql -q 'DELETE FROM r25sa_records;'", SQLMutationDeleteUnbounded},
		{"truncate", "snowsql -q 'TRUNCATE TABLE r25sa_records;'", SQLMutationTruncate},
		{"long options", "snowsql --connection prod --dbname analytics --query='DROP DATABASE analytics'", SQLMutationDropDatabase},
		{"account and warehouse", "snowsql -a acme -u dev -w wh -r analyst -d analytics -s public -q 'DELETE FROM events'", SQLMutationDeleteUnbounded},
		{"with comment", "snowsql -q 'DROP SCHEMA s; // done'", SQLMutationDropSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: tc.command})
			mutations := ExactSQLMutations(facts)
			if len(mutations) != 1 || mutations[0].Engine != "snowflake" || mutations[0].Operation != tc.operation {
				t.Fatalf("mutations=%#v parse=%#v, want one snowflake %s", mutations, facts.Parse, tc.operation)
			}
		})
	}
	for _, tc := range []struct{ name, command string }{
		{"bounded delete", "snowsql -q 'DELETE FROM events WHERE id = 7'"},
		{"select", "snowsql -q 'SELECT COUNT(1) FROM events'"},
		{"query file", "snowsql -f cleanup.sql"},
		{"query file and query", "snowsql -f cleanup.sql -q 'DROP SCHEMA s'"},
		{"positional argument", "snowsql analytics -q 'DROP SCHEMA s'"},
		{"dynamic query", "snowsql -q \"$QUERY\""},
		{"unknown option", "snowsql -o friendly=false -q 'DROP SCHEMA s'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if mutations := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: tc.command})); len(mutations) != 0 {
				t.Fatalf("mutations=%#v, want none", mutations)
			}
		})
	}
}
