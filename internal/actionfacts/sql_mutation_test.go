// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSQLMutationFactsExactInputs(t *testing.T) {
	tests := []struct {
		name      string
		input     Input
		engine    string
		operation SQLMutationOperation
		scope     SQLMutationScope
		source    SQLMutationQuerySource
	}{
		{
			name:   "postgres unbounded delete",
			input:  Input{Tool: "shell", Command: "psql -d production -c 'DELETE FROM public.customers;'"},
			engine: "postgresql", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "mysql truncate",
			input:  Input{Tool: "shell", Command: "mysql --ssl-mode REQUIRED --execute='TRUNCATE TABLE audit_log' app"},
			engine: "mysql", operation: SQLMutationTruncate,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "sqlserver drop database",
			input:  Input{Tool: "shell", Command: `sqlcmd -S db.invalid -Q "DROP DATABASE production"`},
			engine: "sqlserver", operation: SQLMutationDropDatabase,
			scope: SQLMutationScopeDatabase, source: SQLMutationQueryArgv,
		},
		{
			name:   "committed transaction",
			input:  Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; COMMIT;'"},
			engine: "postgresql", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "unbounded delete after rolled back delete",
			input:  Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; DELETE FROM audit_log;'"},
			engine: "postgresql", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "postgres explain analyze executes unbounded delete",
			input:  Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE DELETE FROM customers;'"},
			engine: "postgresql", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "committed postgres explain analyze mutation",
			input:  Input{Tool: "shell", Command: "psql -c 'BEGIN; EXPLAIN ANALYZE DELETE FROM customers; COMMIT;'"},
			engine: "postgresql", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryArgv,
		},
		{
			name:   "literal quoted heredoc",
			input:  Input{Tool: "shell", Command: "psql -d production <<'SQL'\nTRUNCATE TABLE scratch.events;\nSQL"},
			engine: "postgresql", operation: SQLMutationTruncate,
			scope: SQLMutationScopeTable, source: SQLMutationQueryLiteralStdin,
		},
		{
			name: "structured query",
			input: Input{Tool: "sql_query", Args: mustSQLMutationArgs(t,
				"postgresql://db.invalid/production", "production", "DROP SCHEMA scratch RESTRICT")},
			engine: "postgresql", operation: SQLMutationDropSchema,
			scope: SQLMutationScopeSchema, source: SQLMutationQueryStructured,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			mutations := ExactSQLMutations(facts)
			if len(mutations) != 1 {
				t.Fatalf("mutations=%#v parse=%#v commands=%#v", mutations, facts.Parse, facts.Commands)
			}
			mutation := mutations[0]
			if !facts.EnforcementEligible() {
				t.Fatalf("exact mutation is not enforcement eligible: %#v", facts)
			}
			if mutation.Engine != test.engine || mutation.Operation != test.operation ||
				mutation.Scope != test.scope || mutation.QuerySource != test.source || !mutation.Exact {
				t.Fatalf("mutation=%#v", mutation)
			}
			for name, digest := range map[string]string{
				"connection": mutation.ConnectionIdentityDigest,
				"database":   mutation.DatabaseIdentityDigest,
				"object":     mutation.ObjectIdentityDigest,
			} {
				if !validSQLMutationDigest(digest) {
					t.Fatalf("%s digest=%q", name, digest)
				}
			}
			encoded, err := json.Marshal(mutation)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"db.invalid", "production", "customers", "scratch", "audit_log"} {
				if containsJSONText(encoded, secret) {
					t.Fatalf("SQLMutationFact JSON retained %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestSQLMutationFactsHardNegatives(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{name: "bounded delete", input: Input{Tool: "shell", Command: "psql -c 'DELETE FROM customers WHERE id = 7'"}},
		{name: "read only catalog query", input: Input{Tool: "shell", Command: "psql -d _test_db -c \"SELECT n.nspname, p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')\""}},
		{name: "multiple read only commands", input: Input{Tool: "shell", Command: "psql -d _test_db -c '\\dn' -c 'SELECT nspname FROM pg_namespace'"}},
		{name: "keyword in string", input: Input{Tool: "shell", Command: `psql -c "SELECT 'DELETE FROM customers'"`}},
		{name: "keyword in comment", input: Input{Tool: "shell", Command: "mysql -e '-- DELETE FROM customers'"}},
		{name: "comment before mutation", input: Input{Tool: "shell", Command: "psql -c '-- maintenance\nDELETE FROM customers'"}},
		{name: "explain only", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN DELETE FROM customers'"}},
		{name: "explain analyze select", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE SELECT 1'"}},
		{name: "explain analyze truncate is invalid postgres", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE TRUNCATE TABLE audit_log'"}},
		{name: "explain analyze drop is invalid postgres", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE DROP SCHEMA scratch'"}},
		{name: "explain analyze options", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN (ANALYZE, BUFFERS) DELETE FROM customers'"}},
		{name: "mysql explain analyze", input: Input{Tool: "shell", Command: "mysql -e 'EXPLAIN ANALYZE DELETE FROM customers'"}},
		{name: "rolled back explain analyze", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; EXPLAIN ANALYZE DELETE FROM customers; ROLLBACK'"}},
		{name: "explain analyze multi statement", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE DELETE FROM customers; SELECT 1'"}},
		{name: "explain analyze dynamic table", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE DELETE FROM $TABLE'"}},
		{name: "explain analyze comment", input: Input{Tool: "shell", Command: "psql -c 'EXPLAIN ANALYZE DELETE FROM customers -- execute'"}},
		{name: "rollback", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK'"}},
		{name: "open transaction", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers'"}},
		{name: "nested transaction", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; BEGIN; DELETE FROM customers; ROLLBACK; COMMIT'"}},
		{name: "open transaction after rollback", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; BEGIN; DELETE FROM audit_log'"}},
		{name: "bounded delete after rollback", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; DELETE FROM audit_log WHERE id = 7'"}},
		{name: "multiple statements after rollback", input: Input{Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; DELETE FROM audit_log; SELECT 1'"}},
		{name: "multiple statements", input: Input{Tool: "shell", Command: "psql -c 'DELETE FROM customers; SELECT 1'"}},
		{name: "dynamic table", input: Input{Tool: "shell", Command: "psql -c 'DELETE FROM $TABLE'"}},
		{name: "interpolated query", input: Input{Tool: "shell", Command: `psql -c "DELETE FROM ${TABLE}"`}},
		{name: "unquoted dynamic query", input: Input{Tool: "shell", Command: "psql -c $QUERY"}},
		{name: "dry run", input: Input{Tool: "shell", Command: "psql --dry-run -c 'DELETE FROM customers'"}},
		{name: "unknown option", input: Input{Tool: "shell", Command: "psql --file migration.sql -c 'DELETE FROM customers'"}},
		{name: "duplicate query", input: Input{Tool: "shell", Command: "psql -c 'DELETE FROM customers' -c 'TRUNCATE audit_log'"}},
		{name: "conflicting database", input: Input{Tool: "shell", Command: "psql -d one -c 'DELETE FROM customers' two"}},
		{name: "joined short option", input: Input{Tool: "shell", Command: "psql '-cDELETE FROM customers'"}},
		{name: "unquoted heredoc", input: Input{Tool: "shell", Command: "psql <<SQL\nDELETE FROM customers;\nSQL"}},
		{name: "query plus stdin", input: Input{Tool: "shell", Command: "psql -c 'DELETE FROM customers' <<'SQL'\nTRUNCATE audit_log;\nSQL"}},
		{name: "unsupported engine", input: Input{Tool: "sql_query", Args: mustSQLMutationArgs(t, "sqlite:///tmp/test.db", "", "DELETE FROM customers")}},
		{name: "structured missing host", input: Input{Tool: "sql_query", Args: mustSQLMutationArgs(t, "postgresql:///production", "production", "DELETE FROM customers")}},
		{name: "structured database mismatch", input: Input{Tool: "sql_query", Args: mustSQLMutationArgs(t, "postgresql://db.invalid/production", "staging", "DELETE FROM customers")}},
		{name: "structured unknown field", input: Input{Tool: "sql_query", Args: json.RawMessage(`{"connection":"postgresql://db.invalid/production","database":"production","query":"DELETE FROM customers","preview":true}`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if mutations := ExactSQLMutations(facts); len(mutations) != 0 {
				t.Fatalf("mutations=%#v parse=%#v commands=%#v", mutations, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestSQLMutationIdentityDigestsAreStableAndSeparated(t *testing.T) {
	first := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: "psql -d production -c 'DELETE FROM public.customers'"}))
	same := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: "psql -d production --command='DELETE FROM PUBLIC.CUSTOMERS'"}))
	otherObject := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: "psql -d production -c 'DELETE FROM public.orders'"}))
	otherDatabase := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: "psql -d staging -c 'DELETE FROM public.customers'"}))
	if len(first) != 1 || len(same) != 1 || len(otherObject) != 1 || len(otherDatabase) != 1 {
		t.Fatalf("unexpected projections: %#v %#v %#v %#v", first, same, otherObject, otherDatabase)
	}
	if first[0].ObjectIdentityDigest != same[0].ObjectIdentityDigest ||
		first[0].ObjectIdentityDigest == otherObject[0].ObjectIdentityDigest ||
		first[0].DatabaseIdentityDigest == otherDatabase[0].DatabaseIdentityDigest ||
		first[0].ConnectionIdentityDigest == first[0].ObjectIdentityDigest {
		t.Fatalf("identity separation failed: %#v %#v %#v %#v", first, same, otherObject, otherDatabase)
	}
	copyOfFirst := ExactSQLMutations(Facts{SQLMutations: append([]SQLMutationFact(nil), first...)})
	if !reflect.DeepEqual(first, copyOfFirst) {
		t.Fatalf("validated copy=%#v want %#v", copyOfFirst, first)
	}
}

func TestSQLMutationRollbackBoundaryUsesTrailingIdentity(t *testing.T) {
	sequence := ExactSQLMutations(Analyze(Input{
		Tool: "shell", Command: "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; DELETE FROM audit_log;'",
	}))
	rolledBack := ExactSQLMutations(Analyze(Input{
		Tool: "shell", Command: "psql -c 'DELETE FROM customers'",
	}))
	trailing := ExactSQLMutations(Analyze(Input{
		Tool: "shell", Command: "psql -c 'DELETE FROM audit_log'",
	}))
	if len(sequence) != 1 || len(rolledBack) != 1 || len(trailing) != 1 {
		t.Fatalf("unexpected mutation projections: sequence=%#v rolled_back=%#v trailing=%#v", sequence, rolledBack, trailing)
	}
	if sequence[0].ObjectIdentityDigest != trailing[0].ObjectIdentityDigest ||
		sequence[0].ObjectIdentityDigest == rolledBack[0].ObjectIdentityDigest {
		t.Fatalf("rollback boundary retained the wrong mutation identity: sequence=%#v rolled_back=%#v trailing=%#v", sequence, rolledBack, trailing)
	}
}

func mustSQLMutationArgs(t *testing.T, connection, database, query string) json.RawMessage {
	t.Helper()
	value := map[string]string{"connection": connection, "query": query}
	if database != "" {
		value["database"] = database
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func containsJSONText(encoded []byte, value string) bool {
	return strings.Contains(string(encoded), value)
}
