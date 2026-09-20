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
		{
			name: "authenticated MCP SQLite unbounded delete",
			input: Input{
				Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials;"}`),
				ToolResourceIdentity: "mcp://sqlite/synthetic-database",
			},
			engine: "sqlite", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryStructured,
		},
		{
			name: "authenticated db execute truncate database key",
			input: Input{
				Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"TRUNCATE TABLE audit_log;"}`),
				ToolResourceIdentity: "mcp://database/synthetic-production",
			},
			engine: "generic", operation: SQLMutationTruncate,
			scope: SQLMutationScopeTable, source: SQLMutationQueryStructured,
		},
		{
			name: "authenticated db execute unbounded delete db key",
			input: Input{
				Tool: "db.execute", Args: json.RawMessage(`{"db":"app","sql":"DELETE FROM sessions"}`),
				ToolResourceIdentity: "mcp://database/synthetic-app",
			},
			engine: "generic", operation: SQLMutationDeleteUnbounded,
			scope: SQLMutationScopeTable, source: SQLMutationQueryStructured,
		},
		{
			name: "authenticated db execute drop table",
			input: Input{
				Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"DROP TABLE IF EXISTS customers CASCADE"}`),
				ToolResourceIdentity: "mcp://database/synthetic-production",
			},
			engine: "generic", operation: SQLMutationDropTable,
			scope: SQLMutationScopeTable, source: SQLMutationQueryStructured,
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
			for _, secret := range []string{
				"db.invalid", "production", "customers", "scratch", "audit_log",
				"credentials", "mcp://sqlite/synthetic-database",
			} {
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
		{name: "MCPHunt scoped delete by identity", input: sqliteWriteQueryInput(`DELETE FROM users WHERE id = 3`)},
		{name: "MCPHunt scoped delete by name", input: sqliteWriteQueryInput(`DELETE FROM users WHERE name = 'charlie'`)},
		{name: "MCPHunt scoped delete by subquery", input: sqliteWriteQueryInput(`DELETE FROM api_keys WHERE user_id NOT IN (SELECT id FROM users)`)},
		{name: "MCPHunt scoped delete by workspace", input: sqliteWriteQueryInput(`DELETE FROM project_file_stats WHERE scope = 'workspace_excluding_git'`)},
		{name: "MCPHunt scoped sensitive delete", input: sqliteWriteQueryInput(`DELETE FROM employees WHERE id=2;`)},
		{name: "sqlite transaction", input: sqliteWriteQueryInput(`BEGIN; DELETE FROM credentials; COMMIT;`)},
		{name: "sqlite rollback", input: sqliteWriteQueryInput(`BEGIN; DELETE FROM credentials; ROLLBACK;`)},
		{name: "sqlite trailing statement", input: sqliteWriteQueryInput(`DELETE FROM credentials; SELECT 1;`)},
		{name: "sqlite preceding statement", input: sqliteWriteQueryInput(`PRAGMA foreign_keys=OFF; DELETE FROM credentials;`)},
		{name: "sqlite dynamic table", input: sqliteWriteQueryInput(`DELETE FROM ${TABLE}`)},
		{name: "db execute missing resource identity", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"TRUNCATE TABLE audit_log"}`)}},
		{name: "db execute bounded delete", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"DELETE FROM customers WHERE id = 7"}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "db execute unknown field", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"DROP TABLE customers","confirm":true}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "db execute ambiguous database keys", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","db":"production","sql":"DROP TABLE customers"}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "db execute dynamic database", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"${DATABASE}","sql":"DROP TABLE customers"}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "db execute dynamic SQL", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"DROP TABLE ${TABLE}"}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "db execute duplicate key", input: Input{Tool: "db.execute", Args: json.RawMessage(`{"database":"production","sql":"DROP TABLE customers","sql":"TRUNCATE TABLE customers"}`), ToolResourceIdentity: "mcp://database/synthetic-production"}},
		{name: "sqlite templated table", input: sqliteWriteQueryInput(`DELETE FROM {{ table }}`)},
		{name: "sqlite quoted table", input: sqliteWriteQueryInput(`DELETE FROM "credentials"`)},
		{name: "sqlite qualified table", input: sqliteWriteQueryInput(`DELETE FROM main.credentials`)},
		{name: "sqlite comment", input: sqliteWriteQueryInput("DELETE FROM credentials -- all rows")},
		{name: "sqlite block comment", input: sqliteWriteQueryInput(`DELETE FROM /* selected */ credentials`)},
		{name: "sqlite returning clause", input: sqliteWriteQueryInput(`DELETE FROM credentials RETURNING id`)},
		{name: "sqlite common table expression", input: sqliteWriteQueryInput(`WITH selected AS (SELECT id FROM credentials) DELETE FROM credentials`)},
		{name: "sqlite truncate is outside schema", input: sqliteWriteQueryInput(`TRUNCATE TABLE credentials`)},
		{name: "sqlite drop is outside schema", input: sqliteWriteQueryInput(`DROP TABLE credentials`)},
		{name: "sqlite leading whitespace", input: sqliteWriteQueryInput(` DELETE FROM credentials`)},
		{name: "sqlite newline", input: sqliteWriteQueryInput("DELETE FROM\ncredentials")},
		{name: "sqlite missing trusted identity", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials"}`)}},
		{name: "sqlite dynamic trusted identity", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials"}`), ToolResourceIdentity: "mcp://sqlite/${DATABASE}"}},
		{name: "sqlite unknown argument", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials","database":"synthetic"}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite duplicate argument", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials","query":"DELETE FROM file_stats"}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite nested argument", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":{"text":"DELETE FROM credentials"}}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite missing query", input: Input{Tool: "write_query", Args: json.RawMessage(`{}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite null query", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":null}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite conflicting command", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials"}`), Command: "echo inert", ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "sqlite conflicting argv", input: Input{Tool: "write_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials"}`), Argv: []string{"echo", "inert"}, ToolResourceIdentity: "mcp://sqlite/synthetic"}},
		{name: "read query is not a mutation sink", input: Input{Tool: "read_query", Args: json.RawMessage(`{"query":"DELETE FROM credentials"}`), ToolResourceIdentity: "mcp://sqlite/synthetic"}},
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

func TestSQLiteWriteQueryMutationIdentityIsStableJoinedAndPrivate(t *testing.T) {
	t.Parallel()
	resourceIdentity := "mcp://sqlite/synthetic-database"
	first := ExactSQLMutations(Analyze(sqliteWriteQueryInputWithIdentity(
		`DELETE FROM credentials`, resourceIdentity,
	)))
	same := ExactSQLMutations(Analyze(sqliteWriteQueryInputWithIdentity(
		`delete from CREDENTIALS;`, resourceIdentity,
	)))
	otherTable := ExactSQLMutations(Analyze(sqliteWriteQueryInputWithIdentity(
		`DELETE FROM file_stats`, resourceIdentity,
	)))
	otherDatabase := ExactSQLMutations(Analyze(sqliteWriteQueryInputWithIdentity(
		`DELETE FROM credentials`, "mcp://sqlite/other-synthetic-database",
	)))
	read := ExactSensitiveSQLRowsetReads(Analyze(Input{
		Tool: "read_query", Args: json.RawMessage(`{"query":"SELECT password FROM credentials"}`),
		ToolResourceIdentity: resourceIdentity,
	}))
	if len(first) != 1 || len(same) != 1 || len(otherTable) != 1 ||
		len(otherDatabase) != 1 || len(read) != 1 {
		t.Fatalf("unexpected facts: first=%#v same=%#v table=%#v database=%#v read=%#v",
			first, same, otherTable, otherDatabase, read)
	}
	if first[0].DatabaseIdentityDigest != read[0].DatabaseIdentityDigest {
		t.Fatal("read_query and write_query did not retain the same authenticated database identity")
	}
	if first[0].ObjectIdentityDigest != read[0].TableIdentityDigest {
		t.Fatal("read_query and write_query did not retain the same normalized table identity")
	}
	if first[0].DatabaseIdentityDigest != same[0].DatabaseIdentityDigest ||
		first[0].ObjectIdentityDigest != same[0].ObjectIdentityDigest {
		t.Fatal("equivalent database/table identities produced different digests")
	}
	if first[0].ObjectIdentityDigest == otherTable[0].ObjectIdentityDigest {
		t.Fatal("different normalized tables produced the same digest")
	}
	if first[0].DatabaseIdentityDigest == otherDatabase[0].DatabaseIdentityDigest ||
		first[0].ConnectionIdentityDigest == otherDatabase[0].ConnectionIdentityDigest {
		t.Fatal("different authenticated databases produced the same resource digest")
	}

	encodedFact, err := json.Marshal(first[0])
	if err != nil {
		t.Fatal(err)
	}
	encodedFacts, err := json.Marshal(Analyze(sqliteWriteQueryInputWithIdentity(
		`DELETE FROM credentials`, resourceIdentity,
	)))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"DELETE FROM credentials", "credentials", resourceIdentity,
	} {
		if strings.Contains(string(encodedFact), forbidden) ||
			strings.Contains(string(encodedFacts), forbidden) {
			t.Fatalf("private SQLite mutation material %q serialized", forbidden)
		}
	}
}

func FuzzSQLiteWriteQueryMutation(f *testing.F) {
	for _, seed := range []string{
		"DELETE FROM credentials",
		"delete from CREDENTIALS;",
		"DELETE FROM users WHERE id = 3",
		"BEGIN; DELETE FROM credentials; COMMIT;",
		"DELETE FROM ${TABLE}",
		"DELETE FROM credentials; SELECT 1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, query string) {
		input := sqliteWriteQueryInput(query)
		facts := Analyze(input)
		mutations := ExactSQLMutations(facts)
		if len(mutations) > 1 {
			t.Fatalf("mutations=%#v", mutations)
		}
		for _, mutation := range mutations {
			if !validSQLMutationFact(mutation) || mutation.Engine != "sqlite" ||
				mutation.Operation != SQLMutationDeleteUnbounded ||
				mutation.Scope != SQLMutationScopeTable ||
				mutation.QuerySource != SQLMutationQueryStructured {
				t.Fatalf("invalid mutation=%#v", mutation)
			}
			encoded, err := json.Marshal(mutation)
			if err != nil {
				t.Fatal(err)
			}
			if query != "" && strings.Contains(string(encoded), query) {
				t.Fatalf("raw query serialized: %s", encoded)
			}
		}
	})
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

func sqliteWriteQueryInput(query string) Input {
	return sqliteWriteQueryInputWithIdentity(query, "mcp://sqlite/synthetic-database")
}

func sqliteWriteQueryInputWithIdentity(query, identity string) Input {
	args, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		panic(err)
	}
	return Input{
		Tool: "write_query", Args: args, ToolResourceIdentity: identity,
	}
}

func containsJSONText(encoded []byte, value string) bool {
	return strings.Contains(string(encoded), value)
}
