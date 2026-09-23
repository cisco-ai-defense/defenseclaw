// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPostgreSQLCopyProgramExactGrammarIsValueFree(t *testing.T) {
	const connection = "postgresql://fixture-user:fixture-password@db.invalid:5432/production"
	queries := []string{
		"COPY (SELECT '') TO PROGRAM 'id';",
		"copy (select -1) to program 'printf ''ok''';",
		"COPY audit.events TO PROGRAM 'wc -l'",
		"COPY ONLY audit.events (id, \"Event Value\") FROM PROGRAM 'printf data';",
		"COPY \"Tenant\".\"Audit Events\" TO PROGRAM 'true';",
	}
	var firstDigest string
	for _, query := range queries {
		facts := Analyze(Input{
			Tool: "sql_query",
			Args: mustSQLQueryArgs(t, connection, "production", query),
		})
		digest, ok := ExactPostgreSQLCopyProgram(facts)
		if !ok || digest == "" || facts.Parse.Status != StatusComplete ||
			len(facts.Commands) != 0 {
			t.Fatalf("query=%q digest=%q ok=%t facts=%+v", query, digest, ok, facts)
		}
		if firstDigest == "" {
			firstDigest = digest
		} else if digest != firstDigest {
			t.Fatalf("same identity produced different digests")
		}
		encoded, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"fixture-password", "printf", "audit.events"} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatalf("private SQL or connection material survived projection: %s", encoded)
			}
		}
	}
}

func TestPostgreSQLCopyProgramAcceptsClosedLibPQKeywordConnections(t *testing.T) {
	tests := []struct {
		connection string
		database   string
	}{
		{"host=10.10.13.200 port=5432 dbname=postgres user=admin password=admin123", ""},
		{"host=10.2.10.100 port=5432 user=postgres password=password123", "postgres"},
		{"host=localhost port=5432 user=postgres dbname=app_db", "app_db"},
	}
	for _, test := range tests {
		facts := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(
			t, test.connection, test.database, "COPY (SELECT 1) TO PROGRAM 'id';",
		)})
		if _, ok := ExactPostgreSQLCopyProgram(facts); !ok || facts.Parse.Status != StatusComplete {
			t.Fatalf("connection=%q database=%q facts=%+v", test.connection, test.database, facts)
		}
	}
}

func TestPostgreSQLCopyProgramRejectsAmbiguousLibPQKeywordConnections(t *testing.T) {
	tests := []struct {
		connection string
		database   string
	}{
		{"host=10.0.0.1 port=5432 user=postgres", ""},
		{"host=10.0.0.1 port=5432 dbname=one user=postgres", "two"},
		{"host=10.0.0.1 port=05432 dbname=one user=postgres", "one"},
		{"host=10.0.0.1 port=70000 dbname=one user=postgres", "one"},
		{"host=${DB_HOST} port=5432 dbname=one user=postgres", "one"},
		{"host=10.0.0.1 port=5432 dbname=one user=postgres sslmode=require", "one"},
		{"host=10.0.0.1 host=10.0.0.2 port=5432 dbname=one user=postgres", "one"},
		{"host='10.0.0.1' port=5432 dbname=one user=postgres", "one"},
	}
	for _, test := range tests {
		facts := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(
			t, test.connection, test.database, "COPY (SELECT 1) TO PROGRAM 'id';",
		)})
		if _, ok := ExactPostgreSQLCopyProgram(facts); ok {
			t.Fatalf("ambiguous connection accepted: %q", test.connection)
		}
	}
}

func TestPostgreSQLCopyProgramHardNegatives(t *testing.T) {
	const connection = "postgresql://fixture@db.invalid:5432/production"
	tests := []struct {
		name       string
		tool       string
		connection string
		database   string
		query      string
		extra      bool
		command    string
		argv       []string
	}{
		{name: "wrong tool", tool: "database_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "raw command source", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'", command: "COPY t TO PROGRAM 'id'"},
		{name: "argv source", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'", argv: []string{"COPY", "t"}},
		{name: "unknown field", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'", extra: true},
		{name: "bare connection", tool: "sql_query", connection: "production", database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "mysql connection", tool: "sql_query", connection: "mysql://db.invalid/production", database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "https connection", tool: "sql_query", connection: "https://db.invalid/production", database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "missing database path", tool: "sql_query", connection: "postgresql://db.invalid", query: "COPY t TO PROGRAM 'id'"},
		{name: "database mismatch", tool: "sql_query", connection: connection, database: "staging", query: "COPY t TO PROGRAM 'id'"},
		{name: "database query identity", tool: "sql_query", connection: connection + "?dbname=production", database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "dynamic connection", tool: "sql_query", connection: "postgresql://${DB_HOST}/production", database: "production", query: "COPY t TO PROGRAM 'id'"},
		{name: "copy file to", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO '/tmp/out'"},
		{name: "copy file from", tool: "sql_query", connection: connection, database: "production", query: "COPY t FROM '/tmp/in'"},
		{name: "copy stdout", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO STDOUT"},
		{name: "copy stdin", tool: "sql_query", connection: connection, database: "production", query: "COPY t FROM STDIN"},
		{name: "psql copy", tool: "sql_query", connection: connection, database: "production", query: "\\copy t FROM PROGRAM 'id'"},
		{name: "psql shell", tool: "sql_query", connection: connection, database: "production", query: "\\! id"},
		{name: "dynamic program", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM command_text"},
		{name: "concatenated program", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id' || suffix"},
		{name: "dynamic select", tool: "sql_query", connection: connection, database: "production", query: "COPY (SELECT current_user) TO PROGRAM 'id'"},
		{name: "query from program", tool: "sql_query", connection: connection, database: "production", query: "COPY (SELECT 1) FROM PROGRAM 'id'"},
		{name: "escape string", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM E'id'"},
		{name: "dollar string", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM $$id$$"},
		{name: "empty program", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM ''"},
		{name: "program whitespace", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM ' id '"},
		{name: "with options", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id' WITH (FORMAT csv)"},
		{name: "leading comment", tool: "sql_query", connection: connection, database: "production", query: "-- test\nCOPY t TO PROGRAM 'id'"},
		{name: "trailing comment", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'; -- test"},
		{name: "block comment", tool: "sql_query", connection: connection, database: "production", query: "COPY /* test */ t TO PROGRAM 'id'"},
		{name: "unrelated prefix", tool: "sql_query", connection: connection, database: "production", query: "SELECT 1; COPY t TO PROGRAM 'id'"},
		{name: "unrelated suffix", tool: "sql_query", connection: connection, database: "production", query: "COPY t TO PROGRAM 'id'; SELECT 1"},
		{name: "create function wrapper", tool: "sql_query", connection: connection, database: "production", query: "CREATE FUNCTION f() RETURNS void AS $$ BEGIN EXECUTE 'COPY t TO PROGRAM ''id'''; END $$ LANGUAGE plpgsql"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := map[string]any{
				"connection": test.connection,
				"query":      test.query,
			}
			if test.database != "" {
				object["database"] = test.database
			}
			if test.extra {
				object["timeout"] = 30
			}
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{
				Tool: test.tool, Args: raw, Command: test.command, Argv: test.argv,
			})
			if digest, ok := ExactPostgreSQLCopyProgram(facts); ok || digest != "" ||
				len(facts.PostgreSQLCopyPrograms) != 0 {
				t.Fatalf("hard negative projected PostgreSQL operation: %+v", facts)
			}
		})
	}
}

func TestPostgreSQLCopyProgramRejectsMalformedStructuredSchemas(t *testing.T) {
	queries := []json.RawMessage{
		json.RawMessage(`"COPY t TO PROGRAM 'id'"`),
		json.RawMessage(`{"connection":"postgresql://db.invalid/production","query":"COPY t TO PROGRAM 'id'","query":"COPY t TO PROGRAM 'id'"}`),
		json.RawMessage(`{"connection":"postgresql://db.invalid/production","query":7}`),
		json.RawMessage(`{"connection":"postgresql://db.invalid/production","query":"COPY t TO PROGRAM 'id'","database":7}`),
		json.RawMessage(`{"connection":"postgresql://db.invalid/production","query":"COPY t TO PROGRAM 'id'","unknown":true}`),
	}
	for _, raw := range queries {
		facts := Analyze(Input{Tool: "sql_query", Args: raw})
		if _, ok := ExactPostgreSQLCopyProgram(facts); ok {
			t.Fatalf("malformed schema projected PostgreSQL operation: %s", raw)
		}
	}
}

func TestPostgreSQLCopyProgramIdentityDigestIsExact(t *testing.T) {
	const query = "COPY t TO PROGRAM 'id'"
	project := func(connection, database string) string {
		t.Helper()
		facts := Analyze(Input{
			Tool: "sql_query", Args: mustSQLQueryArgs(t, connection, database, query),
		})
		digest, _ := ExactPostgreSQLCopyProgram(facts)
		return digest
	}
	first := project("postgresql://db.invalid/one", "one")
	same := project("postgresql://db.invalid/one", "one")
	different := project("postgresql://db.invalid/two", "two")
	if first == "" || first != same || first == different {
		t.Fatalf("digest exactness equality=%t mismatch=%t", first == same, first != different)
	}
}
