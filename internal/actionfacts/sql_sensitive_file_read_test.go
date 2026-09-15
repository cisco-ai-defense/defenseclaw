// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSQLSensitiveServerFileReadExactStructuredQueries(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		database   string
		query      string
		engine     string
		pathClass  string
	}{
		{
			name:       "mysql uri account database",
			connection: "mysql://analyst:placeholder@db.invalid:3306/app",
			database:   "app",
			query:      "SELECT LOAD_FILE('/etc/passwd');",
			engine:     "mysql",
			pathClass:  SQLSensitiveServerFileAccountDatabase,
		},
		{
			name:       "mysql closed key value credential",
			connection: "user=analyst,password=,host=db.invalid,port=3306",
			query:      "select load_file ( '/etc/shadow' )",
			engine:     "mysql",
			pathClass:  SQLSensitiveServerFileCredential,
		},
		{
			name:       "mysql bare dsn with static alias",
			connection: "analyst:provided-by-secret-store@db.invalid:3306",
			query:      "SELECT LOAD_FILE('/etc/passwd') AS file_contents;",
			engine:     "mysql",
			pathClass:  SQLSensitiveServerFileAccountDatabase,
		},
		{
			name:       "mysql bare dsn direct read",
			connection: "analyst:@db.invalid:3306",
			query:      "SELECT LOAD_FILE('/home/agent/.aws/credentials');",
			engine:     "mysql",
			pathClass:  SQLSensitiveServerFileCredential,
		},
		{
			name:       "postgres uri credential",
			connection: "postgresql://analyst:placeholder@db.invalid:5432/app",
			database:   "app",
			query:      "SELECT pg_read_file('/var/run/secrets/kubernetes.io/serviceaccount/token');",
			engine:     "postgresql",
			pathClass:  SQLSensitiveServerFileCredential,
		},
		{
			name:       "postgres keyword binary read",
			connection: "host=db.invalid port=5432 dbname=app user=analyst",
			database:   "app",
			query:      "SELECT pg_read_binary_file('/home/agent/.ssh/id_ed25519')",
			engine:     "postgresql",
			pathClass:  SQLSensitiveServerFileCredential,
		},
		{
			name:       "postgres copy select sensitive read",
			connection: "host=db.invalid port=5432 dbname=app user=analyst",
			database:   "app",
			query:      "COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/server-copy';",
			engine:     "postgresql",
			pathClass:  SQLSensitiveServerFileCredential,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connectionRecognized := exactPostgreSQLConnection(test.connection, test.database)
			if test.engine == "mysql" {
				connectionRecognized = exactMySQLConnection(test.connection, test.database)
			}
			if !connectionRecognized {
				t.Fatal("expected closed connection form to be recognized")
			}
			functions := []string{"pg_read_file", "pg_read_binary_file"}
			if test.engine == "mysql" {
				functions = []string{"load_file"}
			}
			if _, ok := exactSQLSensitiveFileReadQuery(test.query, functions); !ok {
				t.Fatal("expected closed literal query to be recognized")
			}
			facts := Analyze(sqlSensitiveServerFileReadInput(
				t, test.connection, test.database, test.query,
			))
			fact, ok := ExactSQLSensitiveServerFileRead(facts)
			if !ok || fact.DatabaseEngine != test.engine ||
				fact.PathClass != test.pathClass {
				t.Fatalf("fact=%+v ok=%v", fact, ok)
			}
			encoded, err := json.Marshal(facts)
			if err != nil {
				t.Fatal(err)
			}
			for _, privateValue := range []string{
				test.query, test.connection, "/etc/", "/var/run/", "/.ssh/",
			} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("serialized facts contain private SQL input %q", privateValue)
				}
			}
		})
	}
}

func TestSQLSensitiveServerFileReadRejectsAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		connection string
		database   string
		query      string
	}{
		{
			name: "source text mention", tool: "shell",
			query: "printf %s SELECT LOAD_FILE('/etc/passwd')",
		},
		{
			name: "unrecognized connection", connection: "analyst@db.invalid:3306",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "redacted uri is normalizer only", connection: "mysql://<redacted>@db.invalid:3306/app",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "bare dsn missing separator", connection: "analyst@db.invalid:3306",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "bare dsn missing user", connection: ":provided-by-secret-store@db.invalid:3306",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "bare dsn database path", connection: "analyst:provided-by-secret-store@db.invalid:3306/app",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "mysql postgres function", connection: "mysql://db.invalid/app",
			query: "SELECT pg_read_file('/etc/passwd');",
		},
		{
			name: "postgres mysql function", connection: "postgresql://db.invalid/app",
			query: "SELECT LOAD_FILE('/etc/passwd');",
		},
		{
			name: "temporary test file is not sensitive", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/tmp/test.txt');",
		},
		{
			name: "hostname is not sensitive", connection: "postgresql://db.invalid/app",
			query: "SELECT pg_read_file('/etc/hostname');",
		},
		{
			name: "path traversal", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/srv/../etc/passwd');",
		},
		{
			name: "second statement", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/etc/passwd'); SELECT 1;",
		},
		{
			name: "source string literal", connection: "mysql://db.invalid/app",
			query: "SELECT 'LOAD_FILE(''/etc/passwd'')';",
		},
		{
			name: "dynamic argument", connection: "postgresql://db.invalid/app",
			query: "SELECT pg_read_file(current_setting('config_file'));",
		},
		{
			name: "additional arguments", connection: "postgresql://db.invalid/app",
			query: "SELECT pg_read_file('/etc/passwd', 0, 100);",
		},
		{
			name: "inline comment", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE/* source */('/etc/passwd');",
		},
		{
			name: "implicit alias", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/etc/passwd') file_contents;",
		},
		{
			name: "quoted alias", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/etc/passwd') AS \"file_contents\";",
		},
		{
			name: "qualified alias", connection: "mysql://db.invalid/app",
			query: "SELECT LOAD_FILE('/etc/passwd') AS result.file_contents;",
		},
		{
			name: "copy nonsensitive source", connection: "postgresql://db.invalid/app",
			query: "COPY (SELECT pg_read_file('/etc/hostname')) TO '/tmp/server-copy';",
		},
		{
			name: "copy dynamic output", connection: "postgresql://db.invalid/app",
			query: "COPY (SELECT pg_read_file('/etc/shadow')) TO output_path;",
		},
		{
			name: "copy second statement", connection: "postgresql://db.invalid/app",
			query: "COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/server-copy'; SELECT 1;",
		},
		{
			name: "mysql copy wrapper", connection: "mysql://db.invalid/app",
			query: "COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/server-copy';",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tool := test.tool
			if tool == "" {
				tool = "sql_query"
			}
			input := sqlSensitiveServerFileReadInput(
				t, test.connection, test.database, test.query,
			)
			input.Tool = tool
			facts := Analyze(input)
			if fact, ok := ExactSQLSensitiveServerFileRead(facts); ok {
				t.Fatalf("unexpected fact=%+v", fact)
			}
		})
	}
}

func TestSQLSensitiveServerFileReadRejectsNonClosedSchema(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"connection": "mysql://db.invalid/app",
		"database":   "app",
		"query":      "SELECT LOAD_FILE('/etc/passwd');",
		"dialect":    "mysql",
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{Tool: "sql_query", Args: raw})
	if fact, ok := ExactSQLSensitiveServerFileRead(facts); ok {
		t.Fatalf("unexpected fact=%+v", fact)
	}
}

func TestSQLSensitiveServerFileReadEmptyOptionalDatabaseRemainsAuthoritative(t *testing.T) {
	raw, err := json.Marshal(map[string]string{
		"connection": "mysql://analyst@db.invalid:3306/app",
		"database":   "",
		"query":      "SELECT LOAD_FILE('/etc/passwd');",
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{Tool: "sql_query", Args: raw, CWD: "/repo"})
	if !facts.Authoritative() {
		t.Fatalf("parse=%+v", facts.Parse)
	}
	if fact, ok := ExactSQLSensitiveServerFileRead(facts); !ok ||
		fact.DatabaseEngine != "mysql" ||
		fact.PathClass != SQLSensitiveServerFileAccountDatabase {
		t.Fatalf("fact=%+v ok=%v", fact, ok)
	}
}

func sqlSensitiveServerFileReadInput(
	t *testing.T,
	connection string,
	database string,
	query string,
) Input {
	t.Helper()
	args := map[string]string{"connection": connection, "query": query}
	if database != "" {
		args["database"] = database
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Tool: "sql_query", Args: raw, CWD: "/repo"}
}
