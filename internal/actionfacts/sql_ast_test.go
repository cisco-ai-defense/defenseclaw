// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParseSQLASTFacts(t *testing.T) {
	tests := []struct {
		name                     string
		query                    string
		verbs, tables, functions []string
		statements               int
	}{
		{
			name:  "quoted identifier",
			query: "DROP TABLE \"users\";",
			verbs: []string{"drop"}, tables: []string{"users"}, statements: 1,
		},
		{
			name:  "CTE DML",
			query: "WITH d AS (DELETE FROM users RETURNING 1) SELECT 1;",
			verbs: []string{"delete", "select"}, tables: []string{"users"}, statements: 1,
		},
		{
			name:  "DO execute body",
			query: "DO $$BEGIN EXECUTE 'DROP TABLE x'; END$$;",
			verbs: []string{"do", "begin", "execute", "drop"}, tables: []string{"x"}, statements: 1,
		},
		{
			name:  "multiple statements and file read",
			query: "SELECT pg_read_file('/etc/passwd'); SELECT 1;",
			verbs: []string{"select"}, functions: []string{"pg_read_file"}, statements: 2,
		},
		{
			name:  "literal is not a verb",
			query: "SELECT 'DROP TABLE users';",
			verbs: []string{"select"}, statements: 1,
		},
		{
			name:  "grant and alter",
			query: "GRANT SELECT ON TABLE users TO analyst; ALTER ROLE analyst WITH NOLOGIN;",
			verbs: []string{"grant", "select", "alter"}, tables: []string{"users"}, statements: 2,
		},
		{
			name:  "bracketed identifier",
			query: "DROP TABLE [users];",
			verbs: []string{"drop"}, tables: []string{"users"}, statements: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseSQLAST(test.query)
			if got.unknown {
				t.Fatal("unexpected unknown parse")
			}
			if !reflect.DeepEqual(got.verbs, test.verbs) ||
				!reflect.DeepEqual(got.tables, test.tables) ||
				!reflect.DeepEqual(got.functions, test.functions) ||
				got.statementCount != test.statements {
				t.Fatalf("facts = verbs %v tables %v functions %v statements %d",
					got.verbs, got.tables, got.functions, got.statementCount)
			}
		})
	}
}

func TestParseSQLASTBoundsAndMalformedInput(t *testing.T) {
	cases := []string{
		"SELECT 'unterminated",
		"SELECT $$unterminated",
		"SELECT (1",
		string(make([]byte, maxSQLASTBytes+1)),
	}
	for _, query := range cases {
		if got := parseSQLAST(query); !got.unknown {
			t.Fatalf("expected unknown for %q", query[:min(len(query), 32)])
		}
	}
}

func TestPSQLASTFactsAndMutationFacts(t *testing.T) {
	cases := []struct {
		name, command string
		want          SQLMutationOperation
	}{
		{"quoted drop", "psql -d production -c 'DROP TABLE \"users\";'", SQLMutationDropTable},
		{"CTE delete", "psql -d production -c 'WITH d AS (DELETE FROM users RETURNING 1) SELECT 1;'", SQLMutationDeleteUnbounded},
		{"DO execute drop", "psql -d production <<'SQL'\nDO $$BEGIN EXECUTE 'DROP TABLE x'; END$$;\nSQL", SQLMutationDropTable},
		{"unbounded update", "psql -d production -c 'UPDATE users SET active = false;'", SQLMutationUpdateUnbounded},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command})
			if len(facts.SQLFacts) != 1 {
				t.Fatalf("SQL facts = %#v", facts.SQLFacts)
			}
			mutations := ExactSQLMutations(facts)
			if len(mutations) != 1 || mutations[0].Operation != test.want {
				t.Fatalf("mutations = %#v", mutations)
			}
		})
	}
}

func TestPSQLASTBenignSQLPreserved(t *testing.T) {
	cases := []string{
		"psql -d production -c 'SELECT \"DROP TABLE users\";'",
		"psql -d production -c 'INSERT INTO users VALUES (1);'",
		"psql -d production -c 'DELETE FROM users WHERE id = 1;'",
		"psql -d production -c 'UPDATE users SET active = false WHERE id = 1;'",
		"psql -d production -c 'EXPLAIN DELETE FROM users;'",
		"psql -d production -c 'BEGIN; DELETE FROM users; ROLLBACK;'",
		"psql -d production -c '\\dt'",
	}
	for _, command := range cases {
		if got := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: command})); len(got) != 0 {
			t.Errorf("benign SQL gained mutation fact: %q => %#v", command, got)
		}
	}
}

func TestSQLAST64KiBStdinP99(t *testing.T) {
	query := "SELECT 1" + strings.Repeat(" ", maxSQLASTBytes-len("SELECT 1"))
	facts := Facts{Parse: ParseResult{Status: StatusComplete}, Commands: []CommandFact{{
		Kind: CommandKindProcess, Effect: EffectExecute, Program: "psql",
		Argv: []string{"psql", "-d", "production"}, ArgvComplete: true,
		LiteralStdin: query, LiteralStdinComplete: true,
	}}}
	const samples = 101
	timings := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		_, sqlFacts, _ := projectSQLAnalysis(Input{}, facts)
		timings = append(timings, time.Since(start))
		if len(sqlFacts) != 1 || sqlFacts[0].StatementCount != 1 {
			t.Fatalf("64 KiB SQL stdin not fully classified: %#v", sqlFacts)
		}
	}
	sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
	p99 := timings[(samples*99+99)/100-1]
	t.Logf("64 KiB psql stdin Analyze p99=%s min=%s max=%s samples=%d", p99, timings[0], timings[len(timings)-1], samples)
}

func TestSQLASTDoesNotPromoteStringTokensToMutations(t *testing.T) {
	parsed := parseSQLAST("SELECT 'DROP' 'TABLE' 'users';")
	if parsed.unknown {
		t.Fatal("unexpected unknown parse")
	}
	if len(parsed.mutations) != 0 {
		t.Fatalf("string token sequence became mutations: %#v", parsed.mutations)
	}
}

func TestSQLASTClosesLegacyDestructiveSQLMisses(t *testing.T) {
	cases := []struct {
		name, query, command string
		want                 SQLMutationOperation
	}{
		{"quoted DROP", `DROP TABLE "users";`, `psql -d production -c 'DROP TABLE "users";'`, SQLMutationDropTable},
		{"CTE DELETE", "WITH d AS (DELETE FROM users RETURNING 1) SELECT 1;", `psql -d production -c 'WITH d AS (DELETE FROM users RETURNING 1) SELECT 1;'`, SQLMutationDeleteUnbounded},
		{"DO EXECUTE DROP", "DO $$BEGIN EXECUTE 'DROP TABLE x'; END$$;", "psql -d production <<'SQL'\nDO $$BEGIN EXECUTE 'DROP TABLE x'; END$$;\nSQL", SQLMutationDropTable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, ok := exactSQLMutation("postgresql", test.query); ok {
				t.Fatalf("legacy SQL classifier unexpectedly covered miss %q", test.query)
			}
			facts := Analyze(Input{Tool: "shell", Command: test.command})
			mutations := ExactSQLMutations(facts)
			if len(mutations) != 1 || mutations[0].Operation != test.want {
				t.Fatalf("new SQL AST mutations = %#v", mutations)
			}
		})
	}
}
