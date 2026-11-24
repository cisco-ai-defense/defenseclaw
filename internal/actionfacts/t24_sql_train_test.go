// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

func TestSQLSessionRollbackAcrossInputs(t *testing.T) {
	rows := []struct{ name, command, bare string }{
		{"commit in later option", "psql -c 'BEGIN; DELETE FROM customers;' -c 'COMMIT;'", "psql -c 'DELETE FROM customers'"},
		{"named TSQL rollback", "sqlcmd -Q 'BEGIN TRAN; DELETE FROM customers; ROLLBACK TRAN sp; COMMIT;'", "sqlcmd -Q 'DELETE FROM customers'"},
		{"MySQL implicit commit", "mysql -e 'BEGIN; DELETE FROM customers; LOCK TABLES audit_log READ; ROLLBACK;'", "mysql -e 'DELETE FROM customers'"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: row.command}))
			bare := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: row.bare}))
			if len(bare) != 1 || len(got) != 1 || got[0] != bare[0] {
				t.Fatalf("session mutations=%v, bare=%v", got, bare)
			}
		})
	}
	for _, command := range []string{
		"psql -c 'BEGIN; DELETE FROM customers; ROLLBACK;'",
		"mysql -e 'BEGIN; DELETE FROM customers; ROLLBACK;'",
		"mysql -e 'BEGIN; DELETE FROM customers; RESET PERSIST x; ROLLBACK;'",
		"mysql -e 'BEGIN; DELETE FROM customers; UNLOCK TABLES; ROLLBACK;'",
	} {
		if got := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: command})); len(got) != 0 {
			t.Errorf("rolled-back benign twin mutations=%v", got)
		}
	}
}

func TestSQLDialectSpanBoundaries(t *testing.T) {
	rows := []struct {
		name, engine, query string
		wantDrop            bool
	}{
		{"mysql dash operator", "mysql", "SELECT 5--1; DROP TABLE users;", true},
		{"mysql hash comment", "mysql", "SELECT 1 # ; DROP TABLE hidden\n; DROP TABLE users;", true},
		{"postgres nested comment", "postgresql", "SELECT 1 /* outer /* inner */ '; DROP TABLE hidden; */; DROP TABLE users;", true},
		{"TSQL bracket", "sqlserver", "SELECT [a'b]; DROP TABLE users;", true},
		{"mysql no backslash escapes", "mysql", "SET sql_mode='NO_BACKSLASH_ESCAPES'; SELECT 'x\\'; DROP TABLE users;", true},
		{"mysql hash benign", "mysql", "SELECT 1 # ; DROP TABLE hidden\n;", false},
		{"postgres nested benign", "postgresql", "SELECT 1 /* outer /* inner */ ; DROP TABLE hidden; */;", false},
		{"TSQL bracket benign", "sqlserver", "SELECT [a'b; DROP TABLE hidden];", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			statements, _, _, _ := sqlStatements(row.engine, row.query)
			found := false
			for _, statement := range statements {
				if len(statement.words) > 1 && statement.words[0] == "DROP" && statement.words[1] == "TABLE" {
					found = true
				}
			}
			if found != row.wantDrop {
				t.Errorf("DROP statement=%v, want %v (count=%d)", found, row.wantDrop, len(statements))
			}
		})
	}
}

func TestOverLimitSQLQueryChunksAcrossReaders(t *testing.T) {
	query := strings.Repeat("SELECT 1; ", 600) + "DROP TABLE users;"
	nested := "bash -c " + posixSingleQuoted("psql -c "+posixSingleQuoted(query))
	direct := "kubectl exec db-0 -- psql -c " + posixSingleQuoted(query)
	for _, row := range []struct {
		name, command string
		argv          bool
	}{
		{"nested", nested, true}, {"pod exec", direct, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var split OverLimitWordSplit
			var ok bool
			if row.argv {
				split, ok = SplitOverLimitWordsOfArgv(row.command)
			} else {
				split, ok = SplitOverLimitWords(row.command)
			}
			if !ok || split.Query == 0 || len(split.QueryChunks) == 0 {
				t.Fatalf("split ok=%v query=%d chunks=%d why=%q", ok, split.Query, len(split.QueryChunks), split.Why)
			}
			found := false
			for _, chunk := range split.QueryChunks {
				found = found || strings.Contains(chunk, "DROP TABLE users")
			}
			if !found {
				t.Error("later query chunks lost the last statement")
			}
			if row.name == "pod exec" {
				readDrop := false
				for _, chunk := range split.QueryChunks {
					for _, twin := range PodExecTwinCommands(Analyze(Input{Tool: "shell", Command: chunk})) {
						for _, fact := range ExactSQLMutations(Analyze(Input{Tool: "shell", Command: twin})) {
							readDrop = readDrop || fact.Operation == SQLMutationDropTable
						}
					}
				}
				if !readDrop {
					t.Error("pod exec reading lost the later DROP mutation")
				}
			}
		})
	}
}

func TestSQLServerFileReadCleansPath(t *testing.T) {
	for _, row := range []struct{ engine, query, plain string }{
		{"mysql", "SELECT LOAD_FILE('/etc////shadow')", "SELECT LOAD_FILE('/etc/shadow')"},
		{"postgresql", "SELECT pg_read_file('/etc/./shadow')", "SELECT pg_read_file('/etc/shadow')"},
		{"mysql", "SELECT LOAD_FILE('/srv/../etc/passwd')", "SELECT LOAD_FILE('/etc/passwd')"},
	} {
		got := sqlSensitiveServerFileReadFacts(row.engine, row.query)
		plain := sqlSensitiveServerFileReadFacts(row.engine, row.plain)
		if len(got) != 1 || len(plain) != 1 || got[0] != plain[0] {
			t.Errorf("%s cleaned=%v plain=%v", row.engine, got, plain)
		}
	}
	if got := sqlSensitiveServerFileReadFacts("mysql", "SELECT LOAD_FILE('/srv/app/./readme.txt')"); len(got) != 0 {
		t.Errorf("benign file read=%v", got)
	}
}
