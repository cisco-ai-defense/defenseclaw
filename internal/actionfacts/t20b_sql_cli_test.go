// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestT20BOverLimitSQLQueryIsCode (DET111 T20 review, psql -c long
// identifier): the inline query of a SQL client past the string bound is code
// in the client's grammar, as a sed script is (GAP-0761): the SQL readers read
// it as what the server runs. At 1.0.10, 17170c4ab4 and 06f1da5b94 it was a
// DATA word, judged as a twin with a stand-in query, so a COPY ... PROGRAM
// with a 5000-byte identifier was a clean allow. The database operand and the
// command a pod exec starts stay DATA. Red at 06f1da5b94.
func TestT20BOverLimitSQLQueryIsCode(t *testing.T) {
	big := strings.Repeat("a", 5000)
	query := `COPY "` + big + `" (c) TO PROGRAM 'id'`
	rows := []struct {
		id, command string
		data, code  int
	}{
		{"psql-c", `psql -d production -c "` + strings.ReplaceAll(query, `"`, `\"`) + `"`, 0, 1},
		{"psql-command-glued", `psql -d production '--command=` + strings.ReplaceAll(query, "'", "") + `'`, 0, 1},
		{"psql-command", `psql --command '` + big + `' production`, 0, 1},
		{"mysql-e", `mysql -h db -e '` + big + `'`, 0, 1},
		{"sqlcmd-Q", `sqlcmd -S db -Q '` + big + `'`, 0, 1},
		{"psql-database-operand", `psql -c 'SELECT 1' '` + big + `'`, 1, 0},
		{"kubectl-exec-other", `kubectl exec db-0 -- printf '` + big + `'`, 1, 0},
		{"echo-data", `echo '` + big + `'`, 1, 0},
	}
	for _, r := range rows {
		split, ok := SplitOverLimitWords(r.command)
		if r.data == 0 {
			if ok {
				t.Errorf("%s: split ok with data=%d code=%d, want the query in code position", r.id, split.Data, split.Code)
			}
			continue
		}
		if !ok || split.Data != r.data || split.Code != r.code {
			t.Errorf("%s: split ok=%v data=%d code=%d why=%q, want data=%d code=%d",
				r.id, ok, split.Data, split.Code, split.Why, r.data, r.code)
		}
	}
}

// TestT20BSQLCLIServerReadersCoverMoreClients (DET111 T20 review P3-3): COPY
// ... PROGRAM and the sensitive server file read were read only from a call
// of exactly one psql command. They now read every command of the call, each
// -c of psql, and mysql and mariadb -e for LOAD_FILE. Benign queries on the
// same surfaces give no fact. Red at 06f1da5b94.
func TestT20BSQLCLIServerReadersCoverMoreClients(t *testing.T) {
	copyRows := []struct {
		id, command string
		want        bool
	}{
		{"two-psql", `psql -d production -c "SELECT 1"; psql -d production -c "COPY t (c) TO PROGRAM 'id'"`, true},
		{"psql-two-c", `psql -d production -c "SELECT 1" -c "COPY t (c) TO PROGRAM 'id'"`, true},
		{"benign-copy-stdout", `psql -d production -c "SELECT 1"; psql -d production -c "COPY t TO STDOUT"`, false},
		{"benign-two-c", `psql -d production -c "SELECT 1" -c "SELECT 2"`, false},
		{"mysql-not-copy", `mysql -h db -e "COPY t (c) TO PROGRAM 'id'"`, false},
	}
	for _, r := range copyRows {
		facts := Analyze(Input{Tool: "shell", Command: r.command})
		if _, got := ExactPostgreSQLCopyProgram(facts); got != r.want {
			t.Errorf("copy %s: fact=%v, want %v (%#v)", r.id, got, r.want, facts.PostgreSQLCopyPrograms)
		}
	}
	readRows := []struct {
		id, command, engine string
	}{
		{"mysql-e", `mysql -h db -e "SELECT LOAD_FILE('/etc/shadow')"`, "mysql"},
		{"mariadb-execute", `mariadb -h db --execute="SELECT LOAD_FILE('/etc/passwd')"`, "mysql"},
		{"two-psql", `psql -d production -c "SELECT 1"; psql -d production -c "SELECT pg_read_file('/etc/passwd')"`, "postgresql"},
		{"benign-mysql", `mysql -h db -e "SELECT 1"`, ""},
		{"benign-mysql-load-file-own", `mysql -h db -e "SELECT LOAD_FILE('/srv/app/readme.txt')"`, ""},
		{"benign-kubectl-cat", `kubectl exec db-0 -- cat /etc/passwd`, ""},
	}
	for _, r := range readRows {
		facts := Analyze(Input{Tool: "shell", Command: r.command})
		got, ok := ExactSQLSensitiveServerFileRead(facts)
		if ok != (r.engine != "") || (ok && got.DatabaseEngine != r.engine) {
			t.Errorf("read %s: fact=%#v ok=%v, want engine %q", r.id, got, ok, r.engine)
		}
	}
}
