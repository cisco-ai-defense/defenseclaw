// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"testing"
)

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
