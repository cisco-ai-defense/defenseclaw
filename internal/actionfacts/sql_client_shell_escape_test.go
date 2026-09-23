// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactSQLClientShellEscapes(t *testing.T) {
	tests := []struct {
		name    string
		input   Input
		client  SQLClientShellEscapeClient
		program string
	}{
		{
			name:   "SQLite sh with database",
			input:  Input{Tool: "shell", Command: `sqlite3 /tmp/app.db '.shell /bin/sh'`},
			client: SQLClientShellEscapeSQLite, program: "sqlite3",
		},
		{
			name:   "SQLite bash without database",
			input:  Input{Tool: "shell", Command: `sqlite3 '.shell /bin/bash'`},
			client: SQLClientShellEscapeSQLite, program: "sqlite3",
		},
		{
			name:   "MySQL sh",
			input:  Input{Tool: "shell", Command: `mysql -u root -p'fixture-password' -h db.invalid -D app -e '\! /bin/sh'`},
			client: SQLClientShellEscapeMySQL, program: "mysql",
		},
		{
			name:   "MariaDB bash",
			input:  Input{Tool: "shell", Command: `mariadb --batch --database=app --execute='\! /bin/bash'`},
			client: SQLClientShellEscapeMySQL, program: "mariadb",
		},
		{
			name:   "structured argv",
			input:  Input{Tool: "shell", Argv: []string{"sqlite3", "app.db", ".shell /bin/sh"}, DialectHint: DialectArgv},
			client: SQLClientShellEscapeSQLite, program: "sqlite3",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			got := ExactSQLClientShellEscapes(facts)
			if !facts.Authoritative() || !facts.EnforcementEligible() || len(got) != 1 {
				t.Fatalf("facts not exact/enforceable: parse=%+v commands=%+v escapes=%+v", facts.Parse, facts.Commands, got)
			}
			if got[0].Client != test.client || got[0].CommandID != facts.Commands[0].ID || !got[0].Exact ||
				facts.Commands[0].Program != test.program {
				t.Fatalf("escape=%+v commands=%+v", got[0], facts.Commands)
			}
			projected := facts.EnforcementProjection()
			if projectedEscapes := ExactSQLClientShellEscapes(projected); len(projectedEscapes) != 1 ||
				projectedEscapes[0] != got[0] {
				t.Fatalf("enforcement projection lost exact escape: %+v", projected)
			}
		})
	}
}

func TestExactSQLClientShellEscapeHardNegatives(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{"SQLite help", Input{Tool: "shell", Command: `sqlite3 app.db '.help'`}},
		{"SQLite shell help", Input{Tool: "shell", Command: `sqlite3 app.db '.shell'`}},
		{"SQLite quoted mention", Input{Tool: "shell", Command: `printf '%s\n' '.shell /bin/sh'`}},
		{"SQLite dynamic shell", Input{Tool: "shell", Command: `sqlite3 app.db ".shell $SHELL"`}},
		{"SQLite extra command", Input{Tool: "shell", Command: `sqlite3 app.db '.tables' '.shell /bin/sh'`}},
		{"SQLite extra shell argument", Input{Tool: "shell", Command: `sqlite3 app.db '.shell /bin/sh -c id'`}},
		{"SQLite option", Input{Tool: "shell", Command: `sqlite3 -readonly app.db '.shell /bin/sh'`}},
		{"SQLite wrong shell", Input{Tool: "shell", Command: `sqlite3 app.db '.shell /usr/bin/sh'`}},
		{"SQLite wrong client", Input{Tool: "shell", Command: `sqlite app.db '.shell /bin/sh'`}},
		{"SQLite PowerShell dialect", Input{Tool: "PowerShell", Command: `sqlite3 app.db '.shell /bin/sh'`, DialectHint: DialectPowerShell}},
		{"SQLite compound", Input{Tool: "shell", Command: `sqlite3 app.db '.shell /bin/sh'; echo done`}},
		{"SQLite conditional", Input{Tool: "shell", Command: `if test -f app.db; then sqlite3 app.db '.shell /bin/sh'; fi`}},
		{"SQLite wrapper", Input{Tool: "shell", Command: `sudo sqlite3 app.db '.shell /bin/sh'`}},
		{"SQLite pipeline", Input{Tool: "shell", Command: `sqlite3 app.db '.shell /bin/sh' | cat`}},
		{"MySQL help", Input{Tool: "shell", Command: `mysql --help`}},
		{"MySQL meta help", Input{Tool: "shell", Command: `mysql -e '\h'`}},
		{"MySQL quoted mention", Input{Tool: "shell", Command: `printf '%s\n' '\! /bin/sh'`}},
		{"MySQL dynamic shell", Input{Tool: "shell", Command: `mysql -e "\! $SHELL"`}},
		{"MySQL extra command", Input{Tool: "shell", Command: `mysql -e '\! /bin/sh; SELECT 1'`}},
		{"MySQL extra shell argument", Input{Tool: "shell", Command: `mysql -e '\! /bin/sh -c id'`}},
		{"MySQL duplicate execute", Input{Tool: "shell", Command: `mysql -e '\! /bin/sh' -e 'SELECT 1'`}},
		{"MySQL unsupported option", Input{Tool: "shell", Command: `mysql --raw -e '\! /bin/sh'`}},
		{"MySQL bare password prompt", Input{Tool: "shell", Command: `mysql -p -e '\! /bin/sh'`}},
		{"MySQL wrong shell", Input{Tool: "shell", Command: `mysql -e '\! /usr/bin/bash'`}},
		{"MySQL wrong client", Input{Tool: "shell", Command: `psql -c '\! /bin/sh'`}},
		{"MySQL compound", Input{Tool: "shell", Command: `mysql -e '\! /bin/sh' && echo done`}},
		{"MySQL conditional", Input{Tool: "shell", Command: `mysql -e '\! /bin/sh' || true`}},
		{"MySQL wrapper", Input{Tool: "shell", Command: `env mysql -e '\! /bin/sh'`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if got := ExactSQLClientShellEscapes(facts); len(got) != 0 {
				t.Fatalf("near-negative minted exact shell escape: %+v; parse=%+v commands=%+v", got, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactSQLClientShellEscapesRejectMalformedPrivateFacts(t *testing.T) {
	facts := Facts{
		Parse:                 ParseResult{Status: StatusComplete, Dialect: DialectPOSIX},
		SQLClientShellEscapes: []SQLClientShellEscapeFact{{CommandID: 1, Client: "future_client", Exact: true}},
	}
	if got := ExactSQLClientShellEscapes(facts); got != nil {
		t.Fatalf("malformed private fact accepted: %+v", got)
	}
	facts.SQLClientShellEscapes[0].Client = SQLClientShellEscapeSQLite
	if got := ExactSQLClientShellEscapes(facts); got != nil {
		t.Fatalf("orphaned private fact accepted: %+v", got)
	}
}
