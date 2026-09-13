// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSensitiveSQLRowsetReadMCPHuntShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		tool  string
		args  string
		class SensitiveSQLTableClass
	}{
		{
			name: "mcp sqlite credentials wildcard",
			tool: "read_query", args: `{"query":"SELECT * FROM credentials"}`,
			class: SensitiveSQLTableCredentials,
		},
		{
			name: "credentials explicit field order and limit",
			tool: "read_query", args: `{"query":"SELECT id, password FROM credentials ORDER BY id DESC LIMIT 100;"}`,
			class: SensitiveSQLTableCredentials,
		},
		{
			name: "oauth access token",
			tool: "read_query", args: `{"query":"select access_token from oauth_tokens limit 3"}`,
			class: SensitiveSQLTableOAuthTokens,
		},
		{
			name: "oauth refresh token",
			tool: "read_query", args: `{"query":"SELECT subject, refresh_token FROM oauth_tokens"}`,
			class: SensitiveSQLTableOAuthTokens,
		},
		{
			name: "employee ssn",
			tool: "read_query", args: `{"query":"SELECT employee_id, ssn FROM employees ORDER BY employee_id ASC"}`,
			class: SensitiveSQLTableEmployees,
		},
		{
			name:  "existing structured sql query",
			tool:  "sql_query",
			args:  `{"connection":"sqlite://database.invalid/synthetic","database":"synthetic","query":"SELECT password FROM credentials"}`,
			class: SensitiveSQLTableCredentials,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: test.tool, Args: json.RawMessage(test.args),
				ToolResourceIdentity: "mcp://sqlite/synthetic-database",
			})
			reads := ExactSensitiveSQLRowsetReads(facts)
			if len(reads) != 1 {
				t.Fatalf("reads = %#v, parse = %#v", reads, facts.Parse)
			}
			if reads[0].TableClass != test.class || !reads[0].Exact ||
				!validPrivateDigest(reads[0].DatabaseIdentityDigest) {
				t.Fatalf("read = %#v", reads[0])
			}
		})
	}
}

func TestSensitiveSQLRowsetReadRejectsOpenGrammar(t *testing.T) {
	t.Parallel()
	queries := []string{
		"SELECT id FROM credentials",
		"SELECT access_token FROM credentials",
		"SELECT ssn FROM oauth_tokens",
		"SELECT password FROM users",
		"SELECT password FROM credentials WHERE id = 1",
		"SELECT password FROM credentials JOIN users ON users.id = credentials.user_id",
		"WITH rows AS (SELECT * FROM credentials) SELECT * FROM rows",
		"SELECT password FROM credentials UNION SELECT value FROM configuration",
		"SELECT (SELECT password FROM credentials) FROM users",
		"SELECT lower(password) FROM credentials",
		"SELECT password || suffix FROM credentials",
		"SELECT password FROM credentials; SELECT ssn FROM employees",
		"SELECT password FROM credentials -- reviewed",
		"SELECT password /* reviewed */ FROM credentials",
		"SELECT `password` FROM credentials",
		"SELECT password FROM ${TABLE}",
		"SELECT password FROM credentials ORDER BY id, password",
		"SELECT password FROM credentials LIMIT 0",
		"SELECT password FROM credentials LIMIT 01",
		"SELECT password FROM credentials LIMIT 1000001",
		"SELECT *, password FROM credentials",
		"SELECT password, FROM credentials",
		"SELECT password FROM credentials trailing",
	}
	for _, query := range queries {
		query := query
		t.Run(query, func(t *testing.T) {
			t.Parallel()
			args, err := json.Marshal(map[string]string{"query": query})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{
				Tool: "read_query", Args: args,
				ToolResourceIdentity: "mcp://sqlite/synthetic-database",
			})
			if reads := ExactSensitiveSQLRowsetReads(facts); len(reads) != 0 {
				t.Fatalf("unexpected reads: %#v", reads)
			}
		})
	}
}

func TestSensitiveSQLRowsetReadRequiresTrustedIdentityAndClosedEnvelope(t *testing.T) {
	t.Parallel()
	base := `{"query":"SELECT password FROM credentials"}`
	tests := []struct {
		name     string
		args     string
		identity string
		command  string
	}{
		{name: "missing trusted identity", args: base},
		{name: "dynamic trusted identity", args: base, identity: "mcp://sqlite/${DATABASE}"},
		{name: "unknown argument", args: `{"query":"SELECT password FROM credentials","database":"synthetic"}`, identity: "mcp://sqlite/synthetic"},
		{name: "argument cannot supply trusted identity", args: `{"query":"SELECT password FROM credentials","tool_resource_identity":"mcp://sqlite/attacker-chosen"}`},
		{name: "identity cannot come from arguments", args: `{"query":"SELECT password FROM credentials","tool_resource_identity":"mcp://sqlite/untrusted"}`},
		{name: "duplicate argument", args: `{"query":"SELECT password FROM credentials","query":"SELECT ssn FROM employees"}`, identity: "mcp://sqlite/synthetic"},
		{name: "nested query", args: `{"query":{"text":"SELECT password FROM credentials"}}`, identity: "mcp://sqlite/synthetic"},
		{name: "conflicting command", args: base, identity: "mcp://sqlite/synthetic", command: "echo inert"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: "read_query", Args: json.RawMessage(test.args),
				ToolResourceIdentity: test.identity, Command: test.command,
			})
			if reads := ExactSensitiveSQLRowsetReads(facts); len(reads) != 0 {
				t.Fatalf("unexpected reads: %#v", reads)
			}
		})
	}

	oversized, err := json.Marshal(map[string]string{
		"query": "SELECT password FROM credentials " + strings.Repeat("x", maxCommandBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := Analyze(Input{
		Tool: "read_query", Args: oversized,
		ToolResourceIdentity: "mcp://sqlite/synthetic",
	})
	if reads := ExactSensitiveSQLRowsetReads(facts); len(reads) != 0 {
		t.Fatalf("oversized reads: %#v", reads)
	}
}

func TestSensitiveSQLRowsetIdentityDigestIsStableSeparatedAndPrivate(t *testing.T) {
	t.Parallel()
	input := Input{
		Tool:                 "read_query",
		Args:                 json.RawMessage(`{"query":"SELECT password FROM credentials"}`),
		ToolResourceIdentity: "mcp://sqlite/synthetic-database",
	}
	first := ExactSensitiveSQLRowsetReads(Analyze(input))
	second := ExactSensitiveSQLRowsetReads(Analyze(input))
	other := input
	other.ToolResourceIdentity = "mcp://sqlite/other-synthetic-database"
	third := ExactSensitiveSQLRowsetReads(Analyze(other))
	if len(first) != 1 || len(second) != 1 || len(third) != 1 {
		t.Fatalf("unexpected facts: %#v %#v %#v", first, second, third)
	}
	if first[0].DatabaseIdentityDigest != second[0].DatabaseIdentityDigest {
		t.Fatal("same trusted identity produced different digests")
	}
	if first[0].DatabaseIdentityDigest == third[0].DatabaseIdentityDigest {
		t.Fatal("different trusted identities produced the same digest")
	}
	if first[0].DatabaseIdentityDigest == framedPrivateDigest(
		structuredFilePersistenceIdentityDomain,
		input.ToolResourceIdentity,
		"/synthetic/output.txt",
	) {
		t.Fatal("source and sink digest domains were not separated")
	}

	encodedInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedInput), input.ToolResourceIdentity) {
		t.Fatalf("trusted identity serialized in input: %s", encodedInput)
	}
	encodedFacts, err := json.Marshal(Analyze(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"SELECT password FROM credentials",
		input.ToolResourceIdentity,
		first[0].DatabaseIdentityDigest,
		"SensitiveSQLRowsetReads",
	} {
		if strings.Contains(string(encodedFacts), forbidden) {
			t.Fatalf("private rowset material %q serialized: %s", forbidden, encodedFacts)
		}
	}
}
