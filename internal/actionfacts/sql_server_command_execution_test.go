// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSQLServerCommandExecutionFactsAreExactAndValueFree(t *testing.T) {
	connection := "sqlserver://fixture-user:fixture-password@db.invalid:1433"
	project := func(query string) (SQLServerCommandOperation, string, bool, Facts) {
		t.Helper()
		facts := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(t, connection, "production", query)})
		operation, digest, ok := ExactSQLServerCommandExecution(facts)
		return operation, digest, ok, facts
	}
	enableOperation, enableDigest, enableOK, enableFacts := project(
		"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
	)
	invokeOperation, invokeDigest, invokeOK, invokeFacts := project(
		"EXEC master.dbo.xp_cmdshell 'fixture-command --flag';",
	)
	if !enableOK || enableOperation != SQLServerXPCommandShellEnable ||
		!invokeOK || invokeOperation != SQLServerXPCommandShellInvoke ||
		enableDigest == "" || enableDigest != invokeDigest {
		t.Fatalf("enable=%q/%t invoke=%q/%t digest equality=%t",
			enableOperation, enableOK, invokeOperation, invokeOK, enableDigest == invokeDigest)
	}
	for _, facts := range []Facts{enableFacts, invokeFacts} {
		encoded, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(connection)) ||
			bytes.Contains(encoded, []byte("fixture-password")) ||
			bytes.Contains(encoded, []byte("fixture-command")) {
			t.Fatalf("content-bearing value survived projection")
		}
		if len(facts.SQLServerCommandExecutions) != 1 || len(facts.Commands) != 0 {
			t.Fatalf("unexpected SQL projection: %+v", facts)
		}
	}
}

func TestSQLServerCommandExecutionHardNegatives(t *testing.T) {
	tests := []struct {
		name       string
		tool       string
		connection string
		database   string
		query      string
		extra      bool
	}{
		{name: "wrong tool", tool: "database_query", connection: "prod", query: "EXEC xp_cmdshell 'id'"},
		{name: "disable", tool: "sql_query", connection: "prod", query: "EXEC sp_configure 'xp_cmdshell', 0"},
		{name: "inspection", tool: "sql_query", connection: "prod", query: "EXEC sp_configure 'xp_cmdshell'"},
		{name: "dynamic invocation", tool: "sql_query", connection: "prod", query: "EXEC xp_cmdshell @command"},
		{name: "dynamic query", tool: "sql_query", connection: "prod", query: "EXEC(@sql)"},
		{name: "mixed batch", tool: "sql_query", connection: "prod", query: "SELECT 1; EXEC xp_cmdshell 'id'"},
		{name: "unknown field", tool: "sql_query", connection: "prod", query: "EXEC xp_cmdshell 'id'", extra: true},
		{name: "placeholder connection", tool: "sql_query", connection: "${DATABASE_URL}", query: "EXEC xp_cmdshell 'id'"},
		{name: "empty payload", tool: "sql_query", connection: "prod", query: "EXEC xp_cmdshell ''"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := map[string]any{"connection": test.connection, "query": test.query}
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
			facts := Analyze(Input{Tool: test.tool, Args: raw})
			operation, _, ok := ExactSQLServerCommandExecution(facts)
			if test.name == "disable" {
				if !ok || operation != SQLServerXPCommandShellDisable {
					t.Fatalf("disable barrier omitted: %+v", facts.SQLServerCommandExecutions)
				}
				return
			}
			if ok || len(facts.SQLServerCommandExecutions) != 0 {
				t.Fatalf("hard negative projected SQL operation: %+v", facts.SQLServerCommandExecutions)
			}
		})
	}
}

func TestSQLServerConnectionDigestRequiresExactNormalizedIdentity(t *testing.T) {
	query := "EXEC xp_cmdshell 'id'"
	first := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(t, "prod", "one", query)})
	same := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(t, "prod", "one", query)})
	different := Analyze(Input{Tool: "sql_query", Args: mustSQLQueryArgs(t, "prod", "two", query)})
	_, firstDigest, _ := ExactSQLServerCommandExecution(first)
	_, sameDigest, _ := ExactSQLServerCommandExecution(same)
	_, differentDigest, _ := ExactSQLServerCommandExecution(different)
	if firstDigest == "" || firstDigest != sameDigest || firstDigest == differentDigest {
		t.Fatalf("digest exactness equality=%t mismatch=%t", firstDigest == sameDigest, firstDigest != differentDigest)
	}
}

func mustSQLQueryArgs(t *testing.T, connection, database, query string) json.RawMessage {
	t.Helper()
	object := map[string]string{"connection": connection, "query": query}
	if database != "" {
		object["database"] = database
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
