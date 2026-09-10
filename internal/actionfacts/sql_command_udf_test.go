// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSQLCommandUDFPostgreSQLExactCreateInvokeIdentity(t *testing.T) {
	connection := "postgresql://admin:fixture-password@db.invalid:5432/production"
	create := Analyze(Input{
		Tool: "sql_query",
		Args: mustSQLQueryArgs(
			t,
			connection,
			"production",
			"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import subprocess; return subprocess.check_output(args, shell=True).decode() $$ LANGUAGE plpython3u;",
		),
	})
	invoke := Analyze(Input{
		Tool: "sql_query",
		Args: mustSQLQueryArgs(
			t,
			connection,
			"production",
			"SELECT exec_cmd('id');",
		),
	})
	createOperation, createEngine, createConnection, createFunction, createOK :=
		ExactSQLCommandUDFOperation(create)
	invokeOperation, invokeEngine, invokeConnection, invokeFunction, invokeOK :=
		ExactSQLCommandUDFOperation(invoke)
	if !createOK || createOperation != SQLCommandUDFCreate ||
		!invokeOK || invokeOperation != SQLCommandUDFInvoke ||
		createEngine != "postgresql" || invokeEngine != createEngine ||
		createConnection == "" || invokeConnection != createConnection ||
		createFunction == "" || invokeFunction != createFunction {
		t.Fatalf("create=%q/%q/%t invoke=%q/%q/%t connection_match=%t function_match=%t",
			createOperation, createEngine, createOK,
			invokeOperation, invokeEngine, invokeOK,
			createConnection == invokeConnection,
			createFunction == invokeFunction,
		)
	}
	assertSQLCommandUDFFactsValueFree(t, connection, "fixture-password", "exec_cmd", create, invoke)
}

func TestSQLCommandUDFPostgreSQLSourceShapes(t *testing.T) {
	tests := []struct {
		name     string
		create   string
		function string
	}{
		{
			name:     "plpython os popen",
			create:   "CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS 'import os; return os.popen(args[0]).read()' LANGUAGE plpythonu;",
			function: "exec_cmd",
		},
		{
			name:     "plpython subprocess",
			create:   "CREATE OR REPLACE FUNCTION exec_cmd(cmd text) RETURNS text AS $$ import subprocess; return subprocess.check_output(cmd, shell=True).decode() $$ LANGUAGE plpython3u;",
			function: "exec_cmd",
		},
		{
			name:     "c shared library",
			create:   "CREATE FUNCTION sys_exec(cmd text) RETURNS void AS '/usr/lib/postgresql/14/lib/sys_exec.so', 'sys_exec' LANGUAGE C STRICT;",
			function: "sys_exec",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			create := Analyze(postgreSQLUDFInput(t, "production", test.create))
			invoke := Analyze(postgreSQLUDFInput(t, "production", "SELECT "+test.function+"('id');"))
			createOperation, createEngine, createConnection, createFunction, createOK :=
				ExactSQLCommandUDFOperation(create)
			invokeOperation, invokeEngine, invokeConnection, invokeFunction, invokeOK :=
				ExactSQLCommandUDFOperation(invoke)
			if !createOK || createOperation != SQLCommandUDFCreate ||
				!invokeOK || invokeOperation != SQLCommandUDFInvoke ||
				createEngine != "postgresql" || invokeEngine != createEngine ||
				createConnection != invokeConnection || createFunction != invokeFunction {
				t.Fatalf("create=%+v invoke=%+v", create.SQLCommandUDFOperations, invoke.SQLCommandUDFOperations)
			}
		})
	}
}

func TestSQLCommandUDFMySQLExactShellArguments(t *testing.T) {
	create := Analyze(Input{
		Tool: "execute_command",
		Args: json.RawMessage(`{"command":"mysql -u root -p'example_password' -e \"CREATE FUNCTION sys_exec RETURNS INT SONAME '/tmp/lib_mysqludf_sys.so';\""}`),
	})
	invoke := Analyze(Input{
		Tool: "execute_command",
		Args: json.RawMessage(`{"command":"mysql -u root -p'example_password' -e \"SELECT sys_exec('gcc -o /tmp/shell /tmp/shell.c && chmod u+s /tmp/shell');\""}`),
	})
	createOperation, createEngine, createConnection, createFunction, createOK :=
		ExactSQLCommandUDFOperation(create)
	invokeOperation, invokeEngine, invokeConnection, invokeFunction, invokeOK :=
		ExactSQLCommandUDFOperation(invoke)
	if !createOK || createOperation != SQLCommandUDFCreate ||
		!invokeOK || invokeOperation != SQLCommandUDFInvoke ||
		createEngine != "mysql" || invokeEngine != createEngine ||
		createConnection == "" || createConnection != invokeConnection ||
		createFunction == "" || createFunction != invokeFunction {
		t.Fatalf("create=%+v parse=%+v invoke=%+v parse=%+v",
			create.SQLCommandUDFOperations, create.Parse,
			invoke.SQLCommandUDFOperations, invoke.Parse)
	}
	assertSQLCommandUDFFactsValueFree(
		t,
		"example_password",
		"sys_exec",
		"gcc -o /tmp/shell",
		create,
		invoke,
	)
}

func TestSQLCommandUDFHardNegatives(t *testing.T) {
	tests := []struct {
		name         string
		input        Input
		allowBarrier bool
	}{
		{
			name: "ordinary plpython udf",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION add_one(value integer) RETURNS integer AS $$ return value + 1 $$ LANGUAGE plpython3u;"),
		},
		{
			name: "same command-style name benign body",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ return value.upper() $$ LANGUAGE plpython3u;"),
		},
		{
			name: "comment-only command sink",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ # import os; os.system(value) $$ LANGUAGE plpython3u;"),
		},
		{
			name: "string-only command sink",
			input: postgreSQLUDFInput(t, "production",
				`CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ note = 'import os and os.system('; return note $$ LANGUAGE plpython3u;`),
		},
		{
			name: "docstring-only command sink",
			input: postgreSQLUDFInput(t, "production",
				`CREATE FUNCTION exec_cmd(value text) RETURNS text AS $$ """import os; os.system(value)"""; return value $$ LANGUAGE plpython3u;`),
		},
		{
			name: "ordinary c udf",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION calculate_tax(integer) RETURNS integer AS '/usr/lib/postgresql/tax.so', 'calculate_tax' LANGUAGE C;"),
		},
		{
			name: "command-style c udf arbitrary library",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION exec_cmd(text) RETURNS text AS '/usr/lib/postgresql/extensions/exec_cmd.so', 'exec_cmd' LANGUAGE C;"),
		},
		{
			name: "sys exec c udf wrong library path",
			input: postgreSQLUDFInput(t, "production",
				"CREATE FUNCTION sys_exec(text) RETURNS text AS '/tmp/sys_exec.so', 'sys_exec' LANGUAGE C;"),
		},
		{
			name: "plpgsql lookalike is not a proven process sink",
			input: postgreSQLUDFInput(t, "production",
				"CREATE OR REPLACE FUNCTION cmd_exec(text) RETURNS text AS $$ BEGIN PERFORM system($1); RETURN 'done'; END; $$ LANGUAGE plpgsql;"),
			allowBarrier: true,
		},
		{
			name: "concatenated dynamic sql",
			input: postgreSQLUDFInput(t, "production",
				"CREATE OR REPLACE FUNCTION shell_exec(cmd text) RETURNS text AS $$ BEGIN EXECUTE 'COPY (SELECT 1) TO PROGRAM ' || quote_literal(cmd); RETURN 'done'; END; $$ LANGUAGE plpgsql;"),
			allowBarrier: true,
		},
		{
			name: "create and invoke in one batch",
			input: postgreSQLUDFInput(t, "production",
				"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu; SELECT exec_cmd('id');"),
		},
		{
			name:  "dynamic invocation",
			input: postgreSQLUDFInput(t, "production", "SELECT exec_cmd(command_text);"),
		},
		{
			name:  "invocation batch",
			input: postgreSQLUDFInput(t, "production", "SELECT exec_cmd('id'); SELECT 1;"),
		},
		{
			name:  "function mismatch remains a distinct digest",
			input: postgreSQLUDFInput(t, "production", "SELECT another_function('id');"),
		},
		{
			name: "placeholder connection",
			input: Input{Tool: "sql_query", Args: mustSQLQueryArgs(t, "${DATABASE_URL}", "production",
				"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;")},
		},
		{
			name:  "unknown structured field",
			input: Input{Tool: "sql_query", Args: json.RawMessage(`{"connection":"postgresql://db.invalid/production","database":"production","query":"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;","timeout":30}`)},
		},
		{
			name:  "mysql ordinary library",
			input: Input{Tool: "execute_command", Args: json.RawMessage(`{"command":"mysql -u root -e \"CREATE FUNCTION soundex RETURNS STRING SONAME 'udf_example.so';\""}`)},
		},
		{
			name:  "mysql dynamic shell word",
			input: Input{Tool: "execute_command", Args: json.RawMessage(`{"command":"mysql -u $USER -e \"CREATE FUNCTION sys_exec RETURNS INT SONAME '/tmp/lib_mysqludf_sys.so';\""}`)},
		},
		{
			name:  "mysql multiple statements",
			input: Input{Tool: "execute_command", Args: json.RawMessage(`{"command":"mysql -u root -e \"CREATE FUNCTION sys_exec RETURNS INT SONAME '/tmp/lib_mysqludf_sys.so'; SELECT sys_exec('id');\""}`)},
		},
		{
			name:  "inert documentation text",
			input: Input{Tool: "execute_command", Args: json.RawMessage(`{"command":"printf '%s' \"mysql -u root -e \\\"CREATE FUNCTION sys_exec RETURNS INT SONAME '/tmp/lib_mysqludf_sys.so';\\\"\""}`)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			operation, _, _, functionDigest, ok := ExactSQLCommandUDFOperation(facts)
			if test.allowBarrier {
				if !ok || operation != SQLCommandUDFBarrier || functionDigest == "" {
					t.Fatalf("exact replacement did not project a non-alerting lineage barrier: %+v",
						facts.SQLCommandUDFOperations)
				}
				return
			}
			if test.name == "function mismatch remains a distinct digest" {
				if !ok || operation != SQLCommandUDFInvoke || functionDigest == "" {
					t.Fatalf("static invocation should project as a nonmatching identity: %+v", facts.SQLCommandUDFOperations)
				}
				return
			}
			if ok || len(facts.SQLCommandUDFOperations) != 0 {
				t.Fatalf("hard negative projected UDF operation: %+v parse=%+v", facts.SQLCommandUDFOperations, facts.Parse)
			}
		})
	}
}

func TestSQLCommandUDFLineageBarriersUseExactConnectionAndFunction(t *testing.T) {
	create := Analyze(postgreSQLUDFInput(t, "production",
		"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;"))
	invoke := Analyze(postgreSQLUDFInput(t, "production", "SELECT exec_cmd('id');"))
	replace := Analyze(postgreSQLUDFInput(t, "production",
		"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ return $1 $$ LANGUAGE plpgsql;"))
	drop := Analyze(postgreSQLUDFInput(t, "production", "DROP FUNCTION IF EXISTS exec_cmd(text);"))
	var lineage string
	for index, test := range []struct {
		facts Facts
		op    SQLCommandUDFOperation
	}{
		{create, SQLCommandUDFCreate},
		{invoke, SQLCommandUDFInvoke},
		{replace, SQLCommandUDFBarrier},
		{drop, SQLCommandUDFBarrier},
	} {
		operation, digest, ok := ExactSQLCommandUDFLineageOperation(test.facts)
		if !ok || operation != test.op || digest == "" {
			t.Fatalf("case %d operation=%q digest=%q ok=%t facts=%+v",
				index, operation, digest, ok, test.facts.SQLCommandUDFOperations)
		}
		if lineage == "" {
			lineage = digest
		} else if lineage != digest {
			t.Fatalf("same connection/function produced different lineage: %q != %q",
				lineage, digest)
		}
	}
	different := Analyze(postgreSQLUDFInput(t, "production", "DROP FUNCTION other_exec(text);"))
	_, differentDigest, ok := ExactSQLCommandUDFLineageOperation(different)
	if !ok || differentDigest == lineage {
		t.Fatalf("different function lineage=%q shared=%q ok=%t", differentDigest, lineage, ok)
	}
}

func TestSQLCommandUDFConnectionAndFunctionMismatchesRemainDistinct(t *testing.T) {
	create := Analyze(postgreSQLUDFInput(t, "production",
		"CREATE OR REPLACE FUNCTION exec_cmd(text) RETURNS text AS $$ import os; return os.popen($1).read() $$ LANGUAGE plpythonu;"))
	differentDatabase := Analyze(postgreSQLUDFInput(t, "staging", "SELECT exec_cmd('id');"))
	differentFunction := Analyze(postgreSQLUDFInput(t, "production", "SELECT other_exec('id');"))
	_, _, createConnection, createFunction, _ := ExactSQLCommandUDFOperation(create)
	_, _, databaseConnection, databaseFunction, _ := ExactSQLCommandUDFOperation(differentDatabase)
	_, _, functionConnection, functionFunction, _ := ExactSQLCommandUDFOperation(differentFunction)
	if createConnection == databaseConnection || createFunction != databaseFunction ||
		createConnection != functionConnection || createFunction == functionFunction {
		t.Fatalf("database_match=%t database_function_match=%t function_connection_match=%t function_match=%t",
			createConnection == databaseConnection,
			createFunction == databaseFunction,
			createConnection == functionConnection,
			createFunction == functionFunction,
		)
	}
}

func postgreSQLUDFInput(t *testing.T, database, query string) Input {
	t.Helper()
	return Input{
		Tool: "sql_query",
		Args: mustSQLQueryArgs(
			t,
			"postgresql://fixture:fixture-password@db.invalid:5432/"+database,
			database,
			query,
		),
	}
}

func assertSQLCommandUDFFactsValueFree(t *testing.T, forbidden ...any) {
	t.Helper()
	var facts []Facts
	var stringsToReject []string
	for _, value := range forbidden {
		switch value := value.(type) {
		case Facts:
			facts = append(facts, value)
		case string:
			stringsToReject = append(stringsToReject, value)
		}
	}
	for _, factSet := range facts {
		// Generic command facts intentionally retain static argv. This assertion
		// scopes the value-free contract to the private UDF projection itself.
		factSet.Commands = nil
		factSet.Paths = nil
		factSet.Network = nil
		factSet.DataFlows = nil
		encoded, err := json.Marshal(factSet)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range stringsToReject {
			if bytes.Contains(encoded, []byte(value)) {
				t.Fatalf("content-bearing value %q survived projection: %s", value, encoded)
			}
		}
	}
}
