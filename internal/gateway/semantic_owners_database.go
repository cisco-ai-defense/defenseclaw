// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

const semanticPostgreSQLCopyProgramExpression = `f.tool == 'sql_query'`

const semanticSQLSensitiveServerFileReadExpression = `f.tool == 'sql_query'`

const semanticSQLCommandUDFCreateExpression = `f.tool in ['sql_query', 'execute_command']`

const semanticSQLServerXPCommandShellExpression = `f.tool == 'sql_query'`

const semanticSQLDestructiveMutationExpression = `f.tool == 'sql_query' || f.commands.exists(c, c.argv_complete && c.program in ['psql', 'mysql', 'mariadb', 'sqlcmd'])`

const semanticHTTPSQLInjectionExpression = `f.tool == 'http_request'`

const semanticSQLiteClientShellEscapeExpression = `f.commands.exists(c, c.argv_complete && c.program == 'sqlite3')`

const semanticMySQLClientShellEscapeExpression = `f.commands.exists(c, c.argv_complete && c.program in ['mysql', 'mariadb'])`

var semanticDatabaseOwners = map[string]semanticOwner{
	"attack.http_sql_injection": {
		prerequisite:     httpSQLInjectionPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// The recognizer proves executable SQL-injection grammar in a closed
		// request schema, but does not prove that the target is unauthorized.
		alertOnly: true,
	},
	"impact.sql_destructive_mutation": {
		prerequisite:     sqlDestructiveMutationPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Exact destructive SQL remains dual-use for migrations, fixture reset,
		// and authorized administration. The standard policies therefore alert;
		// an explicitly enabled database-protection pack may enforce it.
		alertOnly: true,
	},
	"exec.postgresql_copy_program": {
		prerequisite:     postgreSQLCopyProgramPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// COPY ... PROGRAM is dual-use administrative functionality. The
		// exact operation is retained as a HIGH local detection, but cannot
		// become a universal synchronous block without protected-database
		// policy context that is not currently present in ActionFacts.
		alertOnly: true,
	},
	"secrets.sql_sensitive_server_file_read": {
		prerequisite:     sqlSensitiveServerFileReadPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// The exact structured statement proves a database server read from a
		// closed sensitive-path class. It remains alert-only because authorized
		// database administration and recovery are possible without protected-
		// database policy context.
		alertOnly: true,
	},
	"exec.sql_command_udf_create": {
		prerequisite:     sqlCommandUDFCreatePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Creating a UDF whose body or shared-library identity proves a process
		// execution sink is a high-confidence local signal. It remains alert-
		// only because database extension installation is dual-use and this
		// atomic event lacks protected-database policy context. A later bounded
		// same-function invocation may strengthen the proof after success.
		alertOnly: true,
	},
	"exec.sqlserver_xp_cmdshell_invoke": {
		prerequisite:     sqlServerXPCommandShellInvokePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// A literal xp_cmdshell invocation proves server-side OS command
		// execution, but can still be authorized administration. Keep the exact
		// atomic signal alert-only; the bounded enable-then-invoke chain and
		// protected-database policy can add stronger context independently.
		alertOnly: true,
	},
	"exec.sqlserver_xp_cmdshell_enable": {
		prerequisite:     sqlServerXPCommandShellEnablePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Enabling xp_cmdshell is a high-signal increase in database execution
		// capability, but can be authorized administration. Keep the atomic
		// operation alert-only; exact enable-then-invoke lineage can strengthen it.
		alertOnly: true,
	},
	"exec.sqlite_client_shell_escape": {
		prerequisite:     sqlClientShellEscapePrerequisite(actionfacts.SQLClientShellEscapeSQLite),
		suppressFallback: authoritativeSemanticSafeNegative,
		alertOnly:        true,
	},
	"exec.mysql_client_shell_escape": {
		prerequisite:     sqlClientShellEscapePrerequisite(actionfacts.SQLClientShellEscapeMySQL),
		suppressFallback: authoritativeSemanticSafeNegative,
		alertOnly:        true,
	},
}

func sqlClientShellEscapePrerequisite(
	client actionfacts.SQLClientShellEscapeClient,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, fact := range actionfacts.ExactSQLClientShellEscapes(facts) {
			if fact.Client == client {
				return true
			}
		}
		return false
	}
}

func sqlDestructiveMutationPrerequisite(facts actionfacts.Facts) bool {
	return len(actionfacts.ExactSQLMutations(facts)) != 0
}

func httpSQLInjectionPrerequisite(facts actionfacts.Facts) bool {
	return len(actionfacts.ExactHTTPSQLInjections(facts)) != 0
}

func postgreSQLCopyProgramPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactPostgreSQLCopyProgram(facts)
	return ok
}

func sqlSensitiveServerFileReadPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactSQLSensitiveServerFileRead(facts)
	return ok
}

func sqlCommandUDFCreatePrerequisite(facts actionfacts.Facts) bool {
	operation, _, _, _, ok := actionfacts.ExactSQLCommandUDFOperation(facts)
	return ok && operation == actionfacts.SQLCommandUDFCreate
}

func sqlServerXPCommandShellInvokePrerequisite(facts actionfacts.Facts) bool {
	operation, _, ok := actionfacts.ExactSQLServerCommandExecution(facts)
	return ok && operation == actionfacts.SQLServerXPCommandShellInvoke
}

func sqlServerXPCommandShellEnablePrerequisite(facts actionfacts.Facts) bool {
	operation, _, ok := actionfacts.ExactSQLServerCommandExecution(facts)
	return ok && operation == actionfacts.SQLServerXPCommandShellEnable
}
