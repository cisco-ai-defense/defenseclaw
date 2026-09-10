// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

const semanticPostgreSQLCopyProgramExpression = `f.tool == 'sql_query'`

const semanticSQLCommandUDFCreateExpression = `f.tool in ['sql_query', 'execute_command']`

var semanticDatabaseOwners = map[string]semanticOwner{
	"exec.postgresql_copy_program": {
		prerequisite:     postgreSQLCopyProgramPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// COPY ... PROGRAM is dual-use administrative functionality. The
		// exact operation is retained as a HIGH local detection, but cannot
		// become a universal synchronous block without protected-database
		// policy context that is not currently present in ActionFacts.
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
}

func postgreSQLCopyProgramPrerequisite(facts actionfacts.Facts) bool {
	_, ok := actionfacts.ExactPostgreSQLCopyProgram(facts)
	return ok
}

func sqlCommandUDFCreatePrerequisite(facts actionfacts.Facts) bool {
	operation, _, _, _, ok := actionfacts.ExactSQLCommandUDFOperation(facts)
	return ok && operation == actionfacts.SQLCommandUDFCreate
}
