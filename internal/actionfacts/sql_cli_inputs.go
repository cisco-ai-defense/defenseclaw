// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

// sqlCLIReadInputs is the inline SQL of each SQL client command line of a
// shell call that the server-side readers (COPY ... PROGRAM, the sensitive
// server file read) judge: every command of the call, not only a call of one
// command; each -c of a psql call; and mysql and mariadb as well as psql
// (each reader keeps its own engines) (DET111 T20 review P3-3). Each input
// is judged by the same exact readers as one psql -c alone, so the wider
// surface only raises. The commands are the analysis's own, already within
// its bounds.
func sqlCLIReadInputs(input Input, facts Facts) []exactSQLMutationInput {
	if input.Tool == "sql_query" || !facts.Authoritative() {
		return nil
	}
	var inputs []exactSQLMutationInput
	for _, command := range facts.Commands {
		inputs = append(inputs, exactSQLCLICommandInputs(command, true)...)
	}
	return inputs
}
