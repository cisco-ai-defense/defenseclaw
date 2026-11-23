// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// sqlCLIReadInputs is the inline SQL of each SQL client command line of a
// shell call that the server-side readers (COPY ... PROGRAM, the sensitive
// server file read) judge: every command of the call, not only a call of one
// command; each -c of a psql call; and mysql and mariadb as well as psql
// (each reader keeps its own engines) (DET111 T20 review P3-3). Each
// statement of a query is its own input (sqlStatementCandidates), a
// statement in a transaction that is rolled back too: what a server-side
// function or program does is done when the transaction is undone. Each
// input is judged by the same exact readers as one psql -c alone, so the
// wider surface only raises. The commands are the analysis's own, already
// within its bounds; caps holds the statement cap of a query read only in
// part.
func sqlCLIReadInputs(input Input, facts Facts) (inputs []exactSQLMutationInput, caps bounded.CapSet) {
	if input.Tool == "sql_query" || !facts.Authoritative() {
		return nil, caps
	}
	for _, command := range facts.Commands {
		for _, query := range exactSQLCLICommandInputs(command, true) {
			statements, capped := sqlStatementCandidates(query)
			if capped {
				caps = caps.Union(bounded.Of(bounded.Items))
			}
			inputs = append(inputs, statements...)
		}
	}
	return inputs, caps
}

// sqlStatementCandidates is the inline query of a SQL client read statement
// by statement (DET111 ruling B on GAP-1926): a query of one statement is
// candidate as it is; a query of more is one candidate per statement, so a
// statement is judged as its bare form, never above it, wherever it stands
// in the query (after a SELECT, inside BEGIN ... COMMIT). A structured query
// keeps its own grammar. rolledBack marks a statement inside a transaction
// the query undoes: one that ROLLBACK ends, or that the query leaves open
// (the client's session end rolls it back), unless a statement the engine
// commits implicitly ends it first (MySQL and Snowflake commit before DDL
// and before a nested BEGIN). capped reports statements past
// maxSQLASTStatements, which are not read.
func sqlStatementCandidates(candidate exactSQLMutationInput) (candidates []exactSQLMutationInput, capped bool) {
	if candidate.source == SQLMutationQueryStructured {
		return []exactSQLMutationInput{candidate}, false
	}
	statements, capped := sqlStatements(candidate.engine, candidate.query)
	if len(statements) <= 1 && !capped {
		return []exactSQLMutationInput{candidate}, false
	}
	candidates = make([]exactSQLMutationInput, len(statements))
	open := -1 // index of the first statement of the open transaction
	undo := func(end int) {
		for i := open; i < end; i++ {
			candidates[i].rolledBack = true
		}
		open = -1
	}
	for i, statement := range statements {
		candidates[i] = candidate
		candidates[i].query = statement.text
		switch control := sqlTransactionControl(candidate.engine, statement.words); {
		case control == sqlTransactionBegin && open < 0:
			open = i
		case control == sqlTransactionBegin && sqlImplicitCommit(candidate.engine, statement.words):
			open = i
		case control == sqlTransactionCommit:
			open = -1
		case control == sqlTransactionRollback && open >= 0:
			undo(i)
		case open >= 0 && sqlImplicitCommit(candidate.engine, statement.words):
			open = -1
		}
	}
	if open >= 0 && !capped {
		undo(len(statements))
	}
	return candidates, capped
}

type sqlTransactionStatement uint8

const (
	sqlTransactionNone sqlTransactionStatement = iota
	sqlTransactionBegin
	sqlTransactionCommit
	sqlTransactionRollback
)

// sqlTransactionControl reads a statement that begins, commits or rolls
// back a transaction. ROLLBACK TO (a savepoint) ends no transaction. On SQL
// Server a bare BEGIN opens a block, not a transaction.
func sqlTransactionControl(engine string, words []string) sqlTransactionStatement {
	if len(words) == 0 {
		return sqlTransactionNone
	}
	next := ""
	if len(words) > 1 {
		next = words[1]
	}
	switch words[0] {
	case "BEGIN":
		if engine == "sqlserver" && next != "TRAN" && next != "TRANSACTION" && next != "DISTRIBUTED" {
			return sqlTransactionNone
		}
		return sqlTransactionBegin
	case "START":
		if next == "TRANSACTION" {
			return sqlTransactionBegin
		}
	case "COMMIT", "END":
		if words[0] == "END" && engine != "postgresql" {
			return sqlTransactionNone
		}
		return sqlTransactionCommit
	case "ROLLBACK", "ABORT":
		if words[0] == "ABORT" && engine != "postgresql" ||
			slices.Contains(words[1:], "TO") {
			return sqlTransactionNone
		}
		return sqlTransactionRollback
	}
	return sqlTransactionNone
}

// sqlImplicitCommit reports a statement before which engine commits the
// open transaction: DDL and a nested BEGIN on MySQL and Snowflake, whose DDL
// is not transactional (a DROP TABLE inside BEGIN ... ROLLBACK is done).
func sqlImplicitCommit(engine string, words []string) bool {
	if engine != "mysql" && engine != "snowflake" || len(words) == 0 {
		return false
	}
	switch words[0] {
	case "BEGIN", "START", "DROP", "TRUNCATE", "CREATE", "ALTER", "RENAME", "GRANT", "REVOKE":
		return true
	}
	return false
}
