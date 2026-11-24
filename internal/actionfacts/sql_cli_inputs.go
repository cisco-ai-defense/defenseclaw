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
// statement of a query is its own input (sqlSessionStatementCandidates), a
// statement in a transaction that is rolled back too: what a server-side
// function or program does is done when the transaction is undone. Each
// input is judged by the same exact readers as one psql -c alone, so the
// wider surface only raises. The commands are the analysis's own, already
// within its bounds; caps holds the statement cap of a query read only in
// part.
//
// unreadDanger reports a query with a statement past the cap that holds a
// modeled danger keyword and could not be read alone (sqlStatements): the
// cap then takes the truncated row, not the record (DET111 ruling on T23
// review P3-1).
func sqlCLIReadInputs(input Input, facts Facts) (inputs []exactSQLMutationInput, caps bounded.CapSet, unreadDanger bool) {
	if input.Tool == "sql_query" || !facts.Authoritative() {
		return nil, caps, false
	}
	for _, command := range facts.Commands {
		statements, capped, danger := sqlSessionStatementCandidates(exactSQLCLICommandInputs(command, true))
		if capped {
			caps = caps.Union(bounded.Of(bounded.Items))
		}
		unreadDanger = unreadDanger || danger
		inputs = append(inputs, statements...)
	}
	return inputs, caps, unreadDanger
}

// sqlSessionStatementCandidates reads one client session in input order. A
// transaction can span several -c options; only a proven full rollback, or a
// session ending with every statement known, makes its mutations unread.
// A statement past an input's cap with a danger keyword is a candidate too,
// read alone outside the transaction reading (GAP-2122); unreadDanger
// reports one past the danger budget (sqlStatements).
func sqlSessionStatementCandidates(inputs []exactSQLMutationInput) (candidates []exactSQLMutationInput, capped, unreadDanger bool) {
	if len(inputs) == 1 && inputs[0].source == SQLMutationQueryStructured {
		return []exactSQLMutationInput{inputs[0]}, false, false
	}
	var danger []exactSQLMutationInput // past-cap danger statements, read alone (GAP-2122)
	open := -1                         // index of the first statement of the open transaction
	tableLocked := false               // MySQL UNLOCK commits only locks acquired by LOCK TABLES.
	undo := func(end int) {
		for i := open; i < end; i++ {
			candidates[i].rolledBack = true
		}
		open = -1
	}
	for _, input := range inputs {
		statements, cut, past, unread := sqlStatements(input.engine, input.query)
		capped = capped || cut
		unreadDanger = unreadDanger || unread
		for _, statement := range past {
			extra := input
			extra.query = statement.text
			danger = append(danger, extra)
		}
		for _, statement := range statements {
			candidate := input
			if len(inputs) != 1 || len(statements) != 1 || cut {
				candidate.query = statement.text
			}
			i := len(candidates)
			candidates = append(candidates, candidate)
			control := sqlTransactionControl(input.engine, statement.words)
			implicit := sqlImplicitCommit(input.engine, statement.words)
			if input.engine == "mysql" && len(statement.words) > 1 {
				name, operand := statement.words[0], statement.words[1]
				if name == "UNLOCK" && (operand == "TABLE" || operand == "TABLES") {
					implicit = tableLocked
					tableLocked = false
				} else if name == "LOCK" && (operand == "TABLE" || operand == "TABLES") {
					tableLocked = true
				} else if control == sqlTransactionBegin {
					tableLocked = false
				}
			}
			switch {
			case control == sqlTransactionBegin && open < 0:
				open = i
			case control == sqlTransactionBegin && implicit:
				open = i
			case control == sqlTransactionCommit:
				open = -1
			case control == sqlTransactionRollback && open >= 0:
				undo(i)
			case open >= 0 && implicit:
				open = -1
			}
		}
	}
	if open >= 0 && !capped {
		undo(len(candidates))
	}
	// The statements past the cap with a danger keyword are judged as their
	// bare form too (GAP-2122: the unpadded cell); a transaction around
	// them is not read, so none is taken as rolled back.
	candidates = append(candidates, danger...)
	return candidates, capped, unreadDanger
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
			slices.Contains(words[1:], "TO") ||
			engine == "sqlserver" && len(words) > 2 && (next == "TRAN" || next == "TRANSACTION") {
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
	if engine == "snowflake" {
		switch words[0] {
		case "BEGIN", "START", "DROP", "TRUNCATE", "CREATE", "ALTER", "RENAME", "GRANT", "REVOKE":
			return true
		}
		return false
	}
	next := ""
	if len(words) > 1 {
		next = words[1]
	}
	switch words[0] {
	case "BEGIN", "DROP", "TRUNCATE", "CREATE", "ALTER", "RENAME", "GRANT", "REVOKE", "FLUSH":
		return true
	case "START":
		return next == "TRANSACTION" || next == "REPLICA" || next == "SLAVE"
	case "STOP":
		return next == "REPLICA" || next == "SLAVE"
	case "LOCK":
		return next == "TABLE" || next == "TABLES"
	case "ANALYZE", "CHECK", "OPTIMIZE", "REPAIR":
		return next == "TABLE"
	case "CACHE":
		return next == "INDEX"
	case "LOAD":
		return next == "INDEX"
	case "RESET":
		return next != "PERSIST"
	case "INSTALL", "UNINSTALL":
		return next == "PLUGIN" || next == "COMPONENT"
	case "SET":
		return next == "PASSWORD"
	}
	return false
}
