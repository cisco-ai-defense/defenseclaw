// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

const sqlServerConnectionDigestDomain = "defenseclaw/actionfacts/sql-server-connection/v1"

var (
	sqlServerXPEnablePattern = regexp.MustCompile(
		`(?is)^\s*(?:exec(?:ute)?\s+)?(?:(?:master\.)?dbo\.)?sp_configure\s+N?'xp_cmdshell'\s*,\s*1\s*;?\s*(?:reconfigure(?:\s+with\s+override)?\s*;?\s*)?$`,
	)
	sqlServerXPAdvancedEnablePattern = regexp.MustCompile(
		`(?is)^\s*(?:exec(?:ute)?\s+)?(?:(?:master\.)?dbo\.)?sp_configure\s+N?'show advanced options'\s*,\s*1\s*;\s*reconfigure(?:\s+with\s+override)?\s*;\s*(?:exec(?:ute)?\s+)?(?:(?:master\.)?dbo\.)?sp_configure\s+N?'xp_cmdshell'\s*,\s*1\s*;?\s*(?:reconfigure(?:\s+with\s+override)?\s*;?\s*)?$`,
	)
	sqlServerXPDisablePattern = regexp.MustCompile(
		`(?is)^\s*(?:exec(?:ute)?\s+)?(?:(?:master\.)?dbo\.)?sp_configure\s+N?'xp_cmdshell'\s*,\s*0\s*;?\s*(?:reconfigure(?:\s+with\s+override)?\s*;?\s*)?$`,
	)
	sqlServerXPInvokePattern = regexp.MustCompile(
		`(?is)^\s*exec(?:ute)?\s+(?:(?:master\.)?dbo\.)?xp_cmdshell\s+N?'(?:''|[^'])*[^'\s](?:''|[^'])*'\s*(?:,\s*no_output)?\s*;?\s*$`,
	)
)

// ExactSQLServerCommandExecution returns one exact, value-free SQL Server
// command-execution operation. It never returns SQL text or connection data.
func ExactSQLServerCommandExecution(
	facts Facts,
) (SQLServerCommandOperation, string, bool) {
	if len(facts.SQLServerCommandExecutions) != 1 {
		return "", "", false
	}
	fact := facts.SQLServerCommandExecutions[0]
	switch fact.Operation {
	case SQLServerXPCommandShellEnable, SQLServerXPCommandShellInvoke,
		SQLServerXPCommandShellDisable:
	default:
		return "", "", false
	}
	if len(fact.ConnectionIdentityDigest) != sha256.Size*2 ||
		fact.ConnectionIdentityDigest != strings.ToLower(fact.ConnectionIdentityDigest) {
		return "", "", false
	}
	if _, err := hex.DecodeString(fact.ConnectionIdentityDigest); err != nil {
		return "", "", false
	}
	return fact.Operation, fact.ConnectionIdentityDigest, true
}

func projectSQLServerCommandExecutions(input Input) []SQLServerCommandExecutionFact {
	connection, database, query, ok := exactSQLQueryInput(input)
	if !ok {
		return nil
	}
	operation := SQLServerCommandOperation("")
	switch {
	case sqlServerXPAdvancedEnablePattern.MatchString(query),
		sqlServerXPEnablePattern.MatchString(query):
		operation = SQLServerXPCommandShellEnable
	case sqlServerXPDisablePattern.MatchString(query):
		operation = SQLServerXPCommandShellDisable
	case sqlServerXPInvokePattern.MatchString(query):
		operation = SQLServerXPCommandShellInvoke
	default:
		return nil
	}
	digest := sqlServerConnectionIdentityDigest(connection, database)
	if digest == "" {
		return nil
	}
	return []SQLServerCommandExecutionFact{{
		Operation: operation, ConnectionIdentityDigest: digest,
	}}
}

func exactSQLQueryInput(input Input) (connection, database, query string, ok bool) {
	if input.Tool != "sql_query" || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) ||
		input.Command != "" || len(input.Argv) != 0 {
		return "", "", "", false
	}
	return exactSQLQueryArgs(input.Args)
}

func exactSQLQueryArgs(raw json.RawMessage) (connection, database, query string, ok bool) {
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes || !utf8.Valid(raw) {
		return "", "", "", false
	}
	if issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue != "" {
		return "", "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || (len(object) != 2 && len(object) != 3) {
		return "", "", "", false
	}
	connection, connectionOK := object["connection"].(string)
	query, queryOK := object["query"].(string)
	if !connectionOK || !queryOK || !exactSQLScalar(connection, maxScalarBytes) ||
		!exactSQLScalar(query, maxCommandBytes) || unresolvedSQLConnectionIdentity(connection) {
		return "", "", "", false
	}
	for key := range object {
		switch key {
		case "connection", "query":
		case "database":
			var databaseOK bool
			database, databaseOK = object[key].(string)
			if !databaseOK || !exactSQLScalar(database, maxScalarBytes) ||
				unresolvedSQLConnectionIdentity(database) {
				return "", "", "", false
			}
		default:
			return "", "", "", false
		}
	}
	return connection, database, query, true
}

func exactSQLScalar(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value &&
		strings.IndexByte(value, 0) < 0 && !strings.ContainsAny(value, "\r\n")
}

func unresolvedSQLConnectionIdentity(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(value, "${") || strings.Contains(value, "#{") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "<%") || strings.Contains(value, "%>") ||
		strings.Contains(lower, "<connection") || strings.Contains(lower, "<database") ||
		strings.Contains(lower, "your_connection") || strings.Contains(lower, "your_database")
}

func sqlServerConnectionIdentityDigest(connection, database string) string {
	return sqlConnectionIdentityDigest(
		sqlServerConnectionDigestDomain,
		connection,
		database,
	)
}

func sqlConnectionIdentityDigest(domain, connection, database string) string {
	if connection == "" {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{domain, connection, database} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
