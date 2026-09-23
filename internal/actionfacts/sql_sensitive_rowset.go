// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

const sensitiveSQLRowsetIdentityDomain = "defenseclaw/actionfacts/sensitive-sql-rowset-resource/v1"

// ExactSensitiveSQLRowsetReads returns validated value-free copies of exact
// rowset-read facts. It never returns SQL, resource identities, or row values.
func ExactSensitiveSQLRowsetReads(facts Facts) []SensitiveSQLRowsetReadFact {
	result := make([]SensitiveSQLRowsetReadFact, 0, len(facts.SensitiveSQLRowsetReads))
	for _, fact := range facts.SensitiveSQLRowsetReads {
		if !validSensitiveSQLRowsetReadFact(fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validSensitiveSQLRowsetReadFact(fact SensitiveSQLRowsetReadFact) bool {
	if !fact.Exact || !validPrivateDigest(fact.DatabaseIdentityDigest) ||
		!validSQLMutationDigest(fact.TableIdentityDigest) {
		return false
	}
	switch fact.TableClass {
	case SensitiveSQLTableCredentials, SensitiveSQLTableOAuthTokens,
		SensitiveSQLTableEmployees:
		return true
	default:
		return false
	}
}

func projectSensitiveSQLRowsetReads(input Input) []SensitiveSQLRowsetReadFact {
	if input.Command != "" || len(input.Argv) != 0 ||
		!validTrustedToolResourceIdentity(input.ToolResourceIdentity) {
		return nil
	}
	query, ok := exactSensitiveSQLInputQuery(input)
	if !ok {
		return nil
	}
	tableClass, ok := exactSensitiveSQLSelect(query)
	if !ok {
		return nil
	}
	fact := SensitiveSQLRowsetReadFact{
		TableClass: tableClass,
		DatabaseIdentityDigest: framedPrivateDigest(
			sensitiveSQLRowsetIdentityDomain,
			input.ToolResourceIdentity,
		),
		TableIdentityDigest: SensitiveSQLTableIdentityDigest(tableClass),
		Exact:               true,
	}
	if !validSensitiveSQLRowsetReadFact(fact) {
		return nil
	}
	return []SensitiveSQLRowsetReadFact{fact}
}

// SensitiveSQLTableIdentityDigest returns the same opaque table identity used
// by exact SQLite mutation facts. Only the closed sensitive-table vocabulary
// is accepted; arbitrary table names cannot enter this helper.
func SensitiveSQLTableIdentityDigest(table SensitiveSQLTableClass) string {
	switch table {
	case SensitiveSQLTableCredentials, SensitiveSQLTableOAuthTokens,
		SensitiveSQLTableEmployees:
		return sqlMutationDigest(
			sqlMutationObjectDigestDomain,
			"sqlite",
			string(table),
		)
	default:
		return ""
	}
}

func exactSensitiveSQLInputQuery(input Input) (string, bool) {
	switch input.Tool {
	case "read_query":
		return exactSensitiveSQLReadQueryArgs(input.Args)
	case "sql_query":
		_, _, query, ok := exactSQLQueryInput(input)
		return query, ok
	default:
		return "", false
	}
}

func exactSensitiveSQLReadQueryArgs(raw json.RawMessage) (string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 1 {
		return "", false
	}
	query, ok := object["query"].(string)
	if !ok || !exactSQLScalar(query, maxCommandBytes) {
		return "", false
	}
	return query, true
}

func exactSensitiveSQLSelect(query string) (SensitiveSQLTableClass, bool) {
	if query == "" || len(query) > maxCommandBytes || !utf8.ValidString(query) ||
		strings.TrimSpace(query) != query || containsUnresolvedSQLRowsetText(query) {
		return "", false
	}
	tokens, ok := tokenizeSensitiveSQLSelect(query)
	if !ok || len(tokens) < 4 || !strings.EqualFold(tokens[0], "select") {
		return "", false
	}
	index := 1
	columns := make([]string, 0, 8)
	expectColumn := true
	for index < len(tokens) && !strings.EqualFold(tokens[index], "from") {
		token := tokens[index]
		if expectColumn {
			if token != "*" && !exactSQLRowsetIdentifier(token) {
				return "", false
			}
			columns = append(columns, strings.ToLower(token))
			if len(columns) > maxArgvItems {
				return "", false
			}
			expectColumn = false
		} else {
			if token != "," {
				return "", false
			}
			expectColumn = true
		}
		index++
	}
	if len(columns) == 0 || expectColumn || index >= len(tokens) ||
		!strings.EqualFold(tokens[index], "from") {
		return "", false
	}
	if len(columns) > 1 {
		for _, column := range columns {
			if column == "*" {
				return "", false
			}
		}
	}
	index++
	if index >= len(tokens) || !exactSQLRowsetIdentifier(tokens[index]) {
		return "", false
	}
	tableClass := SensitiveSQLTableClass(strings.ToLower(tokens[index]))
	index++
	if index < len(tokens) && strings.EqualFold(tokens[index], "order") {
		index++
		if index+1 >= len(tokens) || !strings.EqualFold(tokens[index], "by") ||
			!exactSQLRowsetIdentifier(tokens[index+1]) {
			return "", false
		}
		index += 2
		if index < len(tokens) && (strings.EqualFold(tokens[index], "asc") ||
			strings.EqualFold(tokens[index], "desc")) {
			index++
		}
	}
	if index < len(tokens) && strings.EqualFold(tokens[index], "limit") {
		index++
		if index >= len(tokens) || !canonicalSensitiveSQLLimit(tokens[index]) {
			return "", false
		}
		index++
	}
	if index != len(tokens) || !selectedSensitiveSQLField(tableClass, columns) {
		return "", false
	}
	return tableClass, true
}

func tokenizeSensitiveSQLSelect(query string) ([]string, bool) {
	if strings.HasSuffix(query, ";") {
		query = strings.TrimSpace(strings.TrimSuffix(query, ";"))
	}
	if query == "" || strings.ContainsRune(query, ';') {
		return nil, false
	}
	tokens := make([]string, 0, 16)
	for index := 0; index < len(query); {
		character := query[index]
		switch {
		case character == ' ' || character == '\t' || character == '\n' || character == '\r':
			index++
		case character == ',' || character == '*':
			tokens = append(tokens, string(character))
			index++
		case character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' || character == '_':
			start := index
			index++
			for index < len(query) {
				character = query[index]
				if !(character >= 'A' && character <= 'Z' ||
					character >= 'a' && character <= 'z' ||
					character >= '0' && character <= '9' || character == '_') {
					break
				}
				index++
			}
			tokens = append(tokens, query[start:index])
		case character >= '0' && character <= '9':
			start := index
			for index < len(query) && query[index] >= '0' && query[index] <= '9' {
				index++
			}
			tokens = append(tokens, query[start:index])
		default:
			return nil, false
		}
		if len(tokens) > maxArgvItems*2+12 {
			return nil, false
		}
	}
	return tokens, len(tokens) > 0
}

func exactSQLRowsetIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if index == 0 {
			if !(character >= 'A' && character <= 'Z' ||
				character >= 'a' && character <= 'z' || character == '_') {
				return false
			}
		} else if !(character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func selectedSensitiveSQLField(table SensitiveSQLTableClass, columns []string) bool {
	for _, column := range columns {
		if column == "*" {
			return true
		}
		switch table {
		case SensitiveSQLTableCredentials:
			if column == "password" {
				return true
			}
		case SensitiveSQLTableOAuthTokens:
			if column == "access_token" || column == "refresh_token" {
				return true
			}
		case SensitiveSQLTableEmployees:
			if column == "ssn" {
				return true
			}
		}
	}
	return false
}

func canonicalSensitiveSQLLimit(value string) bool {
	if value == "" || len(value) > 7 || len(value) > 1 && value[0] == '0' {
		return false
	}
	limit, err := strconv.ParseUint(value, 10, 32)
	return err == nil && limit > 0 && limit <= 1_000_000
}

func containsUnresolvedSQLRowsetText(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(value, "${") || strings.Contains(value, "#{") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "<%") || strings.Contains(value, "%>") ||
		strings.Contains(value, "--") || strings.Contains(value, "/*") ||
		strings.Contains(value, "*/") || strings.Contains(lower, " your_")
}

func validateTrustedToolResourceIdentity(value string) IssueCode {
	if value == "" {
		return ""
	}
	if !validTrustedToolResourceIdentity(value) {
		if len(value) > maxScalarBytes {
			return IssueInputLimit
		}
		return IssueInvalidSyntax
	}
	return ""
}

func validTrustedToolResourceIdentity(value string) bool {
	return exactSQLScalar(value, maxScalarBytes) &&
		!unresolvedSQLConnectionIdentity(value) && utf8.ValidString(value)
}
