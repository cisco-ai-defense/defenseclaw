// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"
)

type sqlDirectEgressTokenKind uint8

const (
	sqlDirectEgressIdentifier sqlDirectEgressTokenKind = iota + 1
	sqlDirectEgressNumber
	sqlDirectEgressString
	sqlDirectEgressComma
	sqlDirectEgressOperator
)

type sqlDirectEgressToken struct {
	kind  sqlDirectEgressTokenKind
	value string
}

// ExactSQLDirectExternalEgress reports whether Facts contains exactly one
// validated direct SQL credential-to-external-result proof.
func ExactSQLDirectExternalEgress(facts Facts) bool {
	return len(facts.SQLDirectExternalEgresses) == 1 &&
		facts.SQLDirectExternalEgresses[0].Exact
}

func projectSQLDirectExternalEgresses(input Input) []SQLDirectExternalEgressFact {
	if _, ok := exactSQLDirectExternalEgressInput(input); !ok {
		return nil
	}
	return []SQLDirectExternalEgressFact{{Exact: true}}
}

func exactSQLDirectExternalEgressInput(input Input) (SQLDirectExternalEgressFact, bool) {
	if input.Tool != "db.query" || input.Command != "" || len(input.Argv) != 0 ||
		!validTrustedToolResourceIdentity(input.ToolResourceIdentity) {
		return SQLDirectExternalEgressFact{}, false
	}
	if _, _, ok := exactSQLDirectExternalEgressArgs(input.Args); !ok {
		return SQLDirectExternalEgressFact{}, false
	}
	return SQLDirectExternalEgressFact{Exact: true}, true
}

func exactSQLDirectExternalEgressArgs(raw json.RawMessage) (string, string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 2 {
		return "", "", false
	}
	query, queryOK := object["sql"].(string)
	destination, destinationOK := object["output_url"].(string)
	if !queryOK || !destinationOK || !exactSQLCredentialSelect(query) ||
		!exactExternalSQLResultURL(destination) {
		return "", "", false
	}
	return query, destination, true
}

func exactSQLCredentialSelect(query string) bool {
	if query == "" || len(query) > maxCommandBytes || !utf8.ValidString(query) ||
		strings.TrimSpace(query) != query || containsUnresolvedSQLRowsetText(query) {
		return false
	}
	tokens, ok := tokenizeSQLDirectEgressSelect(query)
	if !ok || len(tokens) < 4 || !sqlDirectEgressKeyword(tokens[0], "select") {
		return false
	}

	index := 1
	selectedCredential := false
	expectColumn := true
	columns := 0
	for index < len(tokens) && !sqlDirectEgressKeyword(tokens[index], "from") {
		token := tokens[index]
		if expectColumn {
			if token.kind != sqlDirectEgressIdentifier {
				return false
			}
			columns++
			if columns > 32 {
				return false
			}
			selectedCredential = selectedCredential || highConfidenceSQLCredentialField(token.value)
			expectColumn = false
		} else {
			if token.kind != sqlDirectEgressComma {
				return false
			}
			expectColumn = true
		}
		index++
	}
	if columns == 0 || expectColumn || !selectedCredential || index >= len(tokens) ||
		!sqlDirectEgressKeyword(tokens[index], "from") {
		return false
	}
	index++
	if index >= len(tokens) || tokens[index].kind != sqlDirectEgressIdentifier {
		return false
	}
	index++

	if index < len(tokens) && sqlDirectEgressKeyword(tokens[index], "where") {
		index++
		var ok bool
		index, ok = consumeSQLDirectEgressWhere(tokens, index)
		if !ok {
			return false
		}
	}
	if index < len(tokens) && sqlDirectEgressKeyword(tokens[index], "order") {
		if index+2 >= len(tokens) || !sqlDirectEgressKeyword(tokens[index+1], "by") ||
			tokens[index+2].kind != sqlDirectEgressIdentifier {
			return false
		}
		index += 3
		if index < len(tokens) && (sqlDirectEgressKeyword(tokens[index], "asc") ||
			sqlDirectEgressKeyword(tokens[index], "desc")) {
			index++
		}
	}
	if index < len(tokens) && sqlDirectEgressKeyword(tokens[index], "limit") {
		if index+1 >= len(tokens) || tokens[index+1].kind != sqlDirectEgressNumber ||
			!canonicalSensitiveSQLLimit(tokens[index+1].value) {
			return false
		}
		index += 2
	}
	return index == len(tokens)
}

func consumeSQLDirectEgressWhere(tokens []sqlDirectEgressToken, index int) (int, bool) {
	predicates := 0
	for {
		if index+2 >= len(tokens) || tokens[index].kind != sqlDirectEgressIdentifier ||
			tokens[index+1].kind != sqlDirectEgressOperator ||
			(tokens[index+2].kind != sqlDirectEgressString &&
				tokens[index+2].kind != sqlDirectEgressNumber) {
			return index, false
		}
		predicates++
		if predicates > 8 {
			return index, false
		}
		index += 3
		if index >= len(tokens) || sqlDirectEgressKeyword(tokens[index], "order") ||
			sqlDirectEgressKeyword(tokens[index], "limit") {
			return index, true
		}
		if !sqlDirectEgressKeyword(tokens[index], "and") {
			return index, false
		}
		index++
	}
}

func tokenizeSQLDirectEgressSelect(query string) ([]sqlDirectEgressToken, bool) {
	if strings.HasSuffix(query, ";") {
		query = strings.TrimSuffix(query, ";")
	}
	if query == "" || strings.ContainsRune(query, ';') {
		return nil, false
	}
	tokens := make([]sqlDirectEgressToken, 0, 24)
	for index := 0; index < len(query); {
		character := query[index]
		switch {
		case character == ' ' || character == '\t' || character == '\n' || character == '\r':
			index++
		case character == ',':
			tokens = append(tokens, sqlDirectEgressToken{kind: sqlDirectEgressComma, value: ","})
			index++
		case character == '=':
			tokens = append(tokens, sqlDirectEgressToken{kind: sqlDirectEgressOperator, value: "="})
			index++
		case character == '!' && index+1 < len(query) && query[index+1] == '=':
			tokens = append(tokens, sqlDirectEgressToken{kind: sqlDirectEgressOperator, value: "!="})
			index += 2
		case character == '<' && index+1 < len(query) && query[index+1] == '>':
			tokens = append(tokens, sqlDirectEgressToken{kind: sqlDirectEgressOperator, value: "<>"})
			index += 2
		case character == '\'':
			index++
			closed := false
			for index < len(query) {
				if query[index] != '\'' {
					index++
					continue
				}
				if index+1 < len(query) && query[index+1] == '\'' {
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				return nil, false
			}
			tokens = append(tokens, sqlDirectEgressToken{kind: sqlDirectEgressString})
		case asciiSQLIdentifierStart(character):
			start := index
			index++
			for index < len(query) && asciiSQLIdentifierContinue(query[index]) {
				index++
			}
			tokens = append(tokens, sqlDirectEgressToken{
				kind: sqlDirectEgressIdentifier, value: strings.ToLower(query[start:index]),
			})
		case character >= '0' && character <= '9':
			start := index
			for index < len(query) && query[index] >= '0' && query[index] <= '9' {
				index++
			}
			tokens = append(tokens, sqlDirectEgressToken{
				kind: sqlDirectEgressNumber, value: query[start:index],
			})
		default:
			return nil, false
		}
		if len(tokens) > 64 {
			return nil, false
		}
	}
	return tokens, len(tokens) != 0
}

func asciiSQLIdentifierStart(character byte) bool {
	return character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z' || character == '_'
}

func asciiSQLIdentifierContinue(character byte) bool {
	return asciiSQLIdentifierStart(character) || character >= '0' && character <= '9'
}

func sqlDirectEgressKeyword(token sqlDirectEgressToken, keyword string) bool {
	return token.kind == sqlDirectEgressIdentifier && token.value == keyword
}

func highConfidenceSQLCredentialField(field string) bool {
	switch strings.ToLower(field) {
	case "password", "password_hash", "passwd_hash", "api_key", "api_secret",
		"client_secret", "access_token", "refresh_token", "private_key",
		"secret", "secret_key", "credential", "credentials":
		return true
	default:
		return false
	}
}

func exactExternalSQLResultURL(raw string) bool {
	if raw == "" || len(raw) > maxScalarBytes || strings.TrimSpace(raw) != raw ||
		validateScalar(raw, maxScalarBytes) != "" || strings.ContainsAny(raw, "$`{}#") {
		return false
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Count(host, ".") == 0 ||
		host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".corp") ||
		strings.HasSuffix(host, ".private") || strings.HasSuffix(host, ".intranet") ||
		strings.HasSuffix(host, ".home") || strings.HasSuffix(host, ".svc") ||
		strings.HasSuffix(host, ".home.arpa") {
		if _, err := netip.ParseAddr(host); err != nil {
			return false
		}
	}
	normalized, scope, kind, _ := deriveNetworkTarget(host)
	if normalized == "" || kind != NetworkTargetSingleHost {
		return false
	}
	if address, err := netip.ParseAddr(normalized); err == nil {
		return scope == NetworkScopePublic && address.Zone() == ""
	}
	return scope == NetworkScopeUnknown
}
