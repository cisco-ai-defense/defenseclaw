// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const postgreSQLConnectionDigestDomain = "defenseclaw/actionfacts/postgresql-copy-program-connection/v1"

// ExactPostgreSQLCopyProgram returns the opaque identity digest for one exact
// structured PostgreSQL COPY ... PROGRAM operation. It never returns SQL,
// program text, connection data, usernames, or passwords.
func ExactPostgreSQLCopyProgram(facts Facts) (string, bool) {
	if len(facts.PostgreSQLCopyPrograms) != 1 {
		return "", false
	}
	digest := facts.PostgreSQLCopyPrograms[0].ConnectionIdentityDigest
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return "", false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", false
	}
	return digest, true
}

func projectPostgreSQLCopyPrograms(input Input) []PostgreSQLCopyProgramFact {
	connection, database, query, ok := exactSQLQueryInput(input)
	if !ok || !exactPostgreSQLConnection(connection, database) ||
		!exactPostgreSQLCopyProgramQuery(query) {
		return nil
	}
	digest := sqlConnectionIdentityDigest(
		postgreSQLConnectionDigestDomain,
		connection,
		database,
	)
	if digest == "" {
		return nil
	}
	return []PostgreSQLCopyProgramFact{{ConnectionIdentityDigest: digest}}
}

func exactPostgreSQLConnection(connection, database string) bool {
	if !strings.HasPrefix(connection, "postgres://") &&
		!strings.HasPrefix(connection, "postgresql://") {
		return exactPostgreSQLKeywordConnection(connection, database)
	}
	parsed, err := url.Parse(connection)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Hostname() == "" || parsed.Path == "" || parsed.Path == "/" {
		return false
	}
	decodedDatabase, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil || !exactSQLScalar(decodedDatabase, maxScalarBytes) ||
		strings.Contains(decodedDatabase, "/") ||
		unresolvedSQLConnectionIdentity(decodedDatabase) {
		return false
	}
	if database != "" && database != decodedDatabase {
		return false
	}
	for key, values := range parsed.Query() {
		if strings.EqualFold(key, "database") || strings.EqualFold(key, "dbname") {
			return false
		}
		for _, value := range values {
			if unresolvedSQLConnectionIdentity(value) {
				return false
			}
		}
	}
	return true
}

// exactPostgreSQLKeywordConnection accepts the closed subset of libpq keyword
// connection strings observed in the source corpus. Quoted/escaped values and
// arbitrary libpq options remain unsupported so token boundaries and database
// identity cannot become ambiguous.
func exactPostgreSQLKeywordConnection(connection, database string) bool {
	fields := strings.Fields(connection)
	if len(fields) < 3 || len(fields) > 5 || strings.Join(fields, " ") != connection {
		return false
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || key == "" || value == "" || strings.Contains(value, "=") ||
			unresolvedSQLConnectionIdentity(value) {
			return false
		}
		switch key {
		case "host", "port", "dbname", "user", "password":
		default:
			return false
		}
		if _, duplicate := values[key]; duplicate {
			return false
		}
		values[key] = value
	}
	if !exactPostgreSQLHost(values["host"]) || values["user"] == "" {
		return false
	}
	port, err := strconv.Atoi(values["port"])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != values["port"] {
		return false
	}
	resolvedDatabase := values["dbname"]
	if resolvedDatabase == "" {
		resolvedDatabase = database
	}
	if !exactPostgreSQLIdentifierValue(resolvedDatabase) ||
		(database != "" && database != resolvedDatabase) {
		return false
	}
	return true
}

func exactPostgreSQLHost(host string) bool {
	if host == "" || len(host) > 253 || unresolvedSQLConnectionIdentity(host) {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Is4() || address.Is6()
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < '0' || character > '9') &&
				(character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') {
				return false
			}
		}
	}
	return true
}

func exactPostgreSQLIdentifierValue(value string) bool {
	if value == "" || len(value) > 128 || unresolvedSQLConnectionIdentity(value) {
		return false
	}
	for _, character := range value {
		if character != '_' && character != '-' && (character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func exactPostgreSQLCopyProgramQuery(query string) bool {
	parser := postgreSQLCopyParser{source: query}
	parser.space()
	if !parser.keyword("copy") || !parser.requiredSpace() {
		return false
	}
	querySource := false
	directionSeparated := false
	if parser.take('(') {
		querySource = true
		parser.space()
		if !parser.keyword("select") || !parser.requiredSpace() ||
			!parser.scalarLiteral() {
			return false
		}
		parser.space()
		if !parser.take(')') {
			return false
		}
	} else {
		if parser.keyword("only") {
			if !parser.requiredSpace() {
				return false
			}
		}
		if !parser.qualifiedIdentifier() {
			return false
		}
		separation := parser.space()
		if parser.take('(') {
			parser.space()
			if !parser.identifier() {
				return false
			}
			for {
				parser.space()
				if !parser.take(',') {
					break
				}
				parser.space()
				if !parser.identifier() {
					return false
				}
			}
			parser.space()
			if !parser.take(')') {
				return false
			}
		} else {
			if separation == 0 {
				return false
			}
			directionSeparated = true
		}
	}
	if !directionSeparated && !parser.requiredSpace() {
		return false
	}
	directionTO := parser.keyword("to")
	directionFROM := false
	if !directionTO {
		directionFROM = parser.keyword("from")
	}
	if (!directionTO && !directionFROM) || (querySource && directionFROM) ||
		!parser.requiredSpace() || !parser.keyword("program") ||
		!parser.requiredSpace() {
		return false
	}
	program, ok := parser.stringLiteral()
	if !ok || program == "" || len(program) > maxCommandBytes ||
		strings.TrimSpace(program) != program {
		return false
	}
	for _, r := range program {
		if r == 0 || r == '\r' || r == '\n' || unicode.IsControl(r) {
			return false
		}
	}
	parser.space()
	if parser.take(';') {
		parser.space()
	}
	return parser.done()
}

type postgreSQLCopyParser struct {
	source string
	index  int
}

func (p *postgreSQLCopyParser) done() bool { return p.index == len(p.source) }

func (p *postgreSQLCopyParser) take(value byte) bool {
	if p.index >= len(p.source) || p.source[p.index] != value {
		return false
	}
	p.index++
	return true
}

func (p *postgreSQLCopyParser) space() int {
	start := p.index
	for p.index < len(p.source) {
		switch p.source[p.index] {
		case ' ', '\t':
			p.index++
		default:
			return p.index - start
		}
	}
	return p.index - start
}

func (p *postgreSQLCopyParser) requiredSpace() bool { return p.space() > 0 }

func (p *postgreSQLCopyParser) keyword(value string) bool {
	end := p.index + len(value)
	if end > len(p.source) || !strings.EqualFold(p.source[p.index:end], value) {
		return false
	}
	if end < len(p.source) && postgreSQLIdentifierByte(p.source[end]) {
		return false
	}
	p.index = end
	return true
}

func (p *postgreSQLCopyParser) scalarLiteral() bool {
	if p.index < len(p.source) && p.source[p.index] == '\'' {
		_, ok := p.stringLiteral()
		return ok
	}
	start := p.index
	if p.index < len(p.source) && (p.source[p.index] == '+' || p.source[p.index] == '-') {
		p.index++
	}
	digitStart := p.index
	for p.index < len(p.source) && p.source[p.index] >= '0' && p.source[p.index] <= '9' {
		p.index++
	}
	if p.index == digitStart || p.index-start > 64 {
		p.index = start
		return false
	}
	return true
}

func (p *postgreSQLCopyParser) stringLiteral() (string, bool) {
	if !p.take('\'') {
		return "", false
	}
	var decoded strings.Builder
	for p.index < len(p.source) {
		if p.source[p.index] != '\'' {
			decoded.WriteByte(p.source[p.index])
			p.index++
			continue
		}
		p.index++
		if p.index < len(p.source) && p.source[p.index] == '\'' {
			decoded.WriteByte('\'')
			p.index++
			continue
		}
		return decoded.String(), true
	}
	return "", false
}

func (p *postgreSQLCopyParser) qualifiedIdentifier() bool {
	if !p.identifier() {
		return false
	}
	for components := 1; components < 3; components++ {
		if p.index >= len(p.source) || p.source[p.index] != '.' {
			return true
		}
		p.index++
		if !p.identifier() {
			return false
		}
	}
	return p.index >= len(p.source) || p.source[p.index] != '.'
}

func (p *postgreSQLCopyParser) identifier() bool {
	if p.index >= len(p.source) {
		return false
	}
	if p.source[p.index] == '"' {
		p.index++
		content := 0
		for p.index < len(p.source) {
			if p.source[p.index] != '"' {
				if p.source[p.index] < 0x20 || p.source[p.index] == 0x7f {
					return false
				}
				content++
				p.index++
				continue
			}
			p.index++
			if p.index < len(p.source) && p.source[p.index] == '"' {
				content++
				p.index++
				continue
			}
			return content > 0
		}
		return false
	}
	start := p.index
	if !postgreSQLIdentifierStart(p.source[p.index]) {
		return false
	}
	p.index++
	for p.index < len(p.source) && postgreSQLIdentifierByte(p.source[p.index]) {
		p.index++
	}
	return p.index-start <= 128
}

func postgreSQLIdentifierStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z'
}

func postgreSQLIdentifierByte(value byte) bool {
	return postgreSQLIdentifierStart(value) || value >= '0' && value <= '9' ||
		value == '$'
}
