// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
)

const (
	SQLSensitiveServerFileAccountDatabase = "posix_account_database"
	SQLSensitiveServerFileCredential      = "credential_file"
)

// ExactSQLSensitiveServerFileRead returns one exact, value-free server-side
// file-read projection. It never returns SQL, paths, connection data,
// usernames, or passwords.
func ExactSQLSensitiveServerFileRead(
	facts Facts,
) (SQLSensitiveServerFileReadFact, bool) {
	if len(facts.SQLSensitiveServerFileReads) != 1 {
		return SQLSensitiveServerFileReadFact{}, false
	}
	fact := facts.SQLSensitiveServerFileReads[0]
	if fact.DatabaseEngine != "mysql" && fact.DatabaseEngine != "postgresql" {
		return SQLSensitiveServerFileReadFact{}, false
	}
	if fact.PathClass != SQLSensitiveServerFileAccountDatabase &&
		fact.PathClass != SQLSensitiveServerFileCredential {
		return SQLSensitiveServerFileReadFact{}, false
	}
	return fact, true
}

func projectSQLSensitiveServerFileReads(input Input, sqlReads []exactSQLMutationInput) []SQLSensitiveServerFileReadFact {
	connection, database, query, structured := exactSQLQueryInput(input)
	if structured {
		switch {
		case exactMySQLConnection(connection, database):
			return sqlSensitiveServerFileReadFacts("mysql", query)
		case exactPostgreSQLConnection(connection, database):
			return sqlSensitiveServerFileReadFacts("postgresql", query)
		default:
			return nil
		}
	}
	// A psql, mysql or mariadb client in any command of a shell call, each
	// -c of psql (DET111 T20 review P3-3) and each statement of a query
	// (sqlCLIReadInputs).
	for _, candidate := range sqlReads {
		if candidate.engine != "postgresql" && candidate.engine != "mysql" {
			continue
		}
		if read := sqlSensitiveServerFileReadFacts(candidate.engine, candidate.query); read != nil {
			return read
		}
	}
	return nil
}

// sqlSensitiveServerFileReadFacts is the one fact of query reading a
// sensitive host file through a server-side file function of engine
// (mysql or postgresql), nil when it reads none.
func sqlSensitiveServerFileReadFacts(engine, query string) []SQLSensitiveServerFileReadFact {
	functions := []string{"pg_read_file", "pg_read_binary_file"}
	if engine == "mysql" {
		functions = []string{"load_file"}
	}
	filePath, ok := exactSQLSensitiveFileReadQuery(query, functions)
	if !ok {
		return nil
	}
	class := sqlSensitiveServerFileClass(filePath)
	if class == "" {
		return nil
	}
	return []SQLSensitiveServerFileReadFact{{
		DatabaseEngine: engine,
		PathClass:      class,
	}}
}

func exactMySQLConnection(connection, database string) bool {
	if strings.HasPrefix(connection, "mysql://") {
		return exactMySQLURIConnection(connection, database)
	}
	if strings.Contains(connection, "@") && !strings.Contains(connection, "=") {
		return exactMySQLBareConnection(connection, database)
	}
	return exactMySQLKeyValueConnection(connection, database)
}

// exactMySQLBareConnection accepts only the observed connector form
// user:password@host:port. It proves a MySQL endpoint without retaining any
// component. URI options, database paths, placeholders, whitespace, and
// ambiguous delimiters are rejected.
func exactMySQLBareConnection(connection, database string) bool {
	if strings.Count(connection, "@") != 1 ||
		strings.ContainsAny(connection, " \t\r\n/?#") ||
		unresolvedSQLConnectionIdentity(connection) {
		return false
	}
	userinfo, hostPort, found := strings.Cut(connection, "@")
	if !found || strings.Count(userinfo, ":") != 1 {
		return false
	}
	user, password, found := strings.Cut(userinfo, ":")
	if !found || user == "" || len(user) > 128 || len(password) > maxScalarBytes {
		return false
	}
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil || !exactPostgreSQLHost(host) {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return false
	}
	return database == "" || exactPostgreSQLIdentifierValue(database)
}

func exactMySQLURIConnection(connection, database string) bool {
	parsed, err := url.Parse(connection)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.Fragment != "" ||
		parsed.Scheme != "mysql" || parsed.Hostname() == "" {
		return false
	}
	resolvedDatabase := ""
	if parsed.Path != "" && parsed.Path != "/" {
		resolvedDatabase, err = url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
		if err != nil || !exactSQLScalar(resolvedDatabase, maxScalarBytes) ||
			strings.Contains(resolvedDatabase, "/") ||
			unresolvedSQLConnectionIdentity(resolvedDatabase) {
			return false
		}
	}
	if database != "" && resolvedDatabase != "" && database != resolvedDatabase {
		return false
	}
	for key, values := range parsed.Query() {
		if strings.EqualFold(key, "database") || strings.EqualFold(key, "dbname") ||
			strings.EqualFold(key, "schema") {
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

// exactMySQLKeyValueConnection accepts the closed comma-separated connector
// form observed in the source corpus. Empty passwords are permitted but never
// retained; quoted, escaped, duplicate, or unknown fields are rejected.
func exactMySQLKeyValueConnection(connection, database string) bool {
	fields := strings.Split(connection, ",")
	if len(fields) < 3 || len(fields) > 5 || strings.Join(fields, ",") != connection {
		return false
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || key == "" || strings.Contains(value, "=") ||
			unresolvedSQLConnectionIdentity(value) {
			return false
		}
		switch key {
		case "host", "port", "user", "password", "database":
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
	resolvedDatabase := values["database"]
	if resolvedDatabase != "" && !exactPostgreSQLIdentifierValue(resolvedDatabase) {
		return false
	}
	return database == "" || resolvedDatabase == "" || database == resolvedDatabase
}

func exactSQLSensitiveFileReadQuery(query string, functions []string) (string, bool) {
	if filePath, ok := exactSQLDirectSensitiveFileReadQuery(query, functions); ok {
		return filePath, true
	}
	if len(functions) == 2 && functions[0] == "pg_read_file" &&
		functions[1] == "pg_read_binary_file" {
		return exactPostgreSQLCopySensitiveFileReadQuery(query, functions)
	}
	return "", false
}

// exactSQLDirectSensitiveFileReadQuery reads a literal SELECT (no FROM)
// whose select list holds, as any of its items, the file function of a
// literal path with an optional AS alias: the server reads the file for that
// item whatever the other items are (rel-1-0-10:GAP-1961). The other items
// are skipped whole, to the next comma outside parentheses and quotes; an
// item the skip cannot read (a comment, an unbalanced parenthesis) leaves the
// query unread.
func exactSQLDirectSensitiveFileReadQuery(query string, functions []string) (string, bool) {
	parser := postgreSQLCopyParser{source: query}
	parser.space()
	if !parser.keyword("select") || !parser.requiredSpace() {
		return "", false
	}
	backslash := len(functions) != 0 && functions[0] == "load_file" // MySQL strings
	filePath := ""
	for {
		item := parser.index
		if path, ok := parseSQLSensitiveFileReadItem(&parser, functions); ok {
			if filePath == "" {
				filePath = path
			}
		} else {
			parser.index = item
			if !skipSQLSelectItem(&parser, backslash) {
				return "", false
			}
		}
		parser.space()
		if !parser.take(',') {
			break
		}
		parser.space()
	}
	if filePath == "" || !finishSingleSQLStatement(&parser) || !validSQLSensitiveFileLiteral(filePath) {
		return "", false
	}
	return filePath, true
}

// parseSQLSensitiveFileReadItem reads one select item that is the file
// function of a literal path with an optional AS alias, ending where the
// item ends (a comma, a semicolon or the end of the query).
func parseSQLSensitiveFileReadItem(parser *postgreSQLCopyParser, functions []string) (string, bool) {
	filePath, ok := parseSQLSensitiveFileReadInvocation(parser, functions)
	if !ok {
		return "", false
	}
	separation := parser.space()
	if separation > 0 && parser.keyword("as") {
		if !parser.requiredSpace() || parser.index >= len(parser.source) ||
			parser.source[parser.index] == '"' || !parser.identifier() {
			return "", false
		}
		parser.space()
	}
	if parser.index < len(parser.source) && parser.source[parser.index] != ',' &&
		parser.source[parser.index] != ';' {
		return "", false
	}
	return filePath, true
}

// skipSQLSelectItem moves parser past one select item: to the next comma or
// semicolon outside parentheses and quotes, or the end of the query. false
// for an item it cannot read with certainty: a comment, an unbalanced
// parenthesis or an unterminated quote.
func skipSQLSelectItem(parser *postgreSQLCopyParser, backslash bool) bool {
	source, depth, start := parser.source, 0, parser.index
	i := start
	for ; i < len(source); i++ {
		switch c := source[i]; {
		case c == '\'' || c == '"' || c == '`':
			end := sqlQuotedEnd(source, i, c, backslash && c != '`')
			if end > len(source) || source[end-1] != c || end == i+1 {
				return false
			}
			i = end - 1
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth < 0 {
				return false
			}
		case c == '#' || strings.HasPrefix(source[i:], "--") || strings.HasPrefix(source[i:], "/*"):
			return false
		case depth == 0 && (c == ',' || c == ';'):
			parser.index = i
			return strings.TrimSpace(source[start:i]) != ""
		}
	}
	parser.index = i
	return depth == 0 && strings.TrimSpace(source[start:i]) != ""
}

func exactPostgreSQLCopySensitiveFileReadQuery(
	query string,
	functions []string,
) (string, bool) {
	parser := postgreSQLCopyParser{source: query}
	parser.space()
	if !parser.keyword("copy") || !parser.requiredSpace() || !parser.take('(') {
		return "", false
	}
	parser.space()
	if !parser.keyword("select") || !parser.requiredSpace() {
		return "", false
	}
	filePath, ok := parseSQLSensitiveFileReadInvocation(&parser, functions)
	if !ok {
		return "", false
	}
	parser.space()
	if !parser.take(')') || !parser.requiredSpace() ||
		!parser.keyword("to") || !parser.requiredSpace() {
		return "", false
	}
	outputPath, ok := parser.stringLiteral()
	if !ok || !validStaticAbsolutePOSIXPath(outputPath) ||
		!finishSingleSQLStatement(&parser) ||
		!validSQLSensitiveFileLiteral(filePath) {
		return "", false
	}
	return filePath, true
}

func parseSQLSensitiveFileReadInvocation(
	parser *postgreSQLCopyParser,
	functions []string,
) (string, bool) {
	matched := false
	for _, function := range functions {
		checkpoint := parser.index
		if parser.keyword(function) {
			matched = true
			break
		}
		parser.index = checkpoint
	}
	if !matched {
		return "", false
	}
	parser.space()
	if !parser.take('(') {
		return "", false
	}
	parser.space()
	filePath, ok := parser.stringLiteral()
	if !ok {
		return "", false
	}
	parser.space()
	if !parser.take(')') {
		return "", false
	}
	return filePath, true
}

func finishSingleSQLStatement(parser *postgreSQLCopyParser) bool {
	parser.space()
	if parser.take(';') {
		parser.space()
	}
	return parser.done()
}

func validSQLSensitiveFileLiteral(filePath string) bool {
	if filePath == "" || len(filePath) > maxScalarBytes {
		return false
	}
	for _, character := range filePath {
		if character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validStaticAbsolutePOSIXPath(value string) bool {
	return validSQLSensitiveFileLiteral(value) && strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && !hasUnresolvedPathSyntax(value)
}

func sqlSensitiveServerFileClass(value string) string {
	if !validSQLSensitiveFileLiteral(value) || !strings.HasPrefix(value, "/") ||
		hasUnresolvedPathSyntax(value) {
		return ""
	}
	value = path.Clean(value)
	switch value {
	case "/etc/passwd":
		return SQLSensitiveServerFileAccountDatabase
	case "/etc/shadow", "/etc/gshadow",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"/var/run/secrets/azure/tokens/azure-identity-token":
		return SQLSensitiveServerFileCredential
	}
	base := path.Base(value)
	if strings.HasSuffix(value, "/.aws/credentials") ||
		strings.HasSuffix(value, "/.git-credentials") ||
		strings.HasSuffix(value, "/.netrc") ||
		strings.HasSuffix(value, "/.npmrc") ||
		strings.HasSuffix(value, "/.pypirc") ||
		strings.HasSuffix(value, "/.kube/config") ||
		strings.HasSuffix(value, "/.docker/config.json") ||
		strings.Contains(value, "/.ssh/") && strings.HasPrefix(base, "id_") &&
			!strings.HasSuffix(base, ".pub") {
		return SQLSensitiveServerFileCredential
	}
	return ""
}
