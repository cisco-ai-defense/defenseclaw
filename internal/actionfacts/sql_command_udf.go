// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"path"
	"strings"
)

const (
	sqlCommandUDFPostgreSQLConnectionDomain = "defenseclaw/actionfacts/sql-command-udf-postgresql-connection/v1"
	sqlCommandUDFMySQLConnectionDomain      = "defenseclaw/actionfacts/sql-command-udf-mysql-connection/v1"
	sqlCommandUDFFunctionDomain             = "defenseclaw/actionfacts/sql-command-udf-function/v1"
	sqlCommandUDFLineageDomain              = "defenseclaw/actionfacts/sql-command-udf-lineage/v1"
	maxSQLUDFBodyBytes                      = 16 * 1024
)

// ExactSQLCommandUDFOperation returns one exact value-free create/invoke
// projection. It never returns SQL, command text, function names, connection
// data, usernames, or passwords.
func ExactSQLCommandUDFOperation(
	facts Facts,
) (SQLCommandUDFOperation, string, string, string, bool) {
	if len(facts.SQLCommandUDFOperations) != 1 {
		return "", "", "", "", false
	}
	fact := facts.SQLCommandUDFOperations[0]
	if fact.Operation != SQLCommandUDFCreate && fact.Operation != SQLCommandUDFInvoke &&
		fact.Operation != SQLCommandUDFBarrier {
		return "", "", "", "", false
	}
	if fact.DatabaseEngine != "mysql" && fact.DatabaseEngine != "postgresql" {
		return "", "", "", "", false
	}
	if !exactLowerSHA256(fact.ConnectionIdentityDigest) ||
		!exactLowerSHA256(fact.FunctionIdentityDigest) {
		return "", "", "", "", false
	}
	return fact.Operation, fact.DatabaseEngine, fact.ConnectionIdentityDigest,
		fact.FunctionIdentityDigest, true
}

// ExactSQLCommandUDFLineageOperation returns one opaque identity joining the
// exact database engine, connection, and function. It is suitable for bounded
// runtime correlation and retains none of the underlying values.
func ExactSQLCommandUDFLineageOperation(
	facts Facts,
) (SQLCommandUDFOperation, string, bool) {
	operation, engine, connectionDigest, functionDigest, ok :=
		ExactSQLCommandUDFOperation(facts)
	if !ok {
		return "", "", false
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{
		sqlCommandUDFLineageDomain, engine, connectionDigest, functionDigest,
	} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return operation, hex.EncodeToString(hash.Sum(nil)), true
}

func projectSQLCommandUDFOperations(input Input, facts Facts) []SQLCommandUDFOperationFact {
	if connection, database, query, ok := exactSQLQueryInput(input); ok &&
		exactPostgreSQLConnection(connection, database) {
		operation, function, matched := exactPostgreSQLCommandUDFQuery(query)
		if !matched {
			return nil
		}
		return newSQLCommandUDFFact(
			operation,
			"postgresql",
			sqlConnectionIdentityDigest(
				sqlCommandUDFPostgreSQLConnectionDomain,
				connection,
				database,
			),
			function,
		)
	}

	connectionIdentity, query, ok := exactMySQLCLIQuery(facts)
	if !ok {
		return nil
	}
	operation, function, matched := exactMySQLCommandUDFQuery(query)
	if !matched {
		return nil
	}
	return newSQLCommandUDFFact(
		operation,
		"mysql",
		sqlConnectionIdentityDigest(
			sqlCommandUDFMySQLConnectionDomain,
			connectionIdentity,
			"",
		),
		function,
	)
}

func newSQLCommandUDFFact(
	operation SQLCommandUDFOperation,
	engine string,
	connectionDigest string,
	function string,
) []SQLCommandUDFOperationFact {
	functionDigest := sqlCommandUDFFunctionDigest(engine, function)
	if connectionDigest == "" || functionDigest == "" {
		return nil
	}
	return []SQLCommandUDFOperationFact{{
		Operation:                operation,
		DatabaseEngine:           engine,
		ConnectionIdentityDigest: connectionDigest,
		FunctionIdentityDigest:   functionDigest,
	}}
}

func exactLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sqlCommandUDFFunctionDigest(engine, function string) string {
	if (engine != "mysql" && engine != "postgresql") || function == "" {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{sqlCommandUDFFunctionDomain, engine, function} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func exactMySQLCLIQuery(facts Facts) (connectionIdentity, query string, ok bool) {
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		return "", "", false
	}
	command := facts.Commands[0]
	if command.Program != "mysql" || command.Effect != EffectExecute ||
		!command.ArgvComplete || command.ControlFlowUncertain ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		len(command.Argv) < 5 || command.Argv[0] != "mysql" {
		return "", "", false
	}
	argv := command.Argv
	index := 1
	if index+1 >= len(argv) || argv[index] != "-u" ||
		!exactMySQLCLIIdentityScalar(argv[index+1]) {
		return "", "", false
	}
	index += 2
	if index < len(argv) && strings.HasPrefix(argv[index], "-p") {
		if len(argv[index]) == 2 || !exactMySQLCLIIdentityScalar(argv[index][2:]) {
			return "", "", false
		}
		index++
	}
	if index+2 != len(argv) || argv[index] != "-e" ||
		!exactSQLScalar(argv[index+1], maxCommandBytes) {
		return "", "", false
	}
	// The exact static CLI prefix is the connection identity. It includes any
	// supplied credential only inside a one-way, domain-separated digest.
	return strings.Join(argv[:index], "\x00"), argv[index+1], true
}

func exactMySQLCLIIdentityScalar(value string) bool {
	return exactSQLScalar(value, maxScalarBytes) &&
		!unresolvedSQLConnectionIdentity(value) &&
		!strings.ContainsAny(value, "\x00\r\n\t ")
}

func exactPostgreSQLCommandUDFQuery(
	query string,
) (SQLCommandUDFOperation, string, bool) {
	if function, body, symbol, language, replace, ok := parsePostgreSQLUDFCreate(query); ok {
		if commandExecutingPostgreSQLUDF(function, body, symbol, language) {
			return SQLCommandUDFCreate, function, true
		}
		if replace {
			return SQLCommandUDFBarrier, function, true
		}
	}
	if function, ok := parseSQLCommandUDFFunctionDrop(query, true); ok {
		return SQLCommandUDFBarrier, function, true
	}
	if function, ok := parseSingleLiteralFunctionInvocation(query); ok {
		return SQLCommandUDFInvoke, function, true
	}
	return "", "", false
}

func exactMySQLCommandUDFQuery(
	query string,
) (SQLCommandUDFOperation, string, bool) {
	if function, library, ok := parseMySQLUDFCreate(query); ok &&
		commandExecutingMySQLUDF(function, library) {
		return SQLCommandUDFCreate, function, true
	}
	if function, ok := parseSingleLiteralFunctionInvocation(query); ok {
		return SQLCommandUDFInvoke, function, true
	}
	if function, ok := parseSQLCommandUDFFunctionDrop(query, false); ok {
		return SQLCommandUDFBarrier, function, true
	}
	return "", "", false
}

func parsePostgreSQLUDFCreate(
	query string,
) (function, body, symbol, language string, replace, ok bool) {
	p := postgreSQLCopyParser{source: query}
	p.space()
	if !p.keyword("create") || !p.requiredSpace() {
		return "", "", "", "", false, false
	}
	if p.keyword("or") {
		if !p.requiredSpace() || !p.keyword("replace") || !p.requiredSpace() {
			return "", "", "", "", false, false
		}
		replace = true
	}
	if !p.keyword("function") || !p.requiredSpace() {
		return "", "", "", "", false, false
	}
	function, ok = parseSimpleQualifiedIdentifier(&p)
	if !ok {
		return "", "", "", "", false, false
	}
	p.space()
	if !parseStaticFunctionSignature(&p) || !p.requiredSpace() ||
		!p.keyword("returns") || !p.requiredSpace() || !parseSimpleReturnType(&p) ||
		!p.requiredSpace() || !p.keyword("as") || !p.requiredSpace() {
		return "", "", "", "", false, false
	}
	body, ok = parseSQLBodyLiteral(&p)
	if !ok || body == "" || len(body) > maxSQLUDFBodyBytes {
		return "", "", "", "", false, false
	}
	separation := p.space()
	if p.take(',') {
		p.space()
		symbol, ok = p.stringLiteral()
		if !ok || symbol == "" || len(symbol) > maxScalarBytes {
			return "", "", "", "", false, false
		}
		separation = p.space()
	}
	if separation == 0 || !p.keyword("language") || !p.requiredSpace() {
		return "", "", "", "", false, false
	}
	language, ok = parseSimpleIdentifier(&p)
	if !ok {
		return "", "", "", "", false, false
	}
	language = strings.ToLower(language)
	p.space()
	if p.keyword("strict") {
		p.space()
	}
	if p.take(';') {
		p.space()
	}
	return function, body, symbol, language, replace, p.done()
}

func parseSQLCommandUDFFunctionDrop(query string, postgres bool) (string, bool) {
	p := postgreSQLCopyParser{source: query}
	p.space()
	if !p.keyword("drop") || !p.requiredSpace() || !p.keyword("function") ||
		!p.requiredSpace() {
		return "", false
	}
	if p.keyword("if") {
		if !p.requiredSpace() || !p.keyword("exists") || !p.requiredSpace() {
			return "", false
		}
	}
	function, ok := parseSimpleQualifiedIdentifier(&p)
	if !ok || !postgres && strings.Contains(function, ".") {
		return "", false
	}
	p.space()
	if postgres && p.index < len(p.source) && p.source[p.index] == '(' {
		if !parseStaticFunctionSignature(&p) {
			return "", false
		}
		p.space()
	}
	if postgres && (p.keyword("cascade") || p.keyword("restrict")) {
		p.space()
	}
	if p.take(';') {
		p.space()
	}
	return function, p.done()
}

func parseMySQLUDFCreate(query string) (function, library string, ok bool) {
	p := postgreSQLCopyParser{source: query}
	p.space()
	if !p.keyword("create") || !p.requiredSpace() || !p.keyword("function") ||
		!p.requiredSpace() {
		return "", "", false
	}
	function, ok = parseSimpleQualifiedIdentifier(&p)
	if !ok || strings.Contains(function, ".") || !p.requiredSpace() ||
		!p.keyword("returns") || !p.requiredSpace() {
		return "", "", false
	}
	returnType, typeOK := parseSimpleIdentifier(&p)
	if !typeOK || !strings.EqualFold(returnType, "int") || !p.requiredSpace() ||
		!p.keyword("soname") || !p.requiredSpace() {
		return "", "", false
	}
	library, ok = p.stringLiteral()
	if !ok || library == "" || len(library) > maxScalarBytes ||
		strings.TrimSpace(library) != library || strings.ContainsAny(library, "\x00\r\n") {
		return "", "", false
	}
	p.space()
	if p.take(';') {
		p.space()
	}
	return function, library, p.done()
}

func parseSingleLiteralFunctionInvocation(query string) (string, bool) {
	p := postgreSQLCopyParser{source: query}
	p.space()
	if !p.keyword("select") || !p.requiredSpace() {
		return "", false
	}
	function, ok := parseSimpleQualifiedIdentifier(&p)
	if !ok {
		return "", false
	}
	p.space()
	if !p.take('(') {
		return "", false
	}
	p.space()
	argument, ok := p.stringLiteral()
	if !ok || argument == "" || len(argument) > maxCommandBytes ||
		strings.TrimSpace(argument) != argument || strings.ContainsAny(argument, "\x00\r\n") {
		return "", false
	}
	p.space()
	if !p.take(')') {
		return "", false
	}
	p.space()
	if p.take(';') {
		p.space()
	}
	return function, p.done()
}

func parseSimpleQualifiedIdentifier(p *postgreSQLCopyParser) (string, bool) {
	parts := make([]string, 0, 3)
	for len(parts) < 3 {
		part, ok := parseSimpleIdentifier(p)
		if !ok {
			return "", false
		}
		parts = append(parts, strings.ToLower(part))
		if p.index >= len(p.source) || p.source[p.index] != '.' {
			return strings.Join(parts, "."), true
		}
		p.index++
	}
	return "", false
}

func parseSimpleIdentifier(p *postgreSQLCopyParser) (string, bool) {
	start := p.index
	if start >= len(p.source) || !postgreSQLIdentifierStart(p.source[start]) {
		return "", false
	}
	p.index++
	for p.index < len(p.source) && postgreSQLIdentifierByte(p.source[p.index]) {
		p.index++
	}
	if p.index-start > 128 {
		return "", false
	}
	return p.source[start:p.index], true
}

func parseStaticFunctionSignature(p *postgreSQLCopyParser) bool {
	if !p.take('(') {
		return false
	}
	start := p.index
	for p.index < len(p.source) && p.source[p.index] != ')' {
		character := p.source[p.index]
		if !(postgreSQLIdentifierByte(character) || character == ' ' ||
			character == '\t' || character == ',' || character == '.') {
			return false
		}
		p.index++
	}
	if p.index-start > 1024 || !p.take(')') {
		return false
	}
	return true
}

func parseSimpleReturnType(p *postgreSQLCopyParser) bool {
	if _, ok := parseSimpleQualifiedIdentifier(p); !ok {
		return false
	}
	// Permit the exact two-token built-in types that can occur without quoting;
	// no arrays, modifiers, defaults, or dynamic type expressions are accepted.
	saved := p.index
	if p.requiredSpace() {
		if value, ok := parseSimpleIdentifier(p); ok &&
			(strings.EqualFold(value, "precision") || strings.EqualFold(value, "varying")) {
			return true
		}
	}
	p.index = saved
	return true
}

func parseSQLBodyLiteral(p *postgreSQLCopyParser) (string, bool) {
	if p.index < len(p.source) && p.source[p.index] == '\'' {
		return p.stringLiteral()
	}
	if p.index+1 >= len(p.source) || p.source[p.index:p.index+2] != "$$" {
		return "", false
	}
	p.index += 2
	end := strings.Index(p.source[p.index:], "$$")
	if end < 0 {
		return "", false
	}
	body := p.source[p.index : p.index+end]
	p.index += end + 2
	return body, true
}

func commandExecutingPostgreSQLUDF(function, body, symbol, language string) bool {
	switch language {
	case "plpythonu", "plpython3u":
		code, scrubbed := scrubPythonCommentsAndStrings(body)
		if !scrubbed {
			return false
		}
		importsRuntime := pythonImportsModule(code, "os") ||
			pythonImportsModule(code, "subprocess")
		hasCommandSink := pythonCalls(code, "os.popen") ||
			pythonCalls(code, "os.system") ||
			pythonCalls(code, "subprocess.run") ||
			pythonCalls(code, "subprocess.Popen") ||
			pythonCalls(code, "subprocess.call") ||
			pythonCalls(code, "subprocess.check_output")
		return importsRuntime && hasCommandSink
	case "plperl", "plperlu":
		// The current corpus has no separately-invoked, closed PL/Perl create;
		// backticks inside strings/comments are not enough to prove execution.
		return false
	case "c":
		// SQL exposes no C implementation body. Admit only the one exact
		// source-observed PostgreSQL sys_exec library/symbol shape; broad C UDF
		// names or arbitrary same-name libraries are not capability evidence.
		if function != "sys_exec" || symbol != "sys_exec" {
			return false
		}
		parts := strings.Split(body, "/")
		if len(parts) != 7 || parts[0] != "" || parts[1] != "usr" ||
			parts[2] != "lib" || parts[3] != "postgresql" ||
			parts[5] != "lib" || parts[6] != "sys_exec.so" {
			return false
		}
		for _, character := range parts[4] {
			if character < '0' || character > '9' {
				return false
			}
		}
		return parts[4] != ""
	default:
		return false
	}
}

// scrubPythonCommentsAndStrings performs a bounded lexical pass over the UDF
// body. It preserves only executable source characters and whitespace; bytes
// inside comments, ordinary strings, and triple-quoted strings become spaces.
// Unterminated strings fail closed. This is intentionally not a Python parser:
// the accepted sink grammar below is limited to the simple source shapes in
// the pinned corpus.
func scrubPythonCommentsAndStrings(source string) (string, bool) {
	if source == "" || len(source) > maxSQLUDFBodyBytes {
		return "", false
	}
	result := []byte(source)
	const (
		pythonCode = iota
		pythonComment
		pythonSingleQuote
		pythonDoubleQuote
		pythonTripleSingle
		pythonTripleDouble
	)
	state := pythonCode
	escaped := false
	for index := 0; index < len(source); index++ {
		character := source[index]
		switch state {
		case pythonCode:
			switch {
			case character == '#':
				result[index] = ' '
				state = pythonComment
			case character == '\'' && index+2 < len(source) && source[index:index+3] == "'''":
				result[index], result[index+1], result[index+2] = ' ', ' ', ' '
				index += 2
				state = pythonTripleSingle
			case character == '"' && index+2 < len(source) && source[index:index+3] == "\"\"\"":
				result[index], result[index+1], result[index+2] = ' ', ' ', ' '
				index += 2
				state = pythonTripleDouble
			case character == '\'':
				result[index] = ' '
				state = pythonSingleQuote
			case character == '"':
				result[index] = ' '
				state = pythonDoubleQuote
			}
		case pythonComment:
			if character == '\n' {
				state = pythonCode
			} else {
				result[index] = ' '
			}
		case pythonSingleQuote, pythonDoubleQuote:
			result[index] = ' '
			quote := byte('\'')
			if state == pythonDoubleQuote {
				quote = '"'
			}
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == quote {
				state = pythonCode
			}
		case pythonTripleSingle, pythonTripleDouble:
			result[index] = ' '
			terminator := "'''"
			if state == pythonTripleDouble {
				terminator = "\"\"\""
			}
			if index+2 < len(source) && source[index:index+3] == terminator {
				result[index+1], result[index+2] = ' ', ' '
				index += 2
				state = pythonCode
			}
		}
	}
	return string(result), state == pythonCode || state == pythonComment
}

func pythonImportsModule(code, module string) bool {
	tokens := pythonIdentifierTokens(code)
	for index := 0; index+1 < len(tokens); index++ {
		if tokens[index] == "import" && tokens[index+1] == module {
			return true
		}
	}
	return false
}

func pythonIdentifierTokens(code string) []string {
	tokens := make([]string, 0, 16)
	for index := 0; index < len(code); {
		if !pythonIdentifierStart(code[index]) {
			index++
			continue
		}
		start := index
		index++
		for index < len(code) && pythonIdentifierByte(code[index]) {
			index++
		}
		tokens = append(tokens, code[start:index])
	}
	return tokens
}

func pythonCalls(code, qualifiedName string) bool {
	for offset := 0; ; {
		found := strings.Index(code[offset:], qualifiedName)
		if found < 0 {
			return false
		}
		found += offset
		end := found + len(qualifiedName)
		leftBoundary := found == 0 || !pythonIdentifierByte(code[found-1])
		rightBoundary := end == len(code) || !pythonIdentifierByte(code[end])
		index := end
		for index < len(code) && (code[index] == ' ' || code[index] == '\t') {
			index++
		}
		if leftBoundary && rightBoundary && index < len(code) && code[index] == '(' {
			return true
		}
		offset = end
	}
}

func pythonIdentifierStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func pythonIdentifierByte(value byte) bool {
	return pythonIdentifierStart(value) || value >= '0' && value <= '9'
}

func commandExecutingMySQLUDF(function, library string) bool {
	return (function == "sys_exec" || function == "sys_eval") &&
		strings.EqualFold(path.Base(library), "lib_mysqludf_sys.so")
}
