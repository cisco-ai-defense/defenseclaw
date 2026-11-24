// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

const (
	maxSQLASTBytes      = 64 << 10
	maxSQLASTTokens     = 16384
	maxSQLASTStatements = 256
	maxSQLASTDepth      = 4
)

type sqlASTTokenKind uint8

const (
	sqlASTWord sqlASTTokenKind = iota
	sqlASTIdentifier
	sqlASTString
	sqlASTPunctuation
)

type sqlASTToken struct {
	text string
	kind sqlASTTokenKind
}

type sqlASTMutation struct {
	operation SQLMutationOperation
	scope     SQLMutationScope
	object    string
}

type sqlASTResult struct {
	tokens         []sqlASTToken
	mutations      []sqlASTMutation
	verbs          []string
	tables         []string
	functions      []string
	statementCount int
	unknown        bool
	// caps are the bounds the reading hit (bytes, depth, statements,
	// tokens): the text past one is unknown, never a clean read.
	caps bounded.CapSet
}

// parseSQLAST extracts bounded, value-free SQL facts. It recognizes lexical
// structure rather than validating a dialect grammar; unknown syntax is kept
// unknown so callers can retain the existing verdict.
func parseSQLAST(query string) sqlASTResult {
	result := sqlASTResult{}
	var trunc bounded.Truncated
	parseSQLASTInto(query, 0, &result, &trunc)
	result.caps = trunc.Set()
	return result
}

func parseSQLASTInto(query string, depth int, result *sqlASTResult, trunc *bounded.Truncated) {
	if !trunc.Within(bounded.Depth, depth, maxSQLASTDepth) ||
		!trunc.Within(bounded.Bytes, len(query), maxSQLASTBytes) {
		result.unknown = true
		return
	}
	tokens, statements, ok := lexSQLAST(query)
	if !ok {
		result.unknown = true
		return
	}
	if depth == 0 {
		result.statementCount += statements
	}
	if !trunc.Within(bounded.Items, result.statementCount, maxSQLASTStatements) {
		result.unknown = true
		return
	}
	result.tokens = append(result.tokens, tokens...)
	result.mutations = append(result.mutations, extractSQLASTMutations(tokens)...)
	if !trunc.Within(bounded.Items, len(result.tokens), maxSQLASTTokens) {
		result.unknown = true
		return
	}
	for _, token := range tokens {
		if token.kind == sqlASTString {
			continue
		}
		if token.kind == sqlASTWord || token.kind == sqlASTIdentifier {
			word := strings.ToUpper(token.text)
			if isSQLASTVerb(word) {
				result.verbs = appendUniqueSQL(result.verbs, strings.ToLower(word))
			}
		}
	}
	for i, token := range tokens {
		if token.kind == sqlASTWord || token.kind == sqlASTIdentifier {
			word := strings.ToUpper(token.text)
			if isSQLASTTableIntroducer(word) && i+1 < len(tokens) {
				next := tokens[i+1]
				if next.kind == sqlASTWord || next.kind == sqlASTIdentifier {
					if !isSQLASTControlWord(strings.ToUpper(next.text)) {
						result.tables = appendUniqueSQL(result.tables, strings.ToLower(next.text))
					}
				}
			}
			if i+1 < len(tokens) && tokens[i+1].text == "(" &&
				isSQLASTIdentifierStart(token.text) && !isSQLASTControlWord(word) {
				result.functions = appendUniqueSQL(result.functions, strings.ToLower(token.text))
			}
			// Recurse only through a literal directly following DO or EXECUTE.
			if (word == "DO" || word == "EXECUTE") && i+1 < len(tokens) &&
				tokens[i+1].kind == sqlASTString {
				parseSQLASTInto(tokens[i+1].text, depth+1, result, trunc)
			}
		}
	}
	if !trunc.Within(bounded.Items, len(result.verbs), maxSQLASTTokens) ||
		!trunc.Within(bounded.Items, len(result.tables), maxSQLASTTokens) ||
		!trunc.Within(bounded.Items, len(result.functions), maxSQLASTTokens) {
		result.unknown = true
	}
}

func lexSQLAST(source string) ([]sqlASTToken, int, bool) {
	tokens := make([]sqlASTToken, 0, min(len(source)/4, 256))
	statements := 0
	parenDepth := 0
	statementTokenStart := 0
	for i := 0; i < len(source); {
		c := source[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if c == '-' && i+1 < len(source) && source[i+1] == '-' {
			i += 2
			for i < len(source) && source[i] != '\n' && source[i] != '\r' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '*' {
			i += 2
			depth := 1
			for i < len(source) && depth > 0 {
				if i+1 < len(source) && source[i] == '/' && source[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < len(source) && source[i] == '*' && source[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
			if depth != 0 {
				return nil, 0, false
			}
			continue
		}
		if c == '$' {
			endTag := i + 1
			for endTag < len(source) && (source[endTag] == '_' ||
				source[endTag] >= 'a' && source[endTag] <= 'z' ||
				source[endTag] >= 'A' && source[endTag] <= 'Z' ||
				source[endTag] >= '0' && source[endTag] <= '9') {
				endTag++
			}
			if endTag < len(source) && source[endTag] == '$' {
				tag := source[i : endTag+1]
				end := strings.Index(source[endTag+1:], tag)
				if end < 0 {
					return nil, 0, false
				}
				body := source[endTag+1 : endTag+1+end]
				tokens = append(tokens, sqlASTToken{text: body, kind: sqlASTString})
				i = endTag + 1 + end + len(tag)
				continue
			}
		}
		if c == '\'' {
			var value strings.Builder
			i++
			closed := false
			for i < len(source) {
				if source[i] == '\'' {
					if i+1 < len(source) && source[i+1] == '\'' {
						value.WriteByte('\'')
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				if source[i] == '\\' && i+1 < len(source) {
					i++
				}
				value.WriteByte(source[i])
				i++
			}
			if !closed {
				return nil, 0, false
			}
			tokens = append(tokens, sqlASTToken{text: value.String(), kind: sqlASTString})
			continue
		}
		if c == '"' || c == '`' || c == '[' {
			close := c
			if c == '[' {
				close = ']'
			}
			var value strings.Builder
			i++
			closed := false
			for i < len(source) {
				if source[i] == close {
					if i+1 < len(source) && source[i+1] == close && close != ']' {
						value.WriteByte(close)
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				value.WriteByte(source[i])
				i++
			}
			if !closed {
				return nil, 0, false
			}
			tokens = append(tokens, sqlASTToken{text: value.String(), kind: sqlASTIdentifier})
			continue
		}
		if c == ';' {
			if parenDepth == 0 {
				if len(tokens) > statementTokenStart {
					statements++
				}
				tokens = append(tokens, sqlASTToken{text: ";", kind: sqlASTPunctuation})
				statementTokenStart = len(tokens)
			}
			i++
			continue
		}
		if c == '(' {
			parenDepth++
		}
		if c == ')' {
			parenDepth--
			if parenDepth < 0 {
				return nil, 0, false
			}
		}
		if isSQLASTWordByte(c) {
			start := i
			i++
			for i < len(source) && isSQLASTWordByte(source[i]) {
				i++
			}
			tokens = append(tokens, sqlASTToken{text: source[start:i], kind: sqlASTWord})
		} else {
			tokens = append(tokens, sqlASTToken{text: string(c), kind: sqlASTPunctuation})
			i++
		}
		if len(tokens) > maxSQLASTTokens {
			return nil, 0, false
		}
	}
	if parenDepth != 0 {
		return nil, 0, false
	}
	if len(tokens) > statementTokenStart {
		statements++
	}
	return tokens, statements, true
}

func isSQLASTWordByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' ||
		c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
func isSQLASTIdentifierStart(s string) bool {
	if s == "" {
		return false
	}
	r := []rune(s)[0]
	return r == '_' || unicode.IsLetter(r)
}
func isSQLASTVerb(s string) bool {
	switch s {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE", "DROP",
		"ALTER", "GRANT", "REVOKE", "CREATE", "COPY", "CALL", "DO", "EXECUTE",
		"BEGIN", "COMMIT", "ROLLBACK":
		return true
	default:
		return false
	}
}
func isSQLASTTableIntroducer(s string) bool {
	switch s {
	case "FROM", "JOIN", "INTO", "UPDATE", "TABLE", "SCHEMA", "DATABASE", "REFERENCES", "ON":
		return true
	default:
		return false
	}
}
func isSQLASTControlWord(s string) bool {
	switch s {
	case "SELECT", "ONLY", "IF", "NOT", "EXISTS", "LATERAL", "UNNEST", "VALUES",
		"SET", "ROLE", "USER", "DATABASE", "SCHEMA", "TABLE", "INDEX", "VIEW",
		"TO", "FROM", "WITH", "AS", "PROGRAM":
		return true
	default:
		return false
	}
}
func appendUniqueSQL(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// SQLASTCaps are the bounds the SQL facts reader (parseSQLAST) hit on the
// call's SQL. The text past one gets no SQLFact and no AST mutation, and the
// legacy SQL readers judge it as at 1.0.10. The hit is recorded in the
// decision and raises nothing by itself: a large benign SQL text must not
// start alerting (DET111 ruling on T20 review P3-1).
func (f Facts) SQLASTCaps() bounded.CapSet { return f.sqlASTCaps }

// SQLUnreadDanger reports a statement past the SQL facts reader's
// statement cap that holds a modeled danger keyword and could not be read
// alone (sqlStatements): the gateway then grades the cap as the truncated
// row, not as a record.
func (f Facts) SQLUnreadDanger() bool { return f.sqlUnreadDanger }

func projectSQLAnalysis(input Input, facts Facts) ([]SQLMutationFact, []SQLFact, bounded.CapSet) {
	inputs := exactSQLMutationInputs(input, facts)
	mutations := make([]SQLMutationFact, 0, len(inputs))
	sqlFacts := make([]SQLFact, 0, len(inputs))
	var caps bounded.CapSet
	var singleParsed sqlASTResult
	for _, candidate := range inputs {
		parsed := parseSQLAST(candidate.query)
		if len(inputs) == 1 {
			singleParsed = parsed
		}
		caps = caps.Union(parsed.caps)
		if !parsed.unknown {
			database := candidate.databaseIdentity
			if !exactSQLIdentity(database) || unresolvedSQLMutationValue(database) {
				database = ""
			}
			sqlFacts = append(sqlFacts, SQLFact{
				Verbs:          append([]string(nil), parsed.verbs...),
				Tables:         append([]string(nil), parsed.tables...),
				Functions:      append([]string(nil), parsed.functions...),
				Database:       database,
				StatementCount: parsed.statementCount,
			})
		}
	}
	statements, capped, _ := sqlSessionStatementCandidates(inputs)
	if capped {
		caps = caps.Union(bounded.Of(bounded.Items))
	}
	for _, statement := range statements {
		if statement.rolledBack {
			continue
		}
		parsed := singleParsed
		if len(inputs) != 1 || len(statements) != 1 || statement.query != inputs[0].query {
			parsed = parseSQLAST(statement.query)
		}
		caps = caps.Union(parsed.caps)
		if fact, ok := exactSQLMutationOf(statement, parsed); ok {
			mutations = append(mutations, fact)
		}
	}
	return mutations, sqlFacts, caps
}

// exactSQLMutationOf is the exact mutation fact of one statement candidate:
// the text grammar (exactSQLMutation), else the SQL facts reading of it
// (exactSQLASTMutationParsed). parsed is the reading of this candidate.
func exactSQLMutationOf(candidate exactSQLMutationInput, parsed sqlASTResult) (SQLMutationFact, bool) {
	operation, scope, object, ok := exactSQLMutation(candidate.engine, candidate.query)
	if candidate.engine == "sqlite" {
		object, ok = exactSQLiteUnboundedDelete(candidate.query)
		operation = SQLMutationDeleteUnbounded
		scope = SQLMutationScopeTable
	} else if !ok {
		if !parsed.unknown {
			operation, scope, object, ok = exactSQLASTMutationParsed(candidate.engine, candidate.query, parsed)
		}
	}
	if !ok {
		return SQLMutationFact{}, false
	}
	return projectSQLMutationFact(candidate, operation, scope, object)
}

func exactSQLASTMutationParsed(engine, query string, parsed sqlASTResult) (SQLMutationOperation, SQLMutationScope, string, bool) {
	if engine == "sqlite" || len(query) == 0 || len(query) > maxSQLASTBytes ||
		strings.Contains(query, "--") || strings.Contains(query, "/*") ||
		strings.Contains(query, "*/") || strings.Contains(query, "#") ||
		parsed.unknown || parsed.statementCount != 1 || len(parsed.mutations) == 0 {
		return "", "", "", false
	}
	upper := strings.ToUpper(strings.TrimSpace(query))
	if strings.HasPrefix(upper, "BEGIN") || strings.HasPrefix(upper, "START TRANSACTION") {
		return "", "", "", false
	}
	if strings.HasPrefix(upper, "EXPLAIN ") {
		if engine != "postgresql" || !strings.HasPrefix(upper, "EXPLAIN ANALYZE ") ||
			parsed.mutations[0].operation != SQLMutationDeleteUnbounded {
			return "", "", "", false
		}
	}
	mutation := parsed.mutations[0]
	object := strings.ToLower(mutation.object)
	if !exactSQLQualifiedIdentity(object) {
		return "", "", "", false
	}
	return mutation.operation, mutation.scope, object, true
}

func extractSQLASTMutations(tokens []sqlASTToken) []sqlASTMutation {
	var result []sqlASTMutation
	for start := 0; start < len(tokens); {
		end := start
		for end < len(tokens) && tokens[end].text != ";" {
			end++
		}
		statement := tokens[start:end]
		start = end + 1
		if len(statement) == 0 {
			continue
		}
		if strings.EqualFold(statement[0].text, "EXPLAIN") &&
			(len(statement) < 2 || !strings.EqualFold(statement[1].text, "ANALYZE")) {
			continue
		}
		for i := 0; i < len(statement); i++ {
			if statement[i].kind == sqlASTString {
				continue
			}
			word := strings.ToUpper(statement[i].text)
			switch word {
			case "TRUNCATE", "DELETE", "UPDATE":
				if !sqlASTStatementVerb(statement, i) {
					continue // a clause word: ON CONFLICT DO UPDATE, GRANT TRUNCATE ON, FOR UPDATE
				}
			}
			switch word {
			case "DROP":
				if i+2 >= len(statement) {
					continue
				}
				kind := strings.ToUpper(statement[i+1].text)
				var scope SQLMutationScope
				var op SQLMutationOperation
				switch kind {
				case "TABLE":
					scope, op = SQLMutationScopeTable, SQLMutationDropTable
				case "SCHEMA":
					scope, op = SQLMutationScopeSchema, SQLMutationDropSchema
				case "DATABASE":
					scope, op = SQLMutationScopeDatabase, SQLMutationDropDatabase
				default:
					continue
				}
				objectIndex := i + 2
				if objectIndex+1 < len(statement) && strings.EqualFold(statement[objectIndex].text, "IF") &&
					strings.EqualFold(statement[objectIndex+1].text, "EXISTS") {
					objectIndex += 2
				}
				if object, ok := sqlASTQualifiedObject(statement, objectIndex); ok {
					result = append(result, sqlASTMutation{operation: op, scope: scope, object: object})
				}
			case "TRUNCATE":
				objectIndex := i + 1
				if objectIndex < len(statement) && strings.EqualFold(statement[objectIndex].text, "TABLE") {
					objectIndex++
				}
				if object, ok := sqlASTMutationObject(statement, objectIndex); ok {
					result = append(result, sqlASTMutation{operation: SQLMutationTruncate, scope: SQLMutationScopeTable, object: object})
				}
			case "DELETE":
				if i+2 >= len(statement) || !strings.EqualFold(statement[i+1].text, "FROM") ||
					sqlASTHasWord(statement[i+2:], "WHERE") {
					continue
				}
				if object, ok := sqlASTMutationObject(statement, i+2); ok {
					result = append(result, sqlASTMutation{operation: SQLMutationDeleteUnbounded, scope: SQLMutationScopeTable, object: object})
				}
			case "UPDATE":
				if i+1 >= len(statement) || sqlASTHasWord(statement[i+1:], "WHERE") {
					continue
				}
				if object, ok := sqlASTMutationObject(statement, i+1); ok &&
					sqlASTHasWord(statement[i+1:], "SET") {
					result = append(result, sqlASTMutation{operation: SQLMutationUpdateUnbounded, scope: SQLMutationScopeTable, object: object})
				}
			}
		}
	}
	return result
}

func sqlASTHasWord(tokens []sqlASTToken, word string) bool {
	for _, token := range tokens {
		if token.kind != sqlASTString && strings.EqualFold(token.text, word) {
			return true
		}
	}
	return false
}

// sqlASTStatementVerb reports whether the TRUNCATE, DELETE or UPDATE at
// statement[i] starts a statement rather than naming an operation in a clause:
// INSERT ... ON CONFLICT ... DO UPDATE SET (a bounded upsert), ON DUPLICATE KEY
// UPDATE, ON UPDATE CASCADE, SELECT ... FOR UPDATE, a trigger's BEFORE/AFTER/
// INSTEAD OF ... OR UPDATE OF, and GRANT/REVOKE privilege lists (DET111 T20
// review P2-1).
func sqlASTStatementVerb(statement []sqlASTToken, i int) bool {
	if i == 0 {
		return true
	}
	previous := statement[i-1]
	if previous.kind == sqlASTPunctuation {
		return previous.text != ","
	}
	switch strings.ToUpper(previous.text) {
	case "DO", "ON", "FOR", "BEFORE", "AFTER", "OF", "OR", "GRANT", "REVOKE", "KEY", "INSTEAD", "EACH":
		return false
	}
	return true
}

// sqlASTMutationObject is the table a TRUNCATE, DELETE FROM or UPDATE names at
// tokens[start] (after an optional ONLY): never a keyword such as SET, so
// DO UPDATE SET is not an update of a table named "set".
func sqlASTMutationObject(tokens []sqlASTToken, start int) (string, bool) {
	if start < len(tokens) && tokens[start].kind == sqlASTWord && strings.EqualFold(tokens[start].text, "ONLY") {
		start++
	}
	if start < len(tokens) && tokens[start].kind == sqlASTWord && isSQLASTControlWord(strings.ToUpper(tokens[start].text)) {
		return "", false
	}
	return sqlASTQualifiedObject(tokens, start)
}

func sqlASTQualifiedObject(tokens []sqlASTToken, start int) (string, bool) {
	if start >= len(tokens) {
		return "", false
	}
	if tokens[start].kind != sqlASTWord && tokens[start].kind != sqlASTIdentifier {
		return "", false
	}
	var object strings.Builder
	object.WriteString(tokens[start].text)
	for i := start + 1; i+1 < len(tokens) && tokens[i].text == "."; i += 2 {
		if tokens[i+1].kind != sqlASTWord && tokens[i+1].kind != sqlASTIdentifier {
			return "", false
		}
		object.WriteByte('.')
		object.WriteString(tokens[i+1].text)
	}
	return object.String(), true
}
