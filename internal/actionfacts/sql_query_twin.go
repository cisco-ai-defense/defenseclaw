// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// sqlQueryWord is an over-limit word that is the inline query of a SQL
// client of engine (overLimitSQLQueryOperand); glued when the word is the
// long option with its value (--command=<SQL>).
type sqlQueryWord struct {
	engine string
	glued  bool
}

// maxSQLQueryChunks is the per-call budget of readings of one over-limit
// inline query: the query is read in chunks of whole statements, each within
// the shell word bound, at most as many as the command bound holds words of
// that bound. The statements past the budget are not read and the call keeps
// its truncation record, which raises nothing (DET111 ruling B on GAP-1926).
const maxSQLQueryChunks = maxCommandBytes / maxScalarBytes

// sqlQueryWordChunks are the stand-ins, single-quoted for the shell, of the
// inline query of a SQL client that is past the shell word bound. A quoted
// literal, a quoted identifier and a comment past stubKeepBytes are data in
// the grammar of SQL, as a data word is to the shell: each is shortened with
// its quoting (sqlQueryShortened), so every statement keeps its shape and the
// SQL readers judge it as the same query with short literals. A query still
// past the bound is cut into chunks of complete statements, each within the
// bound, in order (DET111 ruling B on GAP-1926: the statements past the first
// cut are read too, under the per-call budget maxSQLQueryChunks); each chunk
// is read as the query of its own reading of the call, and each statement of
// a chunk is read alone (sqlSessionStatementCandidates). A statement that is itself
// past the bound ends the chunks, and the statements from there on are not
// read; the call keeps the truncation record (the cut raises nothing by
// itself). A query with no complete statement within the bound leaves the
// stand-in x, as a data word does.
//
// A statement the cut leaves unread that holds a modeled danger keyword
// (sqlDangerStatement) is read too, alone, as one more chunk: a padded
// statement takes the cell of the same statement unpadded (DET111 rulings
// on T23 review P3-1 and GAP-2122), at most maxSQLDangerReadings of them.
// unreadDanger reports one that still cannot be read (itself past the bound,
// or past that budget): the cut then takes the truncated row instead of the
// record. A benign rest keeps the record.
func sqlQueryWordChunks(word sqlQueryWord, value string) (chunks []string, unreadDanger bool) {
	option := ""
	if word.glued {
		name, query, _ := strings.Cut(value, "=")
		option, value = name+"=", query
	}
	query, ends := sqlQueryShortened(word.engine, value)
	if len(option)+len(query) <= maxScalarBytes {
		return []string{sqlQueryChunkWord(option, query)}, false
	}
	start := 0
	for len(chunks) < maxSQLQueryChunks {
		rest := query[start:]
		if strings.TrimSpace(rest) == "" {
			break
		}
		if len(option)+len(rest) <= maxScalarBytes {
			chunks = append(chunks, sqlQueryChunkWord(option, rest))
			start = len(query)
			break
		}
		// The chunk ends after its last complete statement within the
		// bound; none when the next statement is itself past the bound.
		kept := start
		for _, end := range ends {
			if end > start && len(option)+end-start <= maxScalarBytes {
				kept = end
			}
		}
		if kept == start {
			break
		}
		chunks = append(chunks, sqlQueryChunkWord(option, query[start:kept]))
		start = kept
	}
	if len(chunks) == 0 {
		chunks = []string{sqlQueryChunkWord(option, "")}
	}
	// The statements of the unread rest, one pass: each is the text up to
	// its terminating semicolon, the last one up to the end.
	extra := 0
	from := start
	read := func(to int) {
		statement := query[from:to]
		from = to
		if !sqlDangerStatement(word.engine, statement) {
			return
		}
		if len(option)+len(strings.TrimSpace(statement)) > maxScalarBytes || extra == maxSQLDangerReadings {
			unreadDanger = true
			return
		}
		chunks = append(chunks, sqlQueryChunkWord(option, statement))
		extra++
	}
	for _, end := range ends {
		if end > from {
			read(end)
		}
	}
	if from < len(query) {
		read(len(query))
	}
	return chunks, unreadDanger
}

// maxSQLDangerReadings is the per-query budget of unread statements with a
// danger keyword read alone (sqlQueryWordChunks, sqlStatements); one past it
// is the truncated row.
const maxSQLDangerReadings = 8

// sqlDangerPattern is the modeled keywords of the SQL readers' danger
// families, on the upper-case bare text of one statement: a server program
// (COPY ... TO/FROM PROGRAM, xp_cmdshell), a server file read (LOAD_FILE,
// pg_read_file, pg_read_binary_file), and the destructive scopes of the
// mutation reader: dropping a database or schema, and the TRUNCATE
// statement, only at the statement start and followed by TABLE or a name,
// never the MySQL TRUNCATE(x, d) function (GAP-2120). RE2: linear.
var sqlDangerPattern = lazyMustCompile(`^\s*TRUNCATE\s+(?:TABLE\b|[^\s(;])|\b(?:(?:TO|FROM)\s+PROGRAM|XP_CMDSHELL|LOAD_FILE|PG_READ_(?:BINARY_)?FILE|DROP\s+(?:DATABASE|SCHEMA))\b`)

// sqlDangerStatement reports one statement whose SQL outside quotes and
// comments (sqlSpans) holds a danger keyword (sqlDangerPattern): a keyword
// inside a literal is data, as it is to the server. One pass over the text.
func sqlDangerStatement(engine, statement string) bool {
	if strings.TrimSpace(statement) == "" {
		return false
	}
	var bare strings.Builder
	bare.Grow(len(statement))
	sqlSpans(engine, statement, func(kind sqlSpanKind, start, end int) {
		switch kind {
		case sqlSpanByte:
			bare.WriteString(statement[start:end])
		case sqlSpanEnd:
		default:
			bare.WriteByte(' ')
		}
	})
	return sqlDangerPattern.MatchString(strings.ToUpper(bare.String()))
}

// sqlQueryChunkWord is the shell word of one chunk of an inline query.
func sqlQueryChunkWord(option, query string) string {
	// A shortened comment leaves a space; at either end of the query it is
	// no part of a statement, and the exact readers refuse a query with
	// surrounding space.
	if query = strings.TrimSpace(query); query == "" {
		query = "x"
	}
	return posixSingleQuoted(option + query)
}

// sqlSpanKind is the kind of one span of SQL text (sqlSpans).
type sqlSpanKind uint8

const (
	// sqlSpanByte is one byte of SQL outside quotes and comments.
	sqlSpanByte sqlSpanKind = iota
	// sqlSpanQuoted is a quoted literal or identifier, or a PostgreSQL
	// dollar quote, with its quotes.
	sqlSpanQuoted
	// sqlSpanComment is a line or block comment.
	sqlSpanComment
	// sqlSpanEnd is the semicolon that ends a statement.
	sqlSpanEnd
)

// sqlSpans calls visit with each span of query, in order. It reads the
// quoting of SQL: a doubled quote stays inside its string; a backslash
// escapes in a MySQL string and in a PostgreSQL E string; a PostgreSQL dollar
// quote ($$...$$, $tag$...$tag$) ends at its own tag. An unterminated quote
// or block comment runs to the end of the text. It is the one reading of
// statement boundaries of the inline query of a SQL client: the shortened
// twin (sqlQueryShortened) and the statement split (sqlStatements) share it.
func sqlSpans(engine, query string, visit func(kind sqlSpanKind, start, end int)) {
	noBackslash := false
	statementStart := 0
	for i := 0; i < len(query); {
		c := query[i]
		switch {
		case c == '\'' || c == '"' || c == '`' || c == '[' && engine == "sqlserver":
			if c == '[' {
				end := sqlBracketEnd(query, i)
				visit(sqlSpanQuoted, i, end)
				i = end
				continue
			}
			backslash := engine == "mysql" && c != '`' && !noBackslash ||
				engine == "postgresql" && c == '\'' && i > 0 &&
					(query[i-1] == 'E' || query[i-1] == 'e') &&
					(i < 2 || !isSQLASTWordByte(query[i-2]))
			end := sqlQuotedEnd(query, i, c, backslash)
			visit(sqlSpanQuoted, i, end)
			i = end
		case c == '$' && engine == "postgresql":
			tag, ok := sqlDollarTag(query[i:])
			if !ok {
				visit(sqlSpanByte, i, i+1)
				i++
				continue
			}
			end := len(query)
			if close := strings.Index(query[i+len(tag):], tag); close >= 0 {
				end = i + len(tag) + close + len(tag)
			}
			visit(sqlSpanQuoted, i, end)
			i = end
		case c == '-' && strings.HasPrefix(query[i:], "--") &&
			(engine != "mysql" || i+2 < len(query) && query[i+2] <= ' '):
			end := len(query)
			if newline := strings.IndexAny(query[i:], "\r\n"); newline >= 0 {
				end = i + newline
			}
			visit(sqlSpanComment, i, end)
			i = end
		case c == '#' && engine == "mysql":
			end := len(query)
			if newline := strings.IndexAny(query[i:], "\r\n"); newline >= 0 {
				end = i + newline
			}
			visit(sqlSpanComment, i, end)
			i = end
		case c == '/' && strings.HasPrefix(query[i:], "/*"):
			if engine == "mysql" {
				if close := strings.Index(query[i+2:], "*/"); close >= 0 {
					end := i + 2 + close + 2
					if body, ok := sqlMySQLExecutableCommentBody(query, i, end); ok {
						visit(sqlSpanByte, body, end-2)
						i = end
						continue
					}
				}
			}
			depth, end := 1, i+2
			for end < len(query) && depth > 0 {
				switch {
				case strings.HasPrefix(query[end:], "/*") && (engine == "postgresql" || engine == "sqlserver"):
					depth++
					end += 2
				case strings.HasPrefix(query[end:], "*/"):
					depth--
					end += 2
				default:
					end++
				}
			}
			visit(sqlSpanComment, i, end)
			i = end
		case c == ';':
			visit(sqlSpanEnd, i, i+1)
			if engine == "mysql" {
				if mode, ok := sqlMySQLBackslashMode(query[statementStart:i]); ok {
					noBackslash = !mode
				}
			}
			i++
			statementStart = i
		default:
			visit(sqlSpanByte, i, i+1)
			i++
		}
	}
}

// sqlMySQLExecutableCommentBody gives the SQL body of a balanced MySQL or
// MariaDB executable comment. The existing mutation grammar validates the
// whole statement; the span reader must keep the body as code.
func sqlMySQLExecutableCommentBody(query string, start, end int) (int, bool) {
	body := start + 3
	if strings.HasPrefix(query[start:end], "/*M!") {
		body = start + 4
	} else if !strings.HasPrefix(query[start:end], "/*!") {
		return 0, false
	}
	for body < end-2 && query[body] >= '0' && query[body] <= '9' {
		body++
	}
	return body, body < end-2
}

// sqlMySQLBackslashMode reads a literal session SQL mode assignment. Dynamic
// assignments retain the server default interpretation until a later literal
// assignment is known. true means the usual backslash escape mode.
func sqlMySQLBackslashMode(statement string) (bool, bool) {
	left, right, assigned := strings.Cut(strings.TrimSpace(statement), "=")
	if !assigned {
		return false, false
	}
	switch strings.ToUpper(strings.Join(strings.Fields(left), " ")) {
	case "SET SQL_MODE", "SET SESSION SQL_MODE", "SET @@SESSION.SQL_MODE":
	default:
		return false, false
	}
	right = strings.TrimSpace(right)
	if len(right) < 2 || right[0] != '\'' || right[len(right)-1] != '\'' {
		return false, false
	}
	for _, mode := range strings.Split(strings.ToUpper(right[1:len(right)-1]), ",") {
		if strings.TrimSpace(mode) == "NO_BACKSLASH_ESCAPES" {
			return false, true
		}
	}
	return true, true
}

func sqlBracketEnd(query string, start int) int {
	for i := start + 1; i < len(query); i++ {
		if query[i] != ']' {
			continue
		}
		if i+1 < len(query) && query[i+1] == ']' {
			i++
			continue
		}
		return i + 1
	}
	return len(query)
}

// sqlQueryShortened is query with each quoted literal or identifier and each
// comment longer than stubKeepBytes shortened, and the offsets in the result
// just after each semicolon that ends a statement (sqlSpans).
func sqlQueryShortened(engine, query string) (string, []int) {
	var out strings.Builder
	var ends []int
	sqlSpans(engine, query, func(kind sqlSpanKind, start, end int) {
		part := query[start:end]
		switch {
		case kind == sqlSpanQuoted && len(part) > stubKeepBytes:
			if part[0] == '$' {
				tag, _ := sqlDollarTag(part)
				out.WriteString(tag + "x" + tag)
			} else {
				close := part[0]
				if close == '[' {
					close = ']'
				}
				out.WriteString(string(part[0]) + "x" + string(close))
			}
		case kind == sqlSpanComment && len(part) > stubKeepBytes:
			out.WriteByte(' ')
		default:
			out.WriteString(part)
		}
		if kind == sqlSpanEnd {
			ends = append(ends, out.Len())
		}
	})
	return out.String(), ends
}

// sqlStatement is one statement of an inline query: its text as written
// (comments kept, for the exact readers that remove them themselves) and
// its words in upper case with comments removed (for the transaction
// reading).
type sqlStatement struct {
	text  string
	words []string
}

// sqlStatements is query cut at each semicolon that ends a statement
// (sqlSpans: never inside a quote, a dollar quote or a comment), each
// statement trimmed; a statement of only space and comments is left out. At
// most maxSQLASTStatements are read; capped reports that more were left
// unread.
func sqlStatements(engine, query string) (statements []sqlStatement, capped bool, danger []sqlStatement, unreadDanger bool) {
	start, content := 0, false
	var bare strings.Builder
	flush := func(end int) {
		if content {
			if len(statements) == maxSQLASTStatements {
				capped = true
				// A statement past the cap with a danger keyword is read
				// alone (the unpadded cell, GAP-2122), within its budget.
				if text := strings.TrimSpace(query[start:end]); sqlDangerStatement(engine, text) {
					if len(danger) == maxSQLDangerReadings {
						unreadDanger = true
					} else {
						danger = append(danger, sqlStatement{text: text, words: strings.Fields(strings.ToUpper(bare.String()))})
					}
				}
			} else {
				statements = append(statements, sqlStatement{
					text:  strings.TrimSpace(query[start:end]),
					words: strings.Fields(strings.ToUpper(bare.String())),
				})
			}
		}
		bare.Reset()
		content = false
	}
	sqlSpans(engine, query, func(kind sqlSpanKind, spanStart, spanEnd int) {
		switch kind {
		case sqlSpanEnd:
			flush(spanStart)
			start = spanEnd
		case sqlSpanComment:
			bare.WriteByte(' ')
		default:
			part := query[spanStart:spanEnd]
			if strings.TrimSpace(part) != "" {
				content = true
			}
			bare.WriteString(part)
		}
	})
	flush(len(query))
	return statements, capped, danger, unreadDanger
}

// sqlQuotedEnd is the offset just after the quote that closes the quoted
// text opening at query[start], len(query) when none does.
func sqlQuotedEnd(query string, start int, quote byte, backslash bool) int {
	for i := start + 1; i < len(query); i++ {
		switch {
		case backslash && query[i] == '\\':
			i++
		case query[i] == quote && i+1 < len(query) && query[i+1] == quote:
			i++
		case query[i] == quote:
			return i + 1
		}
	}
	return len(query)
}

// sqlDollarTag is the opening tag of a PostgreSQL dollar quote at the start
// of text ($$ or $name$), false for a parameter ($1) or a lone dollar.
func sqlDollarTag(text string) (string, bool) {
	for i := 1; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '$':
			return text[:i+1], true
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 1 && c >= '0' && c <= '9' || c >= 0x80:
		default:
			return "", false
		}
	}
	return "", false
}
