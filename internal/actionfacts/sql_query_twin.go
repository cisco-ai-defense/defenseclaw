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

// sqlQueryWordTwin is the stand-in, single-quoted for the shell, of the
// inline query of a SQL client that is past the shell word bound. A quoted
// literal, a quoted identifier and a comment past stubKeepBytes are data in
// the grammar of SQL, as a data word is to the shell: each is shortened with
// its quoting (sqlQueryShortened), so every statement keeps its shape and the
// SQL readers judge it as the same query with short literals. When the query
// is still past the bound it is cut after its last complete statement
// within the bound; the statements past the cut are not read, and the call
// keeps the truncation record (DET111 ruling on FIX-T20B: the cut is
// recorded and raises nothing by itself; a rule that matches inside the kept
// statements fires). A query with no complete statement within the bound
// leaves the stand-in x, as a data word does.
func sqlQueryWordTwin(word sqlQueryWord, value string) string {
	option := ""
	if word.glued {
		name, query, _ := strings.Cut(value, "=")
		option, value = name+"=", query
	}
	query, ends := sqlQueryShortened(word.engine, value)
	if len(option)+len(query) > maxScalarBytes {
		kept := ""
		for _, end := range ends {
			if len(option)+end > maxScalarBytes {
				break
			}
			kept = query[:end]
		}
		query = kept
	}
	// A shortened comment leaves a space; at either end of the query it is
	// no part of a statement, and the exact readers refuse a query with
	// surrounding space.
	if query = strings.TrimSpace(query); query == "" {
		query = "x"
	}
	return posixSingleQuoted(option + query)
}

// sqlQueryShortened is query with each quoted literal or identifier and each
// comment longer than stubKeepBytes shortened, and the offsets in the result
// just after each semicolon that ends a statement. It reads the quoting of
// SQL: a doubled quote stays inside its string; a backslash escapes in a
// MySQL string and in a PostgreSQL E string; a PostgreSQL dollar quote
// ($$...$$, $tag$...$tag$) ends at its own tag. An unterminated quote runs
// to the end of the text.
func sqlQueryShortened(engine, query string) (string, []int) {
	var out strings.Builder
	var ends []int
	keep := func(part, short string) {
		if len(part) > stubKeepBytes {
			out.WriteString(short)
			return
		}
		out.WriteString(part)
	}
	for i := 0; i < len(query); {
		c := query[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			backslash := engine == "mysql" && c != '`' ||
				c == '\'' && i > 0 && (query[i-1] == 'E' || query[i-1] == 'e') && (i < 2 || !isSQLASTWordByte(query[i-2]))
			end := sqlQuotedEnd(query, i, c, backslash)
			keep(query[i:end], string(c)+"x"+string(c))
			i = end
		case c == '$' && engine == "postgresql":
			tag, ok := sqlDollarTag(query[i:])
			if !ok {
				out.WriteByte(c)
				i++
				continue
			}
			end := len(query)
			if close := strings.Index(query[i+len(tag):], tag); close >= 0 {
				end = i + len(tag) + close + len(tag)
			}
			keep(query[i:end], tag+"x"+tag)
			i = end
		case c == '-' && strings.HasPrefix(query[i:], "--"):
			end := len(query)
			if newline := strings.IndexByte(query[i:], '\n'); newline >= 0 {
				end = i + newline
			}
			keep(query[i:end], " ")
			i = end
		case c == '/' && strings.HasPrefix(query[i:], "/*"):
			end := len(query)
			if close := strings.Index(query[i+2:], "*/"); close >= 0 {
				end = i + 2 + close + 2
			}
			keep(query[i:end], " ")
			i = end
		case c == ';':
			out.WriteByte(c)
			ends = append(ends, out.Len())
			i++
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String(), ends
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
