// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import (
	"regexp"
	"strings"
)

// SQL statement classes. A statement may carry more than one class.
const (
	SQLDrop       = "drop"              // DROP TABLE / DATABASE / SCHEMA / INDEX / VIEW / USER / ROLE
	SQLTruncate   = "truncate"          // TRUNCATE
	SQLDeleteAll  = "delete_all"        // DELETE with no WHERE, or a WHERE that is always true
	SQLPrivilege  = "privilege"         // GRANT, a role or admin flag set to admin, a superuser role
	SQLAuditOff   = "audit_off"         // an audit, logging, rotation or mfa setting switched off
	SQLCredential = "credential_change" // a password or secret column set
)

// SQLClass is one class found in a statement.
type SQLClass struct {
	Class string
}

const ident = "[^\\s;(),]+"

var (
	reDrop      = regexp.MustCompile(`(?i)^\s*drop\s+(?:table|database|schema|index|view|user|role|materialized\s+view)\s+(?:if\s+exists\s+)?` + ident + `(?:\s+on\s+` + ident + `)?(?:\s*,\s*` + ident + `)*(?:\s+(?:cascade|restrict))?\s*$`)
	reTruncate  = regexp.MustCompile(`(?i)^\s*truncate\s+(?:table\s+)?(?:only\s+)?` + ident + `(?:\s*,\s*` + ident + `)*(?:\s+(?:restart|continue)\s+identity)?(?:\s+(?:cascade|restrict))?\s*$`)
	reDelete    = regexp.MustCompile(`(?i)^\s*delete\s+from\s+(?:only\s+)?` + ident + `\s*(.*)$`)
	reWhere     = regexp.MustCompile(`(?is)^where\s+(.*)$`)
	reAlways    = regexp.MustCompile(`(?is)^\(*\s*(?:1\s*=\s*1|true|1|'[^']*'\s*=\s*'[^']*'|\w+\s*=\s*\w+|not\s+false)\s*\)*\s*(?:;|$)`)
	reOrAlways  = regexp.MustCompile(`(?is)\bor\s+\(*\s*(?:1\s*=\s*1|true|'[^']*'\s*=\s*'[^']*')\s*\)*\s*(?:;|$)`)
	reGrant     = regexp.MustCompile(`(?i)^\s*grant\s+(?:all(?:\s+privileges)?|select|insert|update|delete|create|alter|drop|execute|usage|references|trigger|truncate|super|\w+\s+option)(?:\s*\([^)]*\))?(?:\s*,\s*\w+)*\s+on\s+\S|^\s*grant\s+(?:admin|administrator|superuser|sysadmin|dba|root|owner|rds_superuser|cloudsqlsuperuser)\s+to\s+\S`)
	reAlterRole = regexp.MustCompile(`(?i)^\s*alter\s+(?:user|role)\s+\S+.*\b(?:superuser|createrole|createdb|replication|bypassrls)\b`)
	reUpdate    = regexp.MustCompile(`(?is)^\s*update\s+(?:only\s+)?([^\s;(,]+)\s+set\s+(.*)$`)
	rePrivSet   = regexp.MustCompile(`(?i)\b(?:user_)?roles?\s*=\s*'?(?:admin|administrator|superuser|root|owner|sysadmin)'?|\b(?:is_)?(?:admin|superuser|sudo|staff)\s*=\s*(?:true|1|'t'|'true'|'yes')|\b(?:permissions?|privileges?|access_level|scope)\s*=\s*'?(?:admin|all|\*|full|write|superuser)'?`)
	reOff       = `(?:false|0|'false'|'0'|'off'|'no'|'none'|null)`
	reOffSet    = regexp.MustCompile(`(?i)\b\w*(?:enabled|active|enforced|required)\s*=\s*` + reOff + `|\b(?:mfa|two_factor|2fa)\w*\s*=\s*` + reOff)
	reOffTable  = regexp.MustCompile(`(?i)audit|logging|log_config|rotation|retention|mfa|two_factor|2fa|security|auth_config|password_policy`)
	reCredSet   = regexp.MustCompile(`(?i)\b(?:password|passwd|password_hash|pwd|api_key|secret|token)\w*\s*=`)
	reCredTable = regexp.MustCompile(`(?i)users?|accounts?|credentials?|logins?|admins?|members?`)
	reWith      = regexp.MustCompile(`(?i)^\s*with\b`)
	reMainVerb  = regexp.MustCompile(`(?i)^\s*(?:delete|update|insert|select|merge|drop|truncate|grant)\b`)
)

// ClassifySQL reads the statements of sql (split on ";" outside quotes,
// comments removed, a leading WITH skipped) and returns the classes that
// matter for the guardrail. It reads text only; it does not prove that a
// statement runs, and a caller decides whether a tool is a database surface.
// A statement is read under both quoting rules (standard SQL, and MySQL where
// a backslash escapes a quote), and the classes of either reading count.
func ClassifySQL(sql string) []SQLClass {
	var out []SQLClass
	seen := map[string]bool{}
	for _, backslash := range []bool{false, true} {
		for _, stmt := range splitSQL(stripSQLComments(sql), backslash) {
			for _, c := range classifyStatement(skipCTE(stmt)) {
				if !seen[c.Class] {
					seen[c.Class] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// skipCTE returns the main statement of one that starts with WITH: the text
// after the last parenthesised common table expression.
func skipCTE(stmt string) string {
	if !reWith.MatchString(stmt) {
		return stmt
	}
	depth := 0
	var quote byte
	for i := 0; i < len(stmt); i++ {
		c := stmt[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				rest := strings.TrimLeft(stmt[i+1:], " \t\r\n")
				if strings.HasPrefix(rest, ",") {
					continue
				}
				if reMainVerb.MatchString(rest) {
					return strings.TrimSpace(stmt[i+1:])
				}
			}
		}
	}
	return stmt
}

func classifyStatement(stmt string) []SQLClass {
	var out []SQLClass
	if reDrop.MatchString(stmt) {
		out = append(out, SQLClass{Class: SQLDrop})
	}
	if reTruncate.MatchString(stmt) {
		out = append(out, SQLClass{Class: SQLTruncate})
	}
	if m := reDelete.FindStringSubmatch(stmt); m != nil && unbounded(dropAlias(strings.TrimSpace(m[1]))) {
		out = append(out, SQLClass{Class: SQLDeleteAll})
	}
	if reGrant.MatchString(stmt) || reAlterRole.MatchString(stmt) {
		out = append(out, SQLClass{Class: SQLPrivilege})
	}
	if m := reUpdate.FindStringSubmatch(stmt); m != nil {
		table, set := strings.ToLower(strings.Trim(m[1], "`\"[]'")), m[2]
		if i := indexWhere(set); i >= 0 {
			set = set[:i]
		}
		switch {
		case rePrivSet.MatchString(set):
			out = append(out, SQLClass{Class: SQLPrivilege})
		case reOffSet.MatchString(set) && (reOffTable.MatchString(table) || reOffTable.MatchString(set)):
			out = append(out, SQLClass{Class: SQLAuditOff})
		case reCredSet.MatchString(set) && reCredTable.MatchString(table):
			out = append(out, SQLClass{Class: SQLCredential})
		}
	}
	return out
}

// dropAlias removes a table alias (t, AS t) from the tail of a DELETE.
func dropAlias(tail string) string {
	words := strings.Fields(tail)
	if len(words) == 0 {
		return tail
	}
	switch strings.ToLower(strings.TrimRight(words[0], ";")) {
	case "where", "using", "returning":
		return tail
	case "as":
		if len(words) >= 2 {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(tail, words[0])), words[1]))
		}
	}
	return strings.TrimSpace(strings.TrimPrefix(tail, words[0]))
}

// unbounded reports the tail of a DELETE that removes every row: nothing, or a
// WHERE that is always true.
func unbounded(tail string) bool {
	tail = strings.TrimRight(tail, "; \t\r\n")
	if tail == "" {
		return true
	}
	m := reWhere.FindStringSubmatch(tail)
	if m == nil {
		return false
	}
	cond := strings.TrimSpace(m[1])
	return reAlways.MatchString(cond) || reOrAlways.MatchString(cond)
}

var reWhereWord = regexp.MustCompile(`(?i)\bwhere\b`)

func indexWhere(s string) int {
	if loc := reWhereWord.FindStringIndex(s); loc != nil {
		return loc[0]
	}
	return -1
}

// stripSQLComments removes -- and /* */ comments outside quotes. The body of
// a MySQL executable comment (/*! ... */, /*!50000 ... */) is SQL, so it is
// kept and only its markers are dropped.
func stripSQLComments(s string) string {
	var b strings.Builder
	var quote byte
	exec := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
			b.WriteByte(c)
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case c == '/' && i+2 < len(s) && s[i+1] == '*' && s[i+2] == '!':
			i += 2
			for i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				i++
			}
			exec = true
			b.WriteByte(' ')
		case exec && c == '*' && i+1 < len(s) && s[i+1] == '/':
			i++
			exec = false
			b.WriteByte(' ')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 3
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// splitSQL splits on ";" outside quotes. With backslash set, a backslash
// inside a quote escapes the next character (MySQL).
func splitSQL(s string, backslash bool) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if backslash && c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == ';':
			if t := strings.TrimSpace(s[start:i]); t != "" {
				out = append(out, t)
			}
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}
