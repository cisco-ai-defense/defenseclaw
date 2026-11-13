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
	SQLDeleteAll  = "delete_all"        // DELETE with no WHERE
	SQLPrivilege  = "privilege"         // GRANT, a role or admin flag set to admin, a superuser role
	SQLAuditOff   = "audit_off"         // an audit, logging, rotation or mfa setting switched off
	SQLCredential = "credential_change" // a password or secret column set
)

// SQLClass is one class found in a statement. Object is the first object
// name after the verb (lower-case, may be empty). Database is true for a
// DROP of a database or schema.
type SQLClass struct {
	Class    string
	Object   string
	Database bool
}

var (
	reDrop      = regexp.MustCompile(`(?i)^\s*drop\s+(table|database|schema|index|view|user|role|materialized\s+view)\s+(?:if\s+exists\s+)?([^\s;(,]+)`)
	reTruncate  = regexp.MustCompile(`(?i)^\s*truncate\s+(?:table\s+)?(?:only\s+)?([^\s;(,]+)`)
	reDelete    = regexp.MustCompile(`(?i)^\s*delete\s+from\s+([^\s;(,]+)`)
	reWhere     = regexp.MustCompile(`(?i)\bwhere\b`)
	reGrant     = regexp.MustCompile(`(?i)^\s*grant\b`)
	reAlterRole = regexp.MustCompile(`(?i)^\s*alter\s+(?:user|role)\b.*\b(?:superuser|createrole|createdb|replication|bypassrls)\b`)
	reUpdate    = regexp.MustCompile(`(?is)^\s*update\s+([^\s;(,]+)\s+set\s+(.*)$`)
	rePrivSet   = regexp.MustCompile(`(?i)\b(?:user_)?roles?\s*=\s*'?(?:admin|administrator|superuser|root|owner|sysadmin)'?|\b(?:is_)?(?:admin|superuser|sudo|staff)\s*=\s*(?:true|1|'t'|'true'|'yes')|\b(?:permissions?|privileges?|access_level|scope)\s*=\s*'?(?:admin|all|\*|full|write|superuser)'?`)
	reOffSet    = regexp.MustCompile(`(?i)\b(?:enabled|is_enabled|active|enforce\w*|rotation_enabled|audit\w*|logging\w*|mfa\w*|two_factor\w*|2fa\w*)\s*=\s*(?:false|0|'false'|'0'|'off'|'no'|'none'|null)`)
	reOffTable  = regexp.MustCompile(`(?i)audit|logging|log_config|rotation|retention|mfa|two_factor|2fa|security|auth_config|password_policy`)
	reCredSet   = regexp.MustCompile(`(?i)\b(?:password|passwd|password_hash|pwd|api_key|secret|token)\w*\s*=`)
	reCredTable = regexp.MustCompile(`(?i)users?|accounts?|credentials?|logins?|admins?|members?`)
)

// ClassifySQL reads the statements of sql (split on ";" outside quotes,
// comments removed) and returns the classes that matter for the guardrail.
// It reads text only; it does not prove that a statement runs.
func ClassifySQL(sql string) []SQLClass {
	var out []SQLClass
	for _, stmt := range splitSQL(stripSQLComments(sql)) {
		out = append(out, classifyStatement(stmt)...)
	}
	return out
}

func classifyStatement(stmt string) []SQLClass {
	var out []SQLClass
	if m := reDrop.FindStringSubmatch(stmt); m != nil {
		kind := strings.ToLower(m[1])
		out = append(out, SQLClass{Class: SQLDrop, Object: object(m[2]), Database: kind == "database" || kind == "schema"})
	}
	if m := reTruncate.FindStringSubmatch(stmt); m != nil {
		out = append(out, SQLClass{Class: SQLTruncate, Object: object(m[1])})
	}
	if m := reDelete.FindStringSubmatch(stmt); m != nil && !reWhere.MatchString(stmt) {
		out = append(out, SQLClass{Class: SQLDeleteAll, Object: object(m[1])})
	}
	if reGrant.MatchString(stmt) || reAlterRole.MatchString(stmt) {
		out = append(out, SQLClass{Class: SQLPrivilege})
	}
	if m := reUpdate.FindStringSubmatch(stmt); m != nil {
		table, set := object(m[1]), m[2]
		if i := indexWhere(set); i >= 0 {
			set = set[:i]
		}
		switch {
		case rePrivSet.MatchString(set):
			out = append(out, SQLClass{Class: SQLPrivilege, Object: table})
		case reOffSet.MatchString(set) && (reOffTable.MatchString(table) || reOffTable.MatchString(set)):
			out = append(out, SQLClass{Class: SQLAuditOff, Object: table})
		case reCredSet.MatchString(set) && reCredTable.MatchString(table):
			out = append(out, SQLClass{Class: SQLCredential, Object: table})
		}
	}
	return out
}

func indexWhere(s string) int {
	if loc := reWhere.FindStringIndex(s); loc != nil {
		return loc[0]
	}
	return -1
}

func object(s string) string {
	return strings.ToLower(strings.Trim(s, "`\"[]'"))
}

// stripSQLComments removes -- and /* */ comments outside quotes.
func stripSQLComments(s string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == quote {
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

// splitSQL splits on ";" outside quotes.
func splitSQL(s string) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
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
