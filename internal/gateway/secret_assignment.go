// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
)

// secretAssignmentRuleID is the generic credential-in-assignment rule. The
// provider-prefixed SEC-* rules recognise a token by its issuer prefix; this
// rule recognises the rest by the context a person writes around one: a
// credential-named key, a separator, and a value that is random-looking.
const secretAssignmentRuleID = "SEC-SECRET-ASSIGN"

// secretAssignmentParts splits a SEC-SECRET-ASSIGN candidate into the key
// prefix words, the credential keyword, the key suffix words and the value.
// It mirrors the rule pattern in policies/guardrail/*/rules/secrets.yaml.
var secretAssignmentParts = regexp.MustCompile(
	`(?i)^\W?((?:[a-z0-9]+[_-])*)(password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|private[_-]?key|encryption[_-]?key|signing[_-]?key|credential)s?((?:[_-][a-z0-9]+)*)` +
		`\\*["']?\s*(?:[:=,(]|\s+is\s+|=>)\s*\\*["']?(.+)$`)

// secretAssignmentKeySuffixes are words after the credential keyword that
// make the key describe the credential rather than hold it: token_count,
// password_field, secret_name, api_key_header.
var secretAssignmentKeySuffixes = map[string]bool{
	"count": true, "type": true, "types": true, "length": true, "len": true, "min": true, "max": true,
	"field": true, "fields": true, "name": true, "names": true, "header": true, "headers": true,
	"ttl": true, "expiry": true, "expires": true, "expiration": true, "policy": true, "file": true,
	"path": true, "id": true, "label": true, "prefix": true, "suffix": true, "endpoint": true,
	"url": true, "uri": true, "ref": true, "regex": true, "pattern": true, "env": true, "var": true,
	"variable": true, "param": true, "params": true, "arn": true, "version": true, "rotation": true,
	"required": true, "enabled": true, "disabled": true, "hint": true, "help": true, "placeholder": true,
	"format": true, "mask": true, "masked": true, "input": true, "prompt": true, "manager": true,
	"store": true, "provider": true, "source": true, "location": true, "dir": true, "directory": true,
	"hash": true, "hashed": true, "salt": true, "rules": true, "strength": true, "reset": true,
}

// secretAssignmentKeyPrefixes are words before the keyword that mark a
// setting or an identifier, not a credential value: max_tokens, num_tokens,
// is_secret.
var secretAssignmentKeyPrefixes = map[string]bool{
	"max": true, "min": true, "num": true, "total": true, "prompt": true, "completion": true,
	"input": true, "output": true, "is": true, "has": true, "use": true, "enable": true,
	"disable": true, "require": true, "show": true, "hide": true, "get": true, "set": true,
	"confirm": true, "reset": true, "forgot": true, "change": true, "update": true,
	"invalid": true, "wrong": true, "bad": true, "missing": true, "empty": true, "no": true,
	"next": true, "page": true,
}

// secretAssignmentPlaceholderTokens mark a value as a stand-in a person wrote
// on purpose. A leaked credential does not announce itself. A word counts
// only as a whole token of the value (split at _ - .), with or without digits
// around it, or as most of a longer token (examplekey); never as a few letters
// inside a random run.
var secretAssignmentPlaceholderTokens = map[string]bool{
	"example": true, "sample": true, "placeholder": true, "changeme": true, "replace": true, "dummy": true,
	"fake": true, "mock": true, "redacted": true, "your": true, "yourtoken": true, "yoursecret": true,
	"todo": true, "fixme": true, "insert": true, "enter": true, "notreal": true, "testtest": true,
	"foobar": true, "lorem": true, "password123": true, "secret123": true, "abc123": true, "qwerty": true,
	"letmein": true, "hunter2": true,
}

// secretAssignmentPlaceholderValue reports a value that is a stand-in.
func secretAssignmentPlaceholderValue(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "xxxx") {
		return true
	}
	tokens := strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	candidates := make([]string, 0, 2*len(tokens))
	candidates = append(candidates, tokens...)
	for i := 0; i+1 < len(tokens); i++ {
		candidates = append(candidates, tokens[i]+tokens[i+1]) // change_me, not_real
	}
	for _, token := range candidates {
		if secretAssignmentPlaceholderTokens[token] || secretAssignmentPlaceholderTokens[strings.Trim(token, "0123456789")] {
			return true
		}
		for word := range secretAssignmentPlaceholderTokens {
			if len(word) >= 5 && strings.Contains(token, word) && len(word)*10 >= len(token)*6 {
				return true
			}
		}
	}
	return false
}

var (
	secretAssignmentVarRef  = regexp.MustCompile(`^\$\{|^\$\(|^\$[A-Z_][A-Z0-9_]*$|^%[A-Za-z_]+%$|^\{\{|^<|^@[A-Za-z_]+`)
	secretAssignmentCodeRef = regexp.MustCompile(`(?i)^(?:process\.env|os\.environ|os\.getenv|system\.getenv|env\[|getenv|config\.|settings\.|self\.|this\.|secrets?\.|vault:|ref\+|aws:|arn:|kms:|op://)`)
	secretAssignmentDotted  = regexp.MustCompile(`^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$`)
	// snake_case and kebab-case identifiers are names, not generated secrets.
	secretAssignmentIdent = regexp.MustCompile(`^[a-z]+(?:[_-][a-z0-9]+){2,}$`)
)

// acceptedSecretAssignment reports whether a SEC-SECRET-ASSIGN candidate is a
// credential value and not a name, a reference, a placeholder or an example.
// It is the precision stage of the rule: the regex only finds the assignment.
func acceptedSecretAssignment(match string) bool {
	m := secretAssignmentParts.FindStringSubmatch(strings.TrimSpace(match))
	if m == nil {
		return false
	}
	split := func(r rune) bool { return r == '_' || r == '-' }
	for _, word := range strings.FieldsFunc(strings.ToLower(m[1]), split) {
		if secretAssignmentKeyPrefixes[word] {
			return false
		}
	}
	for _, word := range strings.FieldsFunc(strings.ToLower(m[3]), split) {
		if secretAssignmentKeySuffixes[word] {
			return false
		}
	}
	return secretAssignmentValueLooksSecret(m[4])
}

func secretAssignmentValueLooksSecret(raw string) bool {
	value := strings.TrimSpace(raw)
	// The value runs to the first character a secret does not use.
	if end := strings.IndexFunc(value, func(r rune) bool {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		return !letterOrDigit && !strings.ContainsRune("_-+/.!@#$%^&*~", r)
	}); end >= 0 {
		// A name followed by "(" is a call, not a value.
		if value[end] == '(' {
			return false
		}
		value = value[:end]
	}
	value = strings.TrimRight(value, ".,;!=")
	if len(value) < 12 || len(value) > 128 {
		return false
	}
	if secretAssignmentVarRef.MatchString(value) || secretAssignmentCodeRef.MatchString(value) {
		return false
	}
	if secretAssignmentPlaceholderValue(value) {
		return false
	}
	if obviousCredentialPlaceholder(value) {
		return false
	}
	// A path, a host name or a file name is not a secret.
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "~") ||
		strings.Contains(value, "//") || secretAssignmentDotted.MatchString(value) || secretAssignmentIdentifier(value) {
		return false
	}
	// A value built from short underscore- or dash-separated pieces
	// (0nscience_count, max-retry-3) is a name or a phrase. A generated token
	// with separators still carries one long random piece.
	if segments := strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '-' }); len(segments) > 1 {
		longest := 0
		for _, segment := range segments {
			longest = max(longest, len(segment))
		}
		if longest < 10 {
			return false
		}
	}
	// A value made mostly of words (SalesDemo2026, Password.123) is a phrase
	// a person chose, not a generated secret: a generated one has no long
	// run of letters. Words of five letters or more count against it.
	wordLetters, run := 0, 0
	for _, r := range value + " " {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			run++
			continue
		}
		if run >= 5 {
			wordLetters += run
		}
		run = 0
	}
	if wordLetters*10 >= len(value)*6 {
		return false
	}
	var letters, upper, lowerCount, digits, symbols int
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			letters++
			lowerCount++
		case r >= 'A' && r <= 'Z':
			letters++
			upper++
		case r >= '0' && r <= '9':
			digits++
		default:
			symbols++
		}
	}
	// Names, words and identifiers carry no digit; a secret a person or a
	// tool generated mixes letters and digits.
	if letters == 0 || digits == 0 {
		return false
	}
	classes := 0
	for _, n := range []int{lowerCount, upper, digits, symbols} {
		if n > 0 {
			classes++
		}
	}
	if classes < 2 || (classes == 2 && len(value) < 16) {
		return false
	}
	return credentialEntropy(value) >= 3.0
}

// secretAssignmentIdentifier reports a snake_case or kebab-case name made of
// short words (get_password_from_vault2, max-retry-count3). A generated token
// that happens to carry such separators (dd_api_7f8a9b0c1d2e3f4a5b6c) has a
// long random segment, which is what tells it apart.
func secretAssignmentIdentifier(value string) bool {
	if !secretAssignmentIdent.MatchString(value) {
		return false
	}
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '-' }) {
		if len(segment) > 8 {
			return false
		}
	}
	return true
}

// secretAssignmentWholeReference matches a value that is one reference to a
// variable or a template slot and nothing else: ${DB_PASSWORD}, $DB_PASSWORD,
// %DB_PASSWORD%, {{ db_password }}, <password>, $(vault read x). A reference
// in front of literal characters (${X} followed by a password) is a password,
// not a slot.
var secretAssignmentWholeReference = regexp.MustCompile(
	`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^{}]*\}\}|<[A-Za-z_][A-Za-z0-9_-]*>|\$\([^()]*\))$`)

// jsonStringDecoded undoes the JSON string escapes that decide where a line
// starts or a quote closes (backslash n, r, t, quote, backslash, slash), so
// text taken from the arguments of a call reads as the person or the tool
// wrote it. A rule that anchors on a word boundary (SEC-SECRET-ASSIGN) cannot
// see a key that follows the two characters backslash and n.
func jsonStringDecoded(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"', '\\', '/':
			b.WriteByte(s[i+1])
		default:
			b.WriteByte(s[i])
			continue
		}
		i++
	}
	return b.String()
}
