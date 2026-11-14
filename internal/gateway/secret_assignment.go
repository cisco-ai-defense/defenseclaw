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
// identifier and the value. The rule pattern in
// policies/guardrail/*/rules/secrets.yaml finds an identifier that holds a
// credential keyword anywhere in it; the words of the identifier decide
// (secretAssignmentKeyIsCredential).
var secretAssignmentParts = regexp.MustCompile(
	`^\W?([A-Za-z0-9_-]+)\\*["']?\s*([:=,(]|\s+is\s+|=>)\s*\\*["']?(.+)$`)

// secretAssignmentKeywords are the words, joined, that name a credential.
var secretAssignmentKeywords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true, "secret": true, "token": true,
	"apikey": true, "privatekey": true, "encryptionkey": true, "signingkey": true, "credential": true,
}

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

// secretAssignmentPlaceholderTokens are the words a stand-in value is made of.
// A leaked credential does not announce itself; a value is a placeholder only
// when it is made of nothing else (your_api_key_here_1234, changeme123,
// example_token_value), never because one of these words sits next to random
// characters.
var secretAssignmentPlaceholderTokens = map[string]bool{
	"example": true, "sample": true, "placeholder": true, "changeme": true, "replace": true, "dummy": true,
	"fake": true, "mock": true, "redacted": true, "your": true, "yourtoken": true, "yoursecret": true,
	"todo": true, "fixme": true, "insert": true, "enter": true, "notreal": true, "testtest": true,
	"foobar": true, "lorem": true, "password123": true, "secret123": true, "abc123": true, "qwerty": true,
	"letmein": true, "hunter2": true, "test": true,
}

// secretAssignmentFillerTokens may sit between placeholder words.
var secretAssignmentFillerTokens = map[string]bool{
	"api": true, "key": true, "token": true, "secret": true, "here": true, "value": true, "password": true,
	"id": true, "name": true, "goes": true, "the": true, "my": true, "a": true, "of": true, "to": true,
	"me": true, "change": true, "not": true, "real": true, "new": true, "old": true,
}

// secretAssignmentPlaceholderValue reports a value made only of placeholder
// and filler words, with at least one placeholder word, or of a run of x.
func secretAssignmentPlaceholderValue(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "xxxx") && strings.Trim(lower, "x0123456789_-.") == "" {
		return true
	}
	tokens := strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	sawPlaceholder := false
	for i := 0; i < len(tokens); i++ {
		token := strings.Trim(tokens[i], "0123456789")
		if token == "" {
			continue
		}
		if i+1 < len(tokens) && secretAssignmentPlaceholderTokens[token+strings.Trim(tokens[i+1], "0123456789")] {
			sawPlaceholder = true // change_me, not_real
			i++
			continue
		}
		switch {
		case secretAssignmentPlaceholderTokens[tokens[i]] || secretAssignmentPlaceholderTokens[token]:
			sawPlaceholder = true
		case secretAssignmentFillerTokens[token]:
		case secretAssignmentMostlyPlaceholderWord(token):
			sawPlaceholder = true
		default:
			return false
		}
	}
	return sawPlaceholder
}

// secretAssignmentMostlyPlaceholderWord reports one token that is a
// placeholder word with a short tail (examplekey, changemenow).
func secretAssignmentMostlyPlaceholderWord(token string) bool {
	for word := range secretAssignmentPlaceholderTokens {
		if len(word) >= 5 && strings.HasPrefix(token, word) && len(word)*10 >= len(token)*6 {
			return true
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
	if !secretAssignmentKeyIsCredential(m[1]) {
		return false
	}
	if passwordAssignmentKey(m[1]) && passwordAssignmentSeparator(m[2]) {
		return passwordAssignmentRejection(m[3]) == ""
	}
	return secretAssignmentValueLooksSecret(m[3])
}

// passwordAssignmentWords are the credential words of a password a person
// sets. A value assigned to one of them is the password itself, whatever it
// looks like: a short or word-like password is the one most worth reporting.
var passwordAssignmentWords = map[string]bool{"password": true, "passwd": true, "pwd": true, "passphrase": true}

// passwordAssignmentKey reports an identifier whose credential word is a
// password word (db_password, PASSWORD, userPwd).
func passwordAssignmentKey(key string) bool {
	for _, word := range identifierWords(key) {
		if passwordAssignmentWords[strings.TrimSuffix(word, "s")] {
			return true
		}
	}
	return false
}

// passwordAssignmentSeparator is the assignment of a value (password=x,
// password: x, "password" => x), not prose ("the password is required") or a
// call or list (password(x), password, x).
func passwordAssignmentSeparator(sep string) bool {
	switch strings.TrimSpace(sep) {
	case ":", "=", "=>":
		return true
	}
	return false
}

// passwordAssignmentRejection is secretAssignmentRejection for a password
// word: 8 to 128 characters, still not a reference, placeholder, path or
// name, and with a letter and a digit or symbol (a bare word or type name
// such as Optional is code, not a password). The generated-secret checks
// (word shape, character classes, entropy) do not apply (rel-1-0-10:GAP-0371;
// the proxy-only detector removed for GAP-0210 had the same bar).
func passwordAssignmentRejection(raw string) string {
	value := strings.TrimSpace(raw)
	if end := strings.IndexFunc(value, func(r rune) bool {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		return !letterOrDigit && !strings.ContainsRune("_-+/.!@#$%^&*~", r)
	}); end >= 0 {
		if value[end] == '(' {
			return "call"
		}
		value = value[:end]
	}
	value = strings.TrimRight(value, ".,;!=")
	if len(value) < 8 || len(value) > 128 {
		return "length"
	}
	if secretAssignmentVarRef.MatchString(value) || secretAssignmentCodeRef.MatchString(value) {
		return "reference"
	}
	if secretAssignmentPlaceholderValue(value) || obviousCredentialPlaceholder(value) {
		return "placeholder"
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "~") ||
		strings.Contains(value, "//") || secretAssignmentDotted.MatchString(value) || secretAssignmentIdentifier(value) {
		return "path-or-name"
	}
	letter, other := false, false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			letter = true
		} else {
			other = true
		}
	}
	if !letter || !other {
		return "no-digit"
	}
	return ""
}

// secretAssignmentKeyIsCredential reports an identifier that holds a credential
// and does not merely describe one. The identifier is cut into words at _ and
// -, at a lower to upper case change and before the last capital of an
// acronym (dbPassword, SECRET_KEY, apiKey, HTTPToken), so a name is read, not
// listed. One word, or two or three joined (api + key), must be a credential
// keyword; no other word of the identifier may mark a setting around it
// (max_tokens, token_count, isSecret).
func secretAssignmentKeyIsCredential(key string) bool {
	words := identifierWords(key)
	for i := range words {
		for j := i; j < len(words) && j < i+3; j++ {
			joined := strings.Join(words[i:j+1], "")
			if !secretAssignmentKeywords[strings.TrimSuffix(joined, "s")] && !secretAssignmentKeywords[joined] {
				continue
			}
			for _, word := range words[:i] {
				if secretAssignmentKeyPrefixes[word] {
					return false
				}
			}
			for _, word := range words[j+1:] {
				if secretAssignmentKeySuffixes[word] {
					return false
				}
			}
			return true
		}
	}
	return false
}

func secretAssignmentValueLooksSecret(raw string) bool {
	return secretAssignmentRejection(raw) == ""
}

// secretAssignmentRejection names the first check a candidate value fails, or
// returns "" for a value that looks like a generated secret.
func secretAssignmentRejection(raw string) string {
	value := strings.TrimSpace(raw)
	// The value runs to the first character a secret does not use.
	if end := strings.IndexFunc(value, func(r rune) bool {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		return !letterOrDigit && !strings.ContainsRune("_-+/.!@#$%^&*~", r)
	}); end >= 0 {
		// A name followed by "(" is a call, not a value.
		if value[end] == '(' {
			return "call"
		}
		value = value[:end]
	}
	value = strings.TrimRight(value, ".,;!=")
	if len(value) < 12 || len(value) > 128 {
		return "length"
	}
	if secretAssignmentVarRef.MatchString(value) || secretAssignmentCodeRef.MatchString(value) {
		return "reference"
	}
	if secretAssignmentPlaceholderValue(value) {
		return "placeholder"
	}
	if obviousCredentialPlaceholder(value) {
		return "placeholder"
	}
	// A path, a host name or a file name is not a secret.
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "~") ||
		strings.Contains(value, "//") || secretAssignmentDotted.MatchString(value) || secretAssignmentIdentifier(value) {
		return "path-or-name"
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
			return "pieces"
		}
	}
	// A value made mostly of words (SalesDemo2026, Password.123) is a phrase
	// a person chose, not a generated secret. A word is a stretch of letters of
	// one case shape with the vowel and consonant pattern of a word; a random
	// mix of upper and lower case, or of consonants alone, is not one.
	wordLetters := secretAssignmentWordLetters(value)
	if wordLetters*10 >= len(value)*6 {
		return "words"
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
		return "no-digit"
	}
	classes := 0
	for _, n := range []int{lowerCount, upper, digits, symbols} {
		if n > 0 {
			classes++
		}
	}
	if classes < 2 || (classes == 2 && len(value) < 16) {
		return "classes"
	}
	if credentialEntropy(value) < 3.0 {
		return "entropy"
	}
	return ""
}

// secretAssignmentWordLetters counts the letters of value that sit in
// word-shaped segments of four letters or more. A run of letters is cut where
// the case turns from lower to upper (BlueRiver) and before the last capital
// of a capital run followed by lower case (HTTPServer). A segment is
// word-shaped when it is all lower case, all upper case or one capital then
// lower case, a fifth to seven tenths of it are vowels (a, e, i, o, u, y), and
// no run of consonants is longer than four. This is a model of the shape of
// a word, not a list of words: a random password whose letters happen to run
// long (xKqrTbnPzw) has mixed case or no vowels in one segment and does not
// count.
func secretAssignmentWordLetters(value string) int {
	total := 0
	runStart := -1
	flush := func(end int) {
		if runStart < 0 {
			return
		}
		run := value[runStart:end]
		runStart = -1
		segStart := 0
		for i := 1; i <= len(run); i++ {
			boundary := i == len(run)
			if !boundary {
				prevLower := run[i-1] >= 'a' && run[i-1] <= 'z'
				upper := run[i] >= 'A' && run[i] <= 'Z'
				prevUpper := run[i-1] >= 'A' && run[i-1] <= 'Z'
				nextLower := i+1 < len(run) && run[i+1] >= 'a' && run[i+1] <= 'z'
				boundary = upper && (prevLower || (prevUpper && nextLower))
			}
			if boundary {
				if secretAssignmentWordShaped(run[segStart:i]) {
					total += i - segStart
				}
				segStart = i
			}
		}
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		flush(i)
	}
	flush(len(value))
	return total
}

func secretAssignmentWordShaped(segment string) bool {
	if len(segment) < 4 {
		return false
	}
	upper, lower := 0, 0
	for i := 0; i < len(segment); i++ {
		if segment[i] >= 'A' && segment[i] <= 'Z' {
			upper++
		} else {
			lower++
		}
	}
	titleCase := upper == 1 && segment[0] >= 'A' && segment[0] <= 'Z'
	if upper != 0 && lower != 0 && !titleCase {
		return false
	}
	vowels, consonants, longest := 0, 0, 0
	for i := 0; i < len(segment); i++ {
		if strings.IndexByte("aeiouyAEIOUY", segment[i]) >= 0 {
			vowels++
			consonants = 0
			continue
		}
		consonants++
		longest = max(longest, consonants)
	}
	return vowels*5 >= len(segment) && vowels*10 <= len(segment)*7 && longest <= 4
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
