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
	`^\W?([A-Za-z0-9_-]+)\\*["']?\s*(?:[:=,(]|\s+is\s+|=>)\s*\\*["']?(.+)$`)

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
	// A value is one reference when it is a variable ($NAME, %NAME%), a
	// command substitution ($(cmd ...)) or a mention (@name) and nothing
	// else. The rule pattern never lets a value start with { or <, so a
	// ${NAME}, {{ name }} or <name> slot never reaches this check.
	secretAssignmentVarRef  = regexp.MustCompile(`^\$\(|^\$[A-Z_][A-Z0-9_]*$|^%[A-Za-z_]+%$|^@[A-Za-z_]+$`)
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
	return secretAssignmentKeyIsCredential(m[1]) && secretAssignmentValueLooksSecret(m[2])
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
	// The value runs to the first character a secret does not use. = ( and )
	// are secret characters (a Django key holds all three); a closing
	// parenthesis with no opening one in the value closes the code around it.
	if end := strings.IndexFunc(value, func(r rune) bool {
		letterOrDigit := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		return !letterOrDigit && !strings.ContainsRune("_-+/.!@#$%^&*~=()", r)
	}); end >= 0 {
		value = value[:end]
	}
	value = strings.TrimRight(value, ".,;!=")
	for strings.HasSuffix(value, ")") && strings.Count(value, ")") > strings.Count(value, "(") {
		value = strings.TrimRight(strings.TrimSuffix(value, ")"), ".,;!=")
	}
	// Code that calls something (get_token(x), uuid.uuid4().hex,
	// base64.b64encode(os.urandom(32))) generates or fetches a secret and is
	// not one: it has the shape of a call, read from its structure.
	if secretAssignmentCallShaped(value) {
		return "call"
	}
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
	// A value made of words joined by separators and a number
	// (dr_secret_key_1700000000, summer-holiday-2026) is a name a person or a
	// script composed, not a random secret: most of what it holds sits in
	// word-shaped runs of three letters or more. A generated token with
	// separators (dd_api_7f8a9b0c1d2e) has random letter runs of one or two
	// and digits among its letters.
	if strings.ContainsAny(value, "_-.") && secretAssignmentNameShaped(value) {
		return "name"
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

// secretAssignmentCallShaped reports a value that is a call and nothing else:
// an identifier path (letters, digits and _, joined by . or ::), then a
// parenthesised argument list that balances, then only more code of the same
// kind (.attribute, another call) up to the end. The shape is told by its
// structure, not by how word-like the callee is (uuid4, b64encode and
// pbkdf2_sha256.hash are calls too). Inside the parentheses the value holds
// only what code holds (names, digits, dots and arithmetic), so a Django-style
// key that carries a ( among random punctuation, and the characters after a
// closing ) that a literal would carry, are not a call. The value is cut at
// the first space, quote, comma or bracket, so a call whose argument list runs
// on is read as far as the cut and stays a call while it is still open.
func secretAssignmentCallShaped(value string) bool {
	i := secretAssignmentPathEnd(value, 0)
	if i == 0 || i >= len(value) || value[i] != '(' {
		return false
	}
	depth := 0
	for ; i < len(value); i++ {
		switch c := value[i]; {
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth > 0:
			if !secretAssignmentCodeChar(c) {
				return false
			}
		case c == '.':
			end := secretAssignmentPathEnd(value, i+1)
			if end == i+1 {
				return false
			}
			i = end - 1
		default:
			return false
		}
		if depth < 0 {
			return false
		}
	}
	return true
}

// secretAssignmentPathEnd returns the end of the identifier path that starts at
// start: identifiers joined by "." or "::". It returns start when none starts
// there.
func secretAssignmentPathEnd(value string, start int) int {
	end := start
	for i := start; i < len(value) && secretAssignmentIdentStart(value[i]); {
		j := i + 1
		for j < len(value) && (secretAssignmentIdentStart(value[j]) || value[j] >= '0' && value[j] <= '9') {
			j++
		}
		end = j
		switch {
		case j < len(value) && value[j] == '.':
			i = j + 1
		case strings.HasPrefix(value[j:], "::"):
			i = j + 2
		default:
			return end
		}
	}
	return end
}

func secretAssignmentIdentStart(c byte) bool {
	return secretAssignmentLetter(c) || c == '_'
}

// secretAssignmentCodeChar reports a character that code holds inside an
// argument list: a name, a number, a dot or an operator. A secret's own
// punctuation (@ # $ % ^) is not among them.
func secretAssignmentCodeChar(c byte) bool {
	return secretAssignmentIdentStart(c) || c >= '0' && c <= '9' || strings.IndexByte(".+-*/=&!", c) >= 0
}

// secretAssignmentNameShaped reports a value a person composed: words and
// numbers joined by _, - or ., where the letters and digits of the value that
// do not sit in a word-shaped run of three letters or more are under three
// tenths. A separator-delimited number of nine digits or fewer is a counter or
// a year and weighs nothing; so does ONE number of ten or thirteen digits,
// which is a timestamp in seconds or milliseconds (dr_secret_key_1700000000),
// and ONE version token (python3dot11, md5sum2024). Any other digit counts
// against the name, so a random token that holds digits, or words followed by
// a long random number or by several of them, is not one.
func secretAssignmentNameShaped(value string) bool {
	letters, digits, wordLetters := 0, 0, 0
	sawTimestamp, sawVersion := false, false
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		if secretAssignmentCounter(segment) {
			if len(segment) < 10 {
				continue
			}
			if !sawTimestamp {
				sawTimestamp = true
				continue
			}
		} else if secretAssignmentTokenLike(segment) {
			if sawVersion || !secretAssignmentVersionToken(segment) {
				return false
			}
			sawVersion = true
			continue
		}
		for _, run := range strings.FieldsFunc(segment, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
		}) {
			letters += len(run)
			wordLetters += secretAssignmentWordLettersMin(run, 3)
		}
		digits += secretAlnumCount(segment) - countLetters(segment)
	}
	return letters > 0 && wordLetters*10 >= (letters+digits)*7
}

// secretAssignmentVersionToken reports a segment that is a version or a year
// inside words: letters, a version of one or two digits, letters, then a
// number of one to four digits (python3dot11, md5sum2024). It is the one shape
// of letter and digit turns that a person writes in a name, and the token-like
// check would call it a token. The letter run after the version must be a word
// of three letters or more, so a random mix of letters and digits that
// happens to have this shape is not read as one.
func secretAssignmentVersionToken(segment string) bool {
	var parts []string
	for i := 0; i < len(segment); {
		j := i
		for j < len(segment) && secretAssignmentLetter(segment[j]) == secretAssignmentLetter(segment[i]) {
			j++
		}
		parts = append(parts, segment[i:j])
		i = j
	}
	if len(parts) != 4 || !secretAssignmentLetter(segment[0]) {
		return false
	}
	return len(parts[0]) >= 2 && len(parts[1]) <= 2 && len(parts[3]) <= 4 && secretAssignmentWordShaped(parts[2], 3)
}

// secretAssignmentTokenLike reports a segment of eight characters or more
// that turns from letters to digits or back three times or more
// (7f8a9b0c1d2e): a generated token, where a name has its digits in one run
// (summer2026, v2).
func secretAssignmentTokenLike(segment string) bool {
	if len(segment) < 8 {
		return false
	}
	turns, prev := 0, byte(0)
	for i := 0; i < len(segment); i++ {
		class := byte('l')
		if segment[i] >= '0' && segment[i] <= '9' {
			class = 'd'
		} else if !secretAssignmentLetter(segment[i]) {
			continue
		}
		if prev != 0 && class != prev {
			turns++
		}
		prev = class
	}
	return turns >= 3
}

// secretAssignmentCounter reports a segment that is only digits and is short
// or the length of an epoch in milliseconds.
func secretAssignmentCounter(segment string) bool {
	if segment == "" || strings.Trim(segment, "0123456789") != "" {
		return false
	}
	return len(segment) <= 10 || len(segment) == 13
}

func secretAssignmentLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func countLetters(value string) int {
	n := 0
	for i := 0; i < len(value); i++ {
		if secretAssignmentLetter(value[i]) {
			n++
		}
	}
	return n
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
	return secretAssignmentWordLettersMin(value, 4)
}

func secretAssignmentWordLettersMin(value string, minLen int) int {
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
				if secretAssignmentWordShaped(run[segStart:i], minLen) {
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

func secretAssignmentWordShaped(segment string, minLen int) bool {
	if len(segment) < minLen {
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
