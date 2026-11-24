// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Prose credential context (GAP-1079). A value introduced as a password,
// passphrase or secret in a sentence ("my password is X", "the passphrase was
// X", "set the password to X") is a credential, like the value of a
// password=X assignment. The 20-character high-entropy floor catches a long
// one; a shorter one stayed in clear in the llm_prompt audit rows.
//
// This is deliberately narrow, because prose that only talks about passwords
// is everywhere ("the password is wrong", "password is required"). The value
// must be one token of 8 to 128 visible ASCII characters with a mix of
// character classes: at least three of lower case, upper case, digit and
// symbol, and a digit or a special symbol (so an English word, a capitalised
// word, a hyphenated name such as Two-Factor-Auth, a number, a placeholder
// ($VAR, <value>, ${VAR}, ********), a path, a URL, a call and a field path
// all stay readable). A value with no digit and no special symbol is not
// recognised; the high-entropy detector still takes it at 20 characters.
//
// It runs in secrets.assignment, so every sink that projects through
// DetectAndRedact gets it: the laptop audit store, the cluster audit store,
// OTLP, Galileo and the local observability destination.

var (
	proseCredentialRE = lazyregexp.New(`(?i)(?:^|[^A-Za-z0-9_])(?:password|passphrase|passwd|secret)[\t ]+(?:is|was|are|will[\t ]+be|should[\t ]+be|to)(?:[\t ]*:)?[\t ]+`)
)

const (
	proseCredentialMinLen = 8
	proseCredentialMaxLen = 128
)

func recognizeProseCredentials(input string) []candidate {
	var result []candidate
	for _, index := range proseCredentialRE.FindAllStringIndex(input, -1) {
		start := index[1]
		// An opening quote, backtick or parenthesis is not part of the value.
		for start < len(input) && strings.IndexByte("\"'`(", input[start]) >= 0 {
			start++
		}
		end := start
		for end < len(input) && input[end] != ' ' && input[end] != '\t' && input[end] != '\n' && input[end] != '\r' {
			end++
		}
		// Closing punctuation, a quote or the end of the sentence is not.
		for end > start && strings.IndexByte(".,;:!?)]}\"'`", input[end-1]) >= 0 {
			end--
		}
		if end-start < proseCredentialMinLen || end-start > proseCredentialMaxLen {
			continue
		}
		result = append(result, candidate{start: start, end: end, accepted: proseCredentialValue(input[start:end])})
	}
	return result
}

// proseCredentialValue reports whether value, the single token after "password
// is", has the shape of a password rather than of a word, a name or a
// placeholder.
func proseCredentialValue(value string) bool {
	if !visibleWithoutControls(value) || credentialPlaceholder(value) {
		return false
	}
	var lower, upper, digit, symbol, special bool
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 0x80:
			return false
		case isASCIILower(c):
			lower = true
		case isASCIIUpper(c):
			upper = true
		case isASCIIDigit(c):
			digit = true
		default:
			symbol = true
			if c != '-' && c != '_' && c != '.' {
				special = true
			}
		}
	}
	classes := 0
	for _, present := range []bool{lower, upper, digit, symbol} {
		if present {
			classes++
		}
	}
	if classes < 3 || (!digit && !special) {
		return false
	}
	switch value[0] {
	case '/', '~', '.', '\\':
		return false // a path
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "()") ||
		identifierPathRE.MatchString(value) || emailRE.MatchString(value) {
		return false // a URL, a call, a field path, an address
	}
	return true
}
