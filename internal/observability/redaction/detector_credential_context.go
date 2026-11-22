// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Credential-context redaction (GAP-0426). A value in a credential context
// is a credential whatever its shape: the value of an Authorization header
// anywhere in a line (a curl -H argument, a JSON string, a log line), a bare
// Bearer credential, and the value of a key that names a token, secret,
// password, bearer or API key, prefixed or not (SERVICE_API_TOKEN=,
// CANARY_BEARER=, dbPassword:). The line-anchored header and whole-key
// assignment recognizers keep their v1 behaviour; these add the contexts
// they never saw, so nothing they redacted is kept.

var (
	inlineAuthorizationRE = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])(?:proxy-)?authorization(?:\\*["'])?[\t ]*[:=][\t ]*(?:\\*["'])?(?:bearer|basic|digest|token|apikey)[\t ]+([^\s"'\\<>]+)`)
	bareBearerRE          = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])bearer[\t ]+([A-Za-z0-9._~+/=-]{8,})`)
	// credentialKeyWordRE finds a credential word; longer words come first
	// so secret_key wins over secret at the same position.
	credentialKeyWordRE = regexp.MustCompile(`(?i)(?:secret[_-]?key|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|auth[_-]?key|client[_-]?secret|api[_-]?token|auth[_-]?token|access[_-]?token|refresh[_-]?token|passphrase|password|passwd|pwd|secret|token|bearer|credentials|credential|apikey)`)
	identifierPathRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)
)

// recognizeInlineCredentials finds an Authorization header value or a bare
// Bearer credential inside a line that the line-anchored header recognizer
// does not cover.
func recognizeInlineCredentials(input string) []candidate {
	return scanLines(input, func(line string, offset int) []candidate {
		if authorizationRE.MatchString(line) {
			return nil // the v1 header recognizer owns this line
		}
		var result []candidate
		for _, parts := range inlineAuthorizationRE.FindAllStringSubmatchIndex(line, -1) {
			start, end := parts[2], parts[3]
			value := line[start:end]
			// Inside prose the header names a scheme ("Authorization: Bearer
			// token"); a credential value has a digit or a symbol, or is long.
			shaped := len(value) >= 20 || byteAny(value, func(c byte) bool { return !isASCIIUpper(c) && !isASCIILower(c) })
			result = append(result, candidate{
				start: offset + start, end: offset + end,
				accepted: shaped && visibleWithoutControls(value) && !credentialPlaceholder(value),
			})
		}
		for _, parts := range bareBearerRE.FindAllStringSubmatchIndex(line, -1) {
			start, end := parts[2], parts[3]
			if overlapsCandidates(offset+start, offset+end, result) {
				continue
			}
			value := line[start:end]
			// Prose ("bearer authentication") is letters only; a credential
			// has a digit or a token symbol.
			shaped := byteAny(value, func(c byte) bool { return !isASCIIUpper(c) && !isASCIILower(c) })
			result = append(result, candidate{
				start: offset + start, end: offset + end,
				accepted: shaped && visibleWithoutControls(value) && !credentialPlaceholder(value),
			})
		}
		return result
	})
}

// recognizeCredentialKeys finds key=value and key: value where the key ends
// in a credential word that the v1 whole-key recognizer does not match: a
// prefixed key (SERVICE_API_TOKEN, CANARY_BEARER, DB_PASSWORD, dbPassword) or
// a credential word v1 lacks (token, bearer, credential, passphrase).
func recognizeCredentialKeys(input string) []candidate {
	var result []candidate
	var uris [][]int
	urisFound := false
	for _, index := range credentialKeyWordRE.FindAllStringIndex(input, -1) {
		wordStart, wordEnd := index[0], index[1]
		if wordEnd < len(input) && isCredentialKeyByte(input[wordEnd]) {
			continue // the key goes on (token_count, tokens, apiKeyId)
		}
		keyStart := wordStart
		if wordStart > 0 && isCredentialKeyByte(input[wordStart-1]) {
			previous := input[wordStart-1]
			camel := isASCIIUpper(input[wordStart]) && (isASCIILower(previous) || isASCIIDigit(previous))
			if previous != '_' && previous != '-' && previous != '.' && !camel {
				continue // inside a word (mypassword)
			}
			for keyStart > 0 && isCredentialKeyByte(input[keyStart-1]) {
				keyStart--
			}
		}
		word := strings.ToLower(input[wordStart:wordEnd])
		if !urisFound {
			uris, urisFound = uriRE.FindAllStringIndex(input, -1), true
		}
		if _, eligible := eligibleURLQueryKeys[strings.ToLower(input[keyStart:wordEnd])]; eligible &&
			overlapsAnyRange(wordStart, wordEnd, uris) {
			continue // a URI query key secrets.url_query redacts
		}
		// A key inside an escaped JSON string (a tool result that holds
		// stringified JSON, double-encoded arguments): \"KEY\":\"value\".
		escaped := escapedQuoteBefore(input, keyStart)
		if keyStart == wordStart && escaped == 0 &&
			assignmentKeyRE.FindString(input[wordStart:wordEnd]) == input[wordStart:wordEnd] {
			continue // a v1 whole key: recognizeAssignments owns it
		}
		position := wordEnd
		if keyStart > 0 && position < len(input) && (input[keyStart-1] == '"' || input[keyStart-1] == '\'') {
			if escaped > 0 {
				position += escapedQuoteLen(input, position)
			} else if input[position] == input[keyStart-1] {
				position++
			}
		}
		position = skipOWS(input, position)
		if position >= len(input) || (input[position] != '=' && input[position] != ':') {
			continue
		}
		separator := position
		if position+1 < len(input) && (input[position+1] == '=' || input[position+1] == ':' ||
			(input[position] == ':' && input[position+1] == '=')) {
			continue // a comparison, a scope or a Go declaration is code
		}
		if input[position] == '=' && position+1 < len(input) && input[position+1] == '>' {
			position++ // 'password' => 'value'
		}
		position = skipOWS(input, position+1)
		var start, end int
		var valid, quoted bool
		if n := escapedQuoteLen(input, position); n > 0 {
			start, quoted = position+n, true
			if closing := strings.Index(input[start:], input[position:position+n]); closing >= 0 {
				end, valid = start+closing, closing > 0
			} else {
				_, end, valid = parseAssignmentValue(input, start, false)
			}
		} else if closing := singleQuotedEnd(input, position); closing > 0 {
			start, end, valid, quoted = position+1, closing, closing > position+1, true
		} else {
			start, end, valid = parseAssignmentValue(input, position, false)
			quoted = position < len(input) && input[position] == '"'
		}
		if end <= start {
			continue
		}
		decoded := input[start:end]
		if valid && quoted && input[position] == '"' {
			var value string
			if json.Unmarshal([]byte(input[position:end+1]), &value) != nil {
				valid = false
			} else {
				decoded = value
			}
		}
		valid = valid && end-keyStart <= 8192 && !credentialPlaceholder(decoded) && len(decoded) >= 4
		if valid && !quoted && (strings.ContainsAny(decoded, "()") || identifierPathRE.MatchString(decoded) ||
			codeValue(decoded, input[keyStart:wordEnd], word)) {
			valid = false // a call, a field path or a name (os.Getenv("X"), cfg.Token, x = x, None) is code
		}
		if valid && strings.HasSuffix(word, "token") && allDigits(decoded) && len(decoded) <= 10 {
			valid = false // a count (prompt_token: 12345678)
		}
		if valid && word == "token" && keyStart == wordStart && len(decoded) < 16 &&
			!(byteAny(decoded, isASCIIDigit) && byteAny(decoded, func(c byte) bool { return isASCIIUpper(c) || isASCIILower(c) }) &&
				!strings.ContainsAny(decoded, " \t")) {
			valid = false // a bare token key holding a word ({"token": " world"}, logprob and tokenizer output)
		}
		if valid && !quoted && strings.ContainsAny(decoded, "[]") {
			valid = false // a type annotation (token: Optional[str] = None)
		}
		if valid && !quoted && keyStart == wordStart && input[separator] == ':' &&
			!byteAny(decoded, func(c byte) bool { return !isASCIIUpper(c) && !isASCIILower(c) }) {
			valid = false // prose ("Token: the unit of text"); a credential has a digit or symbol
		}
		result = append(result, candidate{start: start, end: end, accepted: valid})
	}
	return result
}

// credentialPlaceholder reports a value that names a credential without
// holding one: a v1 excluded value, a variable or template reference, or a
// structure.
func credentialPlaceholder(value string) bool {
	if excludedAssignmentValue(value) {
		return true
	}
	for _, prefix := range []string{"$", "%", "{", "[", "<", "@"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func isCredentialKeyByte(value byte) bool {
	return isASCIIAlphaNum(value) || value == '_' || value == '-' || value == '.'
}

func overlapsCandidates(start, end int, candidates []candidate) bool {
	for _, item := range candidates {
		if start < item.end && item.start < end {
			return true
		}
	}
	return false
}

// escapedQuoteLen is the length of an escaped quote at position (one or more
// backslashes and a quote), or 0.
func escapedQuoteLen(input string, position int) int {
	end := position
	for end < len(input) && input[end] == '\\' {
		end++
	}
	if end > position && end < len(input) && (input[end] == '"' || input[end] == '\'') {
		return end - position + 1
	}
	return 0
}

// escapedQuoteBefore is the number of backslashes escaping the quote just
// before keyStart, or 0 when there is no quote or it is not escaped.
func escapedQuoteBefore(input string, keyStart int) int {
	if keyStart == 0 || (input[keyStart-1] != '"' && input[keyStart-1] != '\'') {
		return 0
	}
	slash := keyStart - 2
	for slash >= 0 && input[slash] == '\\' {
		slash--
	}
	return keyStart - 2 - slash
}

// singleQuotedEnd is the index of the closing quote of a single-quoted value
// at position on the same line, or 0.
func singleQuotedEnd(input string, position int) int {
	if position >= len(input) || input[position] != '\'' {
		return 0
	}
	for current := position + 1; current < len(input); current++ {
		switch input[current] {
		case '\'':
			return current
		case '\n', '\r':
			return 0
		}
	}
	return 0
}

// codeValue reports an unquoted value that is a name rather than a literal:
// a null of some language, or the key's own name (apiToken = apiToken).
func codeValue(value, key, word string) bool {
	switch value {
	case "None", "nil", "undefined", "NULL", "Nothing":
		return true
	}
	lowerValue, lowerKey := strings.ToLower(value), strings.ToLower(key)
	return lowerValue == lowerKey || lowerValue == word || strings.HasSuffix(lowerKey, "."+lowerValue)
}
