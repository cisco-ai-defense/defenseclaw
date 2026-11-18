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
	inlineAuthorizationRE = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])(?:proxy-)?authorization["']?[\t ]*[:=][\t ]*["']?(?:bearer|basic|digest|token|apikey)[\t ]+([^\s"'\\<>]+)`)
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
		if keyStart == wordStart && assignmentKeyRE.FindString(input[wordStart:wordEnd]) == input[wordStart:wordEnd] {
			continue // a v1 whole key: recognizeAssignments owns it
		}
		position := wordEnd
		if keyStart > 0 && position < len(input) && (input[keyStart-1] == '"' || input[keyStart-1] == '\'') &&
			input[position] == input[keyStart-1] {
			position++
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
		start, end, valid := parseAssignmentValue(input, position, false)
		if end <= start {
			continue
		}
		decoded, quoted := input[start:end], position < len(input) && input[position] == '"'
		if valid && quoted {
			var value string
			if json.Unmarshal([]byte(input[position:end+1]), &value) != nil {
				valid = false
			} else {
				decoded = value
			}
		}
		valid = valid && end-keyStart <= 8192 && !credentialPlaceholder(decoded) && len(decoded) >= 4
		if valid && !quoted && (strings.ContainsAny(decoded, "()") || identifierPathRE.MatchString(decoded)) {
			valid = false // a call or a field path (os.Getenv("X"), cfg.Token) is code
		}
		if valid && strings.HasSuffix(word, "token") && allDigits(decoded) && len(decoded) <= 7 {
			valid = false // a count (last_token: 4096)
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
