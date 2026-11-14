// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
	"unicode"
)

// GAP-0371. Two credential shapes rel found only on the proxy content path
// (the LP-SECRET list): a password assigned to a password-named key, and a
// Bearer credential without its header name. The rule pack reports them on
// every surface: SEC-PASSWORD-ASSIGN and SEC-BEARER-BARE.
//
// Which key names count is pack data: the SEC-PASSWORD-ASSIGN pattern lists
// them and ends the key on its password word, so password_hash or
// passwordReset is not a password key. The validator below only reads the
// structure of the match: the separator, whether the value is quoted, and
// the value.

const (
	passwordAssignRuleID = "SEC-PASSWORD-ASSIGN"
	bareBearerRuleID     = "SEC-BEARER-BARE"
)

// acceptedPasswordAssignment reports a match of SEC-PASSWORD-ASSIGN whose
// value is a password: not a reference, placeholder or path, not code, and
// with a letter and a digit or a symbol (a bare word such as None, required
// or Optional is not a password).
//
// Code or literal is decided by structure (GAP-0476): a quoted value is a
// literal, whatever it holds, so "admin.Secret2024" is a password; an
// unquoted identifier path (opts.Password, config.get(, self->pw,
// Settings::PW) or a call or index on a name is code.
func acceptedPasswordAssignment(match string) bool {
	value, quoted, ok := passwordAssignmentValue(match)
	if !ok || len(value) < 8 {
		return false
	}
	if credentialReference(value) || pathLikeValue(value) || obviousCredentialPlaceholder(value) {
		return false
	}
	if !quoted && unquotedCodeValue(value) {
		return false
	}
	letter, digitOrSymbol := false, false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r):
			letter = true
		case r != '_':
			digitOrSymbol = true
		}
	}
	return letter && digitOrSymbol
}

// passwordAssignmentValue splits a match of key, separator and value: the
// value and whether a quote opens it. The key is an identifier, maybe
// quoted or escaped as in JSON text; the separator is =>, :=, ==, = or :.
func passwordAssignmentValue(match string) (value string, quoted, ok bool) {
	i := 0
	for i < len(match) && (isIdentByte(match[i])) {
		i++
	}
	for i < len(match) && strings.IndexByte("\\\"' \t", match[i]) >= 0 {
		i++
	}
	switch {
	case strings.HasPrefix(match[i:], "=>"), strings.HasPrefix(match[i:], ":="), strings.HasPrefix(match[i:], "=="):
		i += 2
	case i < len(match) && (match[i] == '=' || match[i] == ':'):
		i++
	default:
		return "", false, false
	}
	for i < len(match) && (match[i] == ' ' || match[i] == '\t' || match[i] == '\\') {
		i++
	}
	if i < len(match) && (match[i] == '"' || match[i] == '\'') {
		quoted = true
		i++
	}
	return match[i:], quoted, i < len(match)
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// credentialReference reports a value that names a credential instead of
// holding one: a variable ($X, ${X}, %X%), a template slot ({{x}}, <x>).
func credentialReference(v string) bool {
	switch {
	case strings.HasPrefix(v, "$"), strings.HasPrefix(v, "{{"), strings.HasPrefix(v, "<"):
		return true
	case strings.HasPrefix(v, "%") && strings.Count(v, "%") >= 2:
		return true
	}
	return false
}

// pathLikeValue reports a value that is a location, not a password.
func pathLikeValue(v string) bool {
	switch {
	case strings.Contains(v, "://"),
		strings.HasPrefix(v, "/"), strings.HasPrefix(v, "~/"),
		strings.HasPrefix(v, "./"), strings.HasPrefix(v, "../"),
		strings.HasPrefix(v, `\\`):
		return true
	}
	return len(v) > 2 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') && unicode.IsLetter(rune(v[0]))
}

// unquotedCodeValue reports an unquoted value that is code: an identifier
// path of two or more names (a.b, a->b, A::B, a?.b), or a call or index on
// a name (getpass(, env[, Optional[str]).
func unquotedCodeValue(v string) bool {
	names, i := 0, 0
	for {
		j := i
		if j < len(v) && (v[j] == '_' || unicode.IsLetter(rune(v[j]))) {
			for j < len(v) && isIdentByte(v[j]) {
				j++
			}
		}
		if j == i {
			break
		}
		names++
		i = j
		sep := ""
		for _, s := range []string{"?.", "->", "::", "."} {
			if strings.HasPrefix(v[i:], s) {
				sep = s
				break
			}
		}
		if sep == "" {
			break
		}
		i += len(sep)
	}
	if names == 0 {
		return false
	}
	rest := v[i:]
	if rest == "" {
		return names >= 2
	}
	switch rest[0] {
	case '(', '[':
		return true
	case '{', '<', '!', '?', ')', ']', '}':
		return names >= 2
	}
	return false
}

// bearerHeaderForm is the text SEC-BEARER reports in front of Bearer: a
// header or field name and its separator.
var bearerHeaderForm = regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[:=]\s*$`)

// acceptedBareBearer reports a Bearer credential that SEC-BEARER does not
// already report: no header name in front of it, a value of letters and
// digits that is not a placeholder, with the SEC-BEARER entropy floor.
func acceptedBareBearer(text, match string, start int) bool {
	if start > 0 && start <= len(text) && bearerHeaderForm.MatchString(text[max(0, start-64):start]) {
		return false
	}
	candidate := credentialCandidate(bareBearerRuleID, match)
	if candidate == "" || obviousCredentialPlaceholder(candidate) {
		return false
	}
	letter, digit := false, false
	for _, r := range candidate {
		letter = letter || unicode.IsLetter(r)
		digit = digit || unicode.IsDigit(r)
	}
	return letter && digit && credentialEntropy(compactCredential(candidate)) >= 2.5
}
