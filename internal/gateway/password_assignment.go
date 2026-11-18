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
	"unicode/utf8"
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
//
// The pattern reads the value as a model writes it (rel-1-0-10:GAP-1267,
// GAP-1268): in inline-code backticks (password=`...`), on the line after
// the key (YAML: password:, then the value indented on the next line), and
// with a comma inside it. The validator keeps those readings to a value:
// a value on the next line is the whole of that line and not a YAML key, and
// a comma that starts the next field (password=...,user=bob) ends the value.

const (
	passwordAssignRuleID = "SEC-PASSWORD-ASSIGN"
	bareBearerRuleID     = "SEC-BEARER-BARE"
)

// acceptedPasswordAssignment reports a match of SEC-PASSWORD-ASSIGN, found
// at start in text, whose value is a password: not a reference,
// placeholder or path, not code, and with a letter and a digit or a symbol
// (a bare word such as None, required or Optional is not a password).
//
// Code or literal is decided by structure (GAP-0476): a quoted value is a
// literal, whatever it holds, so "admin.Secret2024" is a password; an
// unquoted identifier path (opts.Password, config.get(, self->pw,
// Settings::PW) or a call or index on a name is code.
//
// What a literal holds is decided by structure too (GAP-0522): a quoted
// value can still be text about a password rather than one. A template
// slot or a decorated word ({password}, %(db_password)s, #{ENV[X]},
// [REDACTED], **redacted**, @Password), a rule list
// (required|string|min:8), a regex, a scheme reference (env:DB_PASSWORD),
// a relative path, or a fill-in that names its own key
// (your-password-here) is not a password, quoted or not. These tests read
// the shape of the value or the key of the match. A stand-in value
// (changeme123456, dummy_password_2024) is read by the placeholder helper
// SEC-SECRET-ASSIGN uses, credentialPlaceholderValue, not by a second list.
func acceptedPasswordAssignment(text, match string, start int) bool {
	return readPasswordAssignment(text, match, start) == passwordReadAsPassword
}

// passwordReading is what the value of a SEC-PASSWORD-ASSIGN match is.
type passwordReading uint8

const (
	// passwordReadAsNone: not a password. A reference, slot, path, code, a
	// mask (********, xxxxxxxxxx), a well-known documentation placeholder
	// (changeme, placeholder, example: namedCredentialPlaceholder) or text
	// about a password (a rule list, a regex, a fill-in naming its key).
	passwordReadAsNone passwordReading = iota
	// passwordReadAsWeak: a literal password, but a stand-in made of
	// placeholder words or a bare word (password123, changeme123,
	// dummysecret, examplepass). The rule does not report it: in a prompt or
	// a tool result such values are sample configs and test fixtures
	// (rel-1-0-10:GAP-0522). The proxy content check still alerts on the
	// bare password assignment of one (weakPasswordAssignmentFindings), as
	// rel always did: a weak default is often the credential an operator
	// most needs to see in a model response.
	passwordReadAsWeak
	// passwordReadAsPassword: a password; the rule reports it.
	passwordReadAsPassword
)

// readPasswordAssignment reads the value of a SEC-PASSWORD-ASSIGN match
// found at start in text. acceptedPasswordAssignment reports only
// passwordReadAsPassword; the strong reading is the one the rule always had.
func readPasswordAssignment(text, match string, start int) passwordReading {
	if start > 0 && start <= len(text) && (text[start-1] == '/' || text[start-1] == '\\') {
		// The key is a path name (/etc/passwd:...), not a key.
		return passwordReadAsNone
	}
	key, value, quoted, ok := passwordAssignmentValue(match)
	if !ok {
		return passwordReadAsNone
	}
	if strings.IndexByte(match[len(key):len(match)-len(value)], '\n') >= 0 && !valueIsItsLine(text, match, start, value) {
		return passwordReadAsNone
	}
	if value = valueBeforeNextField(value); len(value) < 8 {
		return passwordReadAsNone
	}
	if credentialReference(value) || pathLikeValue(value) || maskedCredentialValue(value) ||
		obviousCredentialPlaceholder(value) && !sequenceCredentialPlaceholder(strings.ToLower(value)) {
		return passwordReadAsNone
	}
	if !quoted && unquotedCodeValue(value) {
		return passwordReadAsNone
	}
	if templateSlotValue(value) || decoratedWordValue(value) || ruleListValue(value) ||
		regexValue(value) || schemeReferenceValue(value) || relativePathValue(value) ||
		valueNamesItsKey(key, value) {
		return passwordReadAsNone
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
	switch {
	case !letter && (!digitOrSymbol || symbolRunValue(value)):
		// A run of one symbol (********, --------) masks a value or rules a
		// line; it is not one.
		return passwordReadAsNone
	case !letter:
		// Digits or symbols only (12345678, a date, !@#$%^&*): a weak
		// password, not a reference (rel-1-0-10:GAP-1266). The rule does not
		// report it, as on rel; the proxy reads it on a bare password key.
		return passwordReadAsWeak
	case !digitOrSymbol || secretAssignmentPlaceholderValue(value) || sequenceCredentialPlaceholder(strings.ToLower(value)):
		// A bare word, a stand-in made of placeholder words, or a run or a
		// repeat (abcdefgh1, 12345678): the token placeholder shapes are weak
		// passwords, not documentation placeholders (rel-1-0-10:GAP-1266).
		return passwordReadAsWeak
	}
	return passwordReadAsPassword
}

// symbolRunValue reports a value of one repeated character that is not a
// letter or a digit (********, ••••••••, ========).
func symbolRunValue(v string) bool {
	first, _ := utf8.DecodeRuneInString(v)
	if unicode.IsLetter(first) || unicode.IsDigit(first) {
		return false
	}
	for _, r := range v {
		if r != first {
			return false
		}
	}
	return true
}

// valueIsItsLine reports a value that starts on the line after its key and
// is the whole of that line (YAML: password:, then the value indented below
// it), maybe closed by its quote: not the first word of a sentence and not
// a YAML key of a nested map (description:).
func valueIsItsLine(text, match string, start int, value string) bool {
	end := start + len(match)
	if start < 0 || end > len(text) || text[start:end] != match || strings.HasSuffix(value, ":") {
		return false
	}
	rest := text[end:]
	if rest != "" && strings.IndexByte("\"'`", rest[0]) >= 0 {
		rest = rest[1:]
	}
	rest = strings.TrimLeft(rest, " \t\r")
	return rest == "" || rest[0] == '\n'
}

// valueBeforeNextField is value up to a comma that starts the next field of
// a list of assignments (password=...,user=bob; {password:...,user:bob}): a
// name and = or : after the comma. A comma inside a value is the value's.
func valueBeforeNextField(value string) string {
	for i := 0; i < len(value); i++ {
		if value[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(value) && isIdentByte(value[j]) {
			j++
		}
		if j > i+1 && j < len(value) && (value[j] == '=' || value[j] == ':') {
			return value[:i]
		}
	}
	return value
}

// bareWeakPasswordAssignment reports a match whose value is a weak password
// (passwordReadAsWeak) assigned to a bare password key: an unquoted key of
// one word (password, PASSWORD, pwd, passwd, as in password=, --password=,
// pwd: ). It covers the reach of rel's proxy password regex, which the proxy
// content check keeps (rel-1-0-10:GAP-0210 review r1), and is a little wider:
// the rule's key and separators also take passphrase, a digit after the key
// word (password1=) and the := and => separators. A prefixed key
// (DB_PASSWORD) or a quoted field ("password": ...) with a weak value was
// never reported there and is not now.
func bareWeakPasswordAssignment(text, match string, start int) bool {
	key, _, _, ok := passwordAssignmentValue(match)
	if !ok || len(key) == len(match) || len(identifierWords(key)) != 1 {
		return false
	}
	if c := match[len(key)]; c == '"' || c == '\'' || c == '\\' {
		return false
	}
	return readPasswordAssignment(text, match, start) == passwordReadAsWeak
}

// passwordAssignmentValue splits a match of key, separator and value: the
// key, the value and whether a quote opens it. The key is an identifier,
// maybe quoted or escaped as in JSON text; the separator is =>, :=, ==, =
// or :. The value may start on the next line or after an inline-code
// backtick, which is not a quote.
func passwordAssignmentValue(match string) (key, value string, quoted, ok bool) {
	i := 0
	for i < len(match) && (isIdentByte(match[i])) {
		i++
	}
	key = match[:i]
	for i < len(match) && strings.IndexByte("\\\"' \t", match[i]) >= 0 {
		i++
	}
	switch {
	case strings.HasPrefix(match[i:], "=>"), strings.HasPrefix(match[i:], ":="), strings.HasPrefix(match[i:], "=="):
		i += 2
	case i < len(match) && (match[i] == '=' || match[i] == ':'):
		i++
	default:
		return "", "", false, false
	}
	for i < len(match) && strings.IndexByte(" \t\r\n\\", match[i]) >= 0 {
		i++
	}
	switch {
	case i < len(match) && (match[i] == '"' || match[i] == '\''):
		quoted = true
		i++
	case i < len(match) && match[i] == '`':
		// Inline code shows a value; it is not a string literal, so the
		// code reading still applies (`opts.Password` is code).
		i++
	}
	return key, match[i:], quoted, i < len(match)
}

// slotClose is the bracket that closes open, or 0.
func slotClose(open byte) byte {
	switch open {
	case '{':
		return '}'
	case '[':
		return ']'
	case '(':
		return ')'
	case '<':
		return '>'
	}
	return 0
}

// generatedPiece reports a piece of eight characters or more, split at the
// characters a name holds besides letters and digits, that mixes upper case,
// lower case and digits: a generated string, not a name (GAP-0671). A slot
// that wraps one ([Wq7mz2LpK9xt]) wraps a password, not a variable.
func generatedPiece(s string) bool {
	for _, piece := range strings.FieldsFunc(s, func(r rune) bool { return (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') }) {
		upper, lower, digit := false, false, false
		for i := 0; i < len(piece); i++ {
			switch c := piece[i]; {
			case c >= 'A' && c <= 'Z':
				upper = true
			case c >= 'a' && c <= 'z':
				lower = true
			default:
				digit = true
			}
		}
		if len(piece) >= 8 && upper && lower && digit {
			return true
		}
	}
	return false
}

// nameExpression reports text that names something: it starts with a
// letter or _ and holds only name and index characters (db_password,
// ENV[DB_PASS], vault.db-password).
func nameExpression(s string) bool {
	if s == "" || s[0] != '_' && !unicode.IsLetter(rune(s[0])) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) && strings.IndexByte(".-[]:", s[i]) < 0 {
			return false
		}
	}
	return true
}

// wordOnly reports text of letters and _ only: a word or a snake_case
// name, with no digit or symbol.
func wordOnly(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r != '_' && !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// templateSlotValue reports a value that is one template slot as a whole:
// an optional sigil ($ # %) and a bracketed name that closes at the end of
// the value ({password}, #{ENV[DB_PASS]}, $(DB_PASSWORD), [REDACTED]), with
// the conversion letter of a printf slot after it (%(db_password)s).
func templateSlotValue(v string) bool {
	s, sigil := v, byte(0)
	if strings.IndexByte("$#%", s[0]) >= 0 {
		sigil, s = s[0], s[1:]
	}
	depth, open := 0, byte(0)
	if s != "" {
		open = s[0]
	}
	closer := slotClose(open)
	if closer == 0 {
		return false
	}
	for n := 0; n < len(s); n++ {
		switch s[n] {
		case open:
			depth++
		case closer:
			depth--
			if depth == 0 {
				inner := strings.Trim(s[1:n], string([]byte{open, closer}))
				rest := s[n+1:]
				if !nameExpression(inner) || generatedPiece(inner) {
					return false
				}
				return rest == "" || sigil == '%' && len(rest) == 1 && unicode.IsLetter(rune(rest[0]))
			}
		}
	}
	return false
}

// decoratedWordValue reports a bare word with only decoration around it:
// a run of the same symbol on both sides (**redacted**, __hidden__) or a
// sigil in front of a word (@Password, :password, the SQL variable and
// bind-parameter forms). The decoration does not make a word a password.
func decoratedWordValue(v string) bool {
	if (v[0] == '@' || v[0] == ':') && wordOnly(v[1:]) {
		return true
	}
	c := v[0]
	if isIdentByte(c) || c >= 0x80 {
		return false
	}
	i, j := 0, len(v)
	for i < j && v[i] == c {
		i++
	}
	for j > i && v[j-1] == c {
		j--
	}
	return i > 0 && j < len(v) && i == len(v)-j && wordOnly(v[i:j])
}

// ruleListValue reports a validation rule list: two or more rules joined by
// |, each a word with optional arguments after a colon
// (required|string|min:8|confirmed).
func ruleListValue(v string) bool {
	rules := strings.Split(v, "|")
	if len(rules) < 2 {
		return false
	}
	for _, r := range rules {
		name, _, _ := strings.Cut(r, ":")
		if !wordOnly(name) {
			return false
		}
	}
	return true
}

// regexValue reports a regular expression: two or more regex constructs
// (a group modifier, a wildcard repeat, a character range), or one after a
// ^ anchor (^(?=.*[A-Z])(?=.*[0-9]).{8,}$).
func regexValue(v string) bool {
	constructs := strings.Count(v, "(?") + strings.Count(v, ".*") + strings.Count(v, ".+") + strings.Count(v, ".{")
	for i := 0; i+4 < len(v); i++ {
		if v[i] == '[' && v[i+2] == '-' && v[i+4] == ']' {
			constructs++
		}
	}
	return constructs >= 2 || constructs == 1 && v[0] == '^'
}

// schemeReferenceValue reports a scheme reference to a secret held
// elsewhere: a lower-case scheme, a colon and a constant name or a path
// (env:DB_PASSWORD, vault:secret/db, file:/run/secrets/db).
func schemeReferenceValue(v string) bool {
	scheme, rest, ok := strings.Cut(v, ":")
	if !ok || len(scheme) < 2 || rest == "" {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		if (scheme[i] < 'a' || scheme[i] > 'z') && scheme[i] != '-' {
			return false
		}
	}
	if strings.Contains(rest, "/") {
		return true
	}
	if rest[0] != '_' && (rest[0] < 'A' || rest[0] > 'Z') {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] != '_' && (rest[i] < 'A' || rest[i] > 'Z') && (rest[i] < '0' || rest[i] > '9') {
			return false
		}
	}
	return true
}

// relativePathValue reports a relative path: two or more names joined by /
// (packages/core, src/components/forms, src/components/LoginForm), each
// component of letters, digits, dots, dashes and _ with a letter in it. The
// value is weighed by its characters with the same helper as the
// SEC-SECRET-ASSIGN path rule (weighPath, GAP-0671): ids are at most a
// quarter of its letters and digits, so a base64 password that holds a slash
// (random case, digits, no word) is not a path, and a piece that mixes upper
// case, lower case and digits is an id.
func relativePathValue(v string) bool {
	trimmed := strings.TrimSuffix(v, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.IndexFunc(p, unicode.IsLetter) < 0 {
			return false
		}
		for i := 0; i < len(p); i++ {
			if !isIdentByte(p[i]) && p[i] != '.' && p[i] != '-' {
				return false
			}
		}
	}
	return weighPath(trimmed, true).namesOnly()
}

// valueNamesItsKey reports a fill-in that names its own key: words only,
// joined by - _ or ., one of them the last word of the key
// (your-password-here for password, your_db_password_here for
// DB_PASSWORD). The key comes from the match, not from a list.
func valueNamesItsKey(key, value string) bool {
	keyWord := strings.ToLower(lastKeyWord(key))
	if keyWord == "" {
		return false
	}
	words := strings.FieldsFunc(value, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	if len(words) < 2 {
		return false
	}
	named := false
	for _, w := range words {
		if !wordOnly(w) {
			return false
		}
		named = named || strings.EqualFold(w, keyWord)
	}
	return named
}

// lastKeyWord is the last word of an identifier: after the last _ or -, or
// at the last lower-to-upper change (userPwd: Pwd, MYSQL_PWD: PWD).
func lastKeyWord(key string) string {
	key = strings.TrimRight(key, "_-0123456789")
	if i := strings.LastIndexAny(key, "_-"); i >= 0 {
		key = key[i+1:]
	}
	for i := len(key) - 1; i > 0; i-- {
		if key[i] >= 'A' && key[i] <= 'Z' && key[i-1] >= 'a' && key[i-1] <= 'z' {
			return key[i:]
		}
	}
	return key
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
// path of two or more names (a.b, a->b, A::B, a?.b), a call or index on a
// name (getpass(, env[, Optional[str]), or a name and the colon that ends a
// condition (stored_password:).
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
	case ':':
		// A name that ends a condition or opens a block: the right side of
		// a comparison (if password == stored_password:), not a value.
		return rest == ":"
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
	if candidate == "" || obviousCredentialPlaceholder(candidate) || constantNameValue(candidate) {
		return false
	}
	letter, digit := false, false
	for _, r := range candidate {
		letter = letter || unicode.IsLetter(r)
		digit = digit || unicode.IsDigit(r)
	}
	return letter && digit && credentialEntropy(compactCredential(candidate)) >= 2.5
}

// constantNameValue reports an UPPER_SNAKE constant name of three or more
// words, maybe numbered (YOUR_ACCESS_TOKEN_GOES_HERE_1): a name a document
// puts where a token goes, not a token (GAP-0522).
func constantNameValue(v string) bool {
	words := strings.Split(v, "_")
	if len(words) < 3 {
		return false
	}
	for i, w := range words {
		if w == "" {
			return false
		}
		upper, digits := true, true
		for j := 0; j < len(w); j++ {
			upper = upper && w[j] >= 'A' && w[j] <= 'Z'
			digits = digits && w[j] >= '0' && w[j] <= '9'
		}
		if !upper && (!digits || i != len(words)-1) {
			return false
		}
	}
	return true
}
