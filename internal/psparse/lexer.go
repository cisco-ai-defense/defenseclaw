// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxInput caps the source the lexer will scan. Beyond it the lexer stops and
// the parser records ReasonTruncated. Chosen well above any real tool-call
// command; PowerShell payloads in the corpora are far smaller.
const maxInput = 1 << 20 // 1 MiB

// lexer turns PowerShell source into a token slice. It never panics: every
// malformed construct becomes a TokError with a Reason, and scanning
// continues from the next plausible boundary.
type lexer struct {
	src   string
	runes []rune
	pos   []int // byte offset of runes[i]
	i     int   // index into runes
	toks  []Token
	// prevSignificant is the kind of the last non-newline, non-comment token;
	// used to decide whether '-' / '.' / '@' start an operator or a word, and
	// whether we are at a command-start position.
	prevSignificant TokenKind
	prevWasValue    bool // last token could end a value (for dash disambiguation)
	atStart         bool // at a token boundary (for '#' comment vs bareword)
}

func newLexer(src string) *lexer {
	if len(src) > maxInput {
		src = src[:maxInput]
	}
	l := &lexer{src: src, atStart: true}
	l.runes = make([]rune, 0, len(src))
	l.pos = make([]int, 0, len(src)+1)
	for off := 0; off < len(src); {
		r, w := utf8.DecodeRuneInString(src[off:])
		if r == utf8.RuneError && w == 1 {
			r = rune(src[off])
		}
		l.runes = append(l.runes, r)
		l.pos = append(l.pos, off)
		off += w
	}
	l.pos = append(l.pos, len(src))
	return l
}

func (l *lexer) byteAt(ri int) int {
	if ri >= len(l.pos) {
		return len(l.src)
	}
	return l.pos[ri]
}

func (l *lexer) slice(a, b int) string { return l.src[l.byteAt(a):l.byteAt(b)] }

func (l *lexer) peek(n int) rune {
	j := l.i + n
	if j < 0 || j >= len(l.runes) {
		return -1
	}
	return l.runes[j]
}

func (l *lexer) cur() rune { return l.peek(0) }

func (l *lexer) emit(k TokenKind, a, b int) {
	t := Token{Kind: k, Raw: l.slice(a, b), Start: l.byteAt(a), End: l.byteAt(b)}
	t.Value = t.Raw
	l.toks = append(l.toks, t)
	if k != TokNewline && k != TokComment {
		l.prevSignificant = k
		l.prevWasValue = k == TokVariable || k == TokNumber || k == TokString ||
			k == TokGeneric || k == TokRParen || k == TokRBracket || k == TokRBrace
	}
	l.setAtStart(k)
}

func (l *lexer) push(t Token) {
	l.toks = append(l.toks, t)
	if t.Kind != TokNewline && t.Kind != TokComment {
		l.prevSignificant = t.Kind
		l.prevWasValue = t.Kind == TokVariable || t.Kind == TokNumber || t.Kind == TokString ||
			t.Kind == TokGeneric || t.Kind == TokRParen || t.Kind == TokRBracket || t.Kind == TokRBrace
	}
	l.setAtStart(t.Kind)
}

// setAtStart records whether the next token begins at a token boundary (after a
// separator, opener or comment/newline), which decides whether a '#' starts a
// line comment or is part of a generic token.
func (l *lexer) setAtStart(k TokenKind) {
	switch k {
	case TokNewline, TokComment, TokSemi, TokPipe, TokPipePipe, TokAmpAmp, TokAmp,
		TokLParen, TokLBrace, TokLBracket, TokComma, TokAtParen, TokAtBrace:
		l.atStart = true
	default:
		l.atStart = false
	}
}

// lex scans the whole source and returns the token slice, always ending in EOF.
func (l *lexer) lex() []Token {
	for l.i < len(l.runes) {
		r := l.cur()
		switch {
		case r == ' ' || r == '\t' || r == '\r' || r == '\f' || r == 0xA0:
			l.i++
			l.atStart = true
		case r == '`' && (l.peek(1) == '\n' || l.peek(1) == '\r' || l.peek(1) == -1):
			// line continuation: swallow backtick + newline
			l.i++
			if l.cur() == '\r' {
				l.i++
			}
			if l.cur() == '\n' {
				l.i++
			}
			l.atStart = true
		case r == '\n':
			a := l.i
			l.i++
			l.emit(TokNewline, a, l.i)
		case r == '#' && l.atStart:
			l.lexLineComment()
		case r == '<' && l.peek(1) == '#':
			l.lexBlockComment()
		case isSingleQuote(r):
			l.lexSingleString()
		case isDoubleQuote(r):
			l.lexDoubleString()
		case r == '@' && (l.peek(1) == '"' || l.peek(1) == '\''):
			l.lexHereString()
		case r == '@' && l.peek(1) == '(':
			a := l.i
			l.i += 2
			l.emit(TokAtParen, a, l.i)
		case r == '@' && l.peek(1) == '{':
			a := l.i
			l.i += 2
			l.emit(TokAtBrace, a, l.i)
		case r == '@' && isNameStart(l.peek(1)):
			l.lexSplatVariable()
		case r == '$':
			l.lexDollar()
		case isDash(r):
			l.lexDash()
		case r == '*' && l.peek(1) == '>':
			a := l.i
			l.i++ // consume *
			l.scanRedirectFromHere(a, "*")
		case r >= '1' && r <= '6' && l.peek(1) == '>':
			a := l.i
			l.i++ // consume the stream digit
			l.scanRedirectFromHere(a, string(r))
		case unicode.IsDigit(r):
			l.lexNumber()
		case r == '.' && unicode.IsDigit(l.peek(1)) && !l.prevWasValue:
			l.lexNumber()
		default:
			l.lexOperatorOrWord()
		}
	}
	l.emit(TokEOF, l.i, l.i)
	return l.toks
}

func (l *lexer) lexLineComment() {
	a := l.i
	for l.i < len(l.runes) && l.cur() != '\n' {
		l.i++
	}
	l.emit(TokComment, a, l.i)
}

func (l *lexer) lexBlockComment() {
	a := l.i
	l.i += 2
	for l.i < len(l.runes) {
		if l.cur() == '#' && l.peek(1) == '>' {
			l.i += 2
			l.emit(TokComment, a, l.i)
			return
		}
		l.i++
	}
	// unterminated
	t := Token{Kind: TokError, Value: ReasonUnterminated, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	l.push(t)
}

func (l *lexer) lexSingleString() {
	a := l.i
	l.i++ // opening '
	for l.i < len(l.runes) {
		if isSingleQuote(l.cur()) {
			if isSingleQuote(l.peek(1)) { // a doubled quote escapes one
				l.i += 2
				continue
			}
			l.i++
			t := Token{Kind: TokString, Str: StrSingle, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
			t.Value = t.Raw
			l.push(t)
			return
		}
		l.i++
	}
	l.push(Token{Kind: TokError, Str: StrSingle, Value: ReasonUnterminated, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)})
}

func (l *lexer) lexDoubleString() {
	a := l.i
	l.i++      // opening "
	depth := 0 // $( ) nesting so a ) inside does not confuse us
	for l.i < len(l.runes) {
		r := l.cur()
		switch {
		case r == '`':
			l.i += 2 // backtick escapes the next rune
			continue
		case r == '$' && l.peek(1) == '(':
			depth++
			l.i += 2
			continue
		case r == ')' && depth > 0:
			depth--
			l.i++
			continue
		case isDoubleQuote(r) && depth == 0:
			if isDoubleQuote(l.peek(1)) { // a doubled quote escapes one
				l.i += 2
				continue
			}
			l.i++
			t := Token{Kind: TokString, Str: StrDouble, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
			t.Value = t.Raw
			l.push(t)
			return
		}
		l.i++
	}
	l.push(Token{Kind: TokError, Str: StrDouble, Value: ReasonUnterminated, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)})
}

func (l *lexer) lexHereString() {
	a := l.i
	quote := l.peek(1) // ' or "
	kind := StrHereDouble
	if quote == '\'' {
		kind = StrHereSingle
	}
	l.i += 2 // @ and quote
	// Per the grammar the rest of the opening line must be blank; we tolerate
	// trailing whitespace. Skip to end of line.
	for l.i < len(l.runes) && l.cur() != '\n' {
		l.i++
	}
	if l.cur() == '\n' {
		l.i++
	}
	// Terminator: a line that begins with  "@  (or '@), i.e. the quote then @
	// at the start of a line.
	for l.i < len(l.runes) {
		atLineStart := l.i == 0 || l.runes[l.i-1] == '\n'
		if atLineStart && l.cur() == quote && l.peek(1) == '@' {
			l.i += 2
			t := Token{Kind: TokString, Str: kind, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
			t.Value = t.Raw
			l.push(t)
			return
		}
		l.i++
	}
	l.push(Token{Kind: TokError, Str: kind, Value: ReasonUnterminated, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)})
}

func (l *lexer) lexSplatVariable() {
	a := l.i
	l.i++ // @
	name, scope := l.scanVarName()
	t := Token{Kind: TokVariable, Splat: true, VarName: name, VarScope: scope, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	t.Value = t.Raw
	l.push(t)
}

func (l *lexer) lexDollar() {
	if l.peek(1) == '(' {
		a := l.i
		l.i += 2
		l.emit(TokDollarParen, a, l.i)
		return
	}
	a := l.i
	l.i++ // $
	if l.cur() == '{' {
		// ${ name } - name may contain escaped chars and almost anything but }
		l.i++
		start := l.i
		for l.i < len(l.runes) && l.cur() != '}' {
			if l.cur() == '`' {
				l.i++
			}
			l.i++
		}
		if l.i > len(l.runes) { // a trailing backtick escape can overshoot
			l.i = len(l.runes)
		}
		name := string(l.runes[start:l.i])
		if l.cur() == '}' {
			l.i++
		}
		scope := ""
		if idx := strings.IndexByte(name, ':'); idx >= 0 {
			scope = name[:idx]
			name = name[idx+1:]
		}
		t := Token{Kind: TokVariable, VarName: name, VarScope: scope, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	// special single-char variables
	switch l.cur() {
	case '$', '?', '^':
		l.i++
		t := Token{Kind: TokVariable, VarName: string(l.runes[l.i-1]), Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	name, scope := l.scanVarName()
	if name == "" && scope == "" {
		// a lone $ ; treat as generic word
		t := Token{Kind: TokGeneric, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	t := Token{Kind: TokVariable, VarName: name, VarScope: scope, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	t.Value = t.Raw
	l.push(t)
}

// scanVarName reads a (possibly scoped) variable name after the $/@ sigil has
// been consumed, advancing l.i. A scope is name chars followed by a single ':'.
func (l *lexer) scanVarName() (name, scope string) {
	start := l.i
	for l.i < len(l.runes) && isNameChar(l.cur()) {
		l.i++
	}
	first := string(l.runes[start:l.i])
	if l.cur() == ':' && l.i > start {
		// scope or drive qualifier
		l.i++
		nstart := l.i
		for l.i < len(l.runes) && isNameChar(l.cur()) {
			l.i++
		}
		return string(l.runes[nstart:l.i]), first
	}
	return first, ""
}

func (l *lexer) lexDash() {
	// --% stop-parsing: the remainder of the logical line is verbatim and must
	// not be tokenized (an apostrophe or quote after it is literal text).
	if l.peek(1) == '-' && l.peek(2) == '%' {
		a := l.i
		l.i += 3
		l.emit(TokStopParse, a, l.i)
		for l.i < len(l.runes) && isSpace(l.cur()) {
			l.i++
		}
		vs := l.i
		for l.i < len(l.runes) && l.cur() != '\n' {
			l.i++
		}
		if l.i > vs {
			raw := l.slice(vs, l.i)
			l.push(Token{Kind: TokGeneric, Str: StrBare, Raw: raw, Value: raw, Start: l.byteAt(vs), End: l.byteAt(l.i)})
		}
		return
	}
	// '--name' is a double-dash bareword argument in PowerShell, not an
	// operator; only a bare '--' (decrement / no following name) is the operator.
	if l.peek(1) == '-' {
		if isNameStart(l.peek(2)) || l.peek(2) == '/' {
			l.lexBareword()
			return
		}
		a := l.i
		l.i += 2
		t := Token{Kind: TokOperator, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	// -Name parameter or -word operator: a dash followed by a letter/underscore
	if isNameStart(l.peek(1)) {
		a := l.i
		l.i++ // dash
		start := l.i
		for l.i < len(l.runes) && isNameChar(l.cur()) {
			l.i++
		}
		name := string(l.runes[start:l.i])
		hasColon := false
		if l.cur() == ':' {
			hasColon = true
			l.i++
		}
		t := Token{Kind: TokParameter, Value: name, VarName: name, HasColon: hasColon, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		l.push(t)
		return
	}
	// -= operator
	if l.peek(1) == '=' {
		a := l.i
		l.i += 2
		t := Token{Kind: TokOperator, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	// bare minus
	a := l.i
	l.i++
	t := Token{Kind: TokOperator, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	t.Value = t.Raw
	l.push(t)
}

func (l *lexer) lexNumber() {
	a := l.i
	if l.cur() == '0' && (l.peek(1) == 'x' || l.peek(1) == 'X') {
		l.i += 2
		for l.i < len(l.runes) && isHex(l.cur()) {
			l.i++
		}
	} else {
		for l.i < len(l.runes) && (unicode.IsDigit(l.cur()) || l.cur() == '.') {
			l.i++
		}
		if l.cur() == 'e' || l.cur() == 'E' {
			l.i++
			if l.cur() == '+' || l.cur() == '-' {
				l.i++
			}
			for l.i < len(l.runes) && unicode.IsDigit(l.cur()) {
				l.i++
			}
		}
	}
	// multiplier / type suffix (kb mb gb tb pb, l, d)
	for l.i < len(l.runes) && isLetter(l.cur()) {
		l.i++
	}
	raw := l.slice(a, l.i)
	// A run with more than one dot (an IP or a version) is not a number: re-lex
	// the whole token as a bareword string to match the reference parser.
	if strings.Count(raw, ".") > 1 {
		l.i = a
		l.lexBareword()
		return
	}
	t := Token{Kind: TokNumber, Raw: raw, Start: l.byteAt(a), End: l.byteAt(l.i)}
	t.Value = t.Raw
	l.push(t)
}

// lexOperatorOrWord handles everything else: structural punctuation, operator
// symbols, and barewords (unquoted strings / command names).
func (l *lexer) lexOperatorOrWord() {
	r := l.cur()
	a := l.i
	switch r {
	case ';':
		l.i++
		l.emit(TokSemi, a, l.i)
		return
	case ',':
		l.i++
		l.emit(TokComma, a, l.i)
		return
	case '|':
		if l.peek(1) == '|' {
			l.i += 2
			l.emit(TokPipePipe, a, l.i)
			return
		}
		l.i++
		l.emit(TokPipe, a, l.i)
		return
	case '&':
		if l.peek(1) == '&' {
			l.i += 2
			l.emit(TokAmpAmp, a, l.i)
			return
		}
		l.i++
		l.emit(TokAmp, a, l.i)
		return
	case '(':
		l.i++
		l.emit(TokLParen, a, l.i)
		return
	case ')':
		l.i++
		l.emit(TokRParen, a, l.i)
		return
	case '{':
		l.i++
		l.emit(TokLBrace, a, l.i)
		return
	case '}':
		l.i++
		l.emit(TokRBrace, a, l.i)
		return
	case '[':
		l.i++
		l.emit(TokLBracket, a, l.i)
		return
	case ']':
		l.i++
		l.emit(TokRBracket, a, l.i)
		return
	case '.':
		// member access "." directly after a value with no space: $x.Prop
		if l.prevWasValue && !isSpace(l.peek(-1)) {
			l.i++
			l.emit(TokDot, a, l.i)
			return
		}
		// a '.' glued to a path or name char begins a bareword (relative path
		// or a hidden file such as .ssh, .git, .env), not a dot-source operator
		if l.peek(1) == '/' || l.peek(1) == '\\' || l.peek(1) == '.' || isNameStart(l.peek(1)) {
			l.lexBareword()
			return
		}
		// otherwise a dot-source operator (dot then space) or a stray dot
		l.i++
		l.emit(TokDot, a, l.i)
		return
	case ':':
		if l.peek(1) == ':' {
			l.i += 2
			t := Token{Kind: TokOperator, Value: "::", Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
			l.push(t)
			return
		}
		// :label  or  stray colon
		if isNameStart(l.peek(1)) {
			l.i++
			for l.i < len(l.runes) && isNameChar(l.cur()) {
				l.i++
			}
			l.emit(TokLabel, a, l.i)
			return
		}
		l.lexBareword()
		return
	case '=', '+', '*', '/', '%', '!', '<', '>', '?':
		l.lexSymbolOperator()
		return
	}
	l.lexBareword()
}

func (l *lexer) lexSymbolOperator() {
	a := l.i
	r := l.cur()
	// A leading '/' followed by a letter or another '/' starts a bareword
	// (a command switch like /ve, or a POSIX path), not a division operator.
	if r == '/' {
		if n := l.peek(1); isLetter(n) || n == '/' {
			l.lexBareword()
			return
		}
	}
	// '%' glued to a name char begins a bareword (a cmd-style %VAR% or a
	// percent-prefixed token), not the modulo / ForEach alias operator.
	if r == '%' && isNameChar(l.peek(1)) {
		l.lexBareword()
		return
	}
	// redirections: > >> 2> *> n> n>> n>&m  and input <
	if r == '>' {
		l.scanRedirectFromHere(a, "")
		return
	}
	if r == '<' {
		l.i++
		t := Token{Kind: TokRedir, Value: "<", Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		l.push(t)
		return
	}
	// compound assignment / increment operators
	two := string(r)
	if n := l.peek(1); n == '=' || (r == '+' && n == '+') || (r == '?' && n == '?') {
		two = string(r) + string(n)
	}
	switch two {
	case "+=", "*=", "/=", "%=", "++", "??":
		if two == "??" && l.peek(2) == '=' {
			l.i += 3
			t := Token{Kind: TokOperator, Value: "??=", Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
			l.push(t)
			return
		}
		l.i += 2
		t := Token{Kind: TokOperator, Value: two, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		l.push(t)
		return
	}
	l.i++
	t := Token{Kind: TokOperator, Value: string(r), Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	l.push(t)
}

// scanRedirectFromHere scans a redirection operator starting at the current
// position (l.cur()=='>'), with an optional preceding stream number captured
// by the caller in numPrefix.
func (l *lexer) scanRedirectFromHere(a int, numPrefix string) {
	l.i++ // first >
	op := numPrefix + ">"
	merge := ""
	if l.cur() == '>' {
		l.i++
		op = numPrefix + ">>"
	}
	if l.cur() == '&' {
		l.i++
		if unicode.IsDigit(l.cur()) {
			merge = string(l.cur())
			l.i++
		}
	}
	t := Token{Kind: TokRedir, Value: op, ColonArg: merge, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
	l.push(t)
}

// lexBareword reads an unquoted word (command name, path, argument). It stops
// at whitespace or a structural delimiter but allows embedded ., \, /, :, and
// treats a backtick as an escape of the next rune.
func (l *lexer) lexBareword() {
	a := l.i
	for l.i < len(l.runes) {
		r := l.cur()
		if r == '`' {
			l.i += 2
			continue
		}
		if isSpace(r) || r == '\n' || r == -1 {
			break
		}
		if strings.ContainsRune(";,|&(){}[]'\"", r) {
			break
		}
		if r == '>' || r == '<' {
			break
		}
		if r == '$' && dollarStartsVar(l.peek(1)) {
			break // a variable / $( ) starts here; the bareword ends
		}
		// a redirect stream number like 2> ends the word only at the digit+>
		l.i++
	}
	if l.i == a {
		// no progress: consume one rune as an error to guarantee termination
		l.i++
		l.push(Token{Kind: TokError, Value: ReasonUnknownToken, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)})
		return
	}
	raw := l.slice(a, l.i)
	// a trailing stream redirect glued to a word (e.g. foo2>bar) is rare; keep simple.
	t := Token{Kind: TokGeneric, Str: StrBare, Raw: raw, Value: raw, Start: l.byteAt(a), End: l.byteAt(l.i)}
	l.push(t)
}

func isNameStart(r rune) bool {
	return r == '_' || r == '?' || unicode.IsLetter(r)
}
func isNameChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
func isLetter(r rune) bool { return unicode.IsLetter(r) }
func isHex(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\f' || r == 0xA0 }

// PowerShell treats several Unicode quote and dash characters the same as the
// ASCII ones (its tokenizer's special-character tables).
func isSingleQuote(r rune) bool {
	switch r {
	case '\'', '‘', '’', '‚', '‛':
		return true
	}
	return false
}
func isDoubleQuote(r rune) bool {
	switch r {
	case '"', '“', '”', '„', '‟':
		return true
	}
	return false
}
func isDash(r rune) bool {
	switch r {
	case '-', '–', '—', '―':
		return true
	}
	return false
}
