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

// truncatedInput is the one byte bound of a PowerShell reading (GAP-2086): a
// source of maxInput bytes or more is cut here (or may have been cut to
// maxInput by its caller), so its reading is a truncated row. Parse reads it
// (its first maxInput bytes, with a ReasonTruncated diagnostic) and the port
// declines it (FromPwshparse).
func truncatedInput(src string) bool { return len(src) >= maxInput }

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
	// wordOpen: the last token is a piece of an unquoted word that pwsh still
	// scans as one generic token (a bareword, variable, number or parameter,
	// or a quoted piece glued to one). A quote, '#' or '<#' glued to an open
	// word continues that word; it does not start a token (GAP-1850).
	wordOpen bool
	// stmtLead is the kind of the first significant token of the current
	// statement (TokEOF until one is seen). An assignment operator in a
	// statement led by a variable is an expression operator, so the next rune
	// starts a fresh token, where '#' and '<#' begin comments.
	stmtLead TokenKind
	// leadStack saves stmtLead across ( ), $( ), @( ), { } and @{ } so the
	// statement that encloses a group keeps its lead after the group closes.
	leadStack  []TokenKind
	braceStack []byte // 'h' for an open @{ hashtable, 'b' for a { scriptblock
	// diags are parse errors the lexer found but read past (a here-string
	// whose $( ) never closes); Parse reports them with every TokError.
	diags []Diagnostic
}

func newLexer(src string) *lexer {
	if len(src) > maxInput {
		src = src[:maxInput]
	}
	l := &lexer{src: src, atStart: true, stmtLead: TokEOF}
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
	l.push(t)
}

func (l *lexer) push(t Token) {
	glued := false
	if n := len(l.toks); n > 0 {
		glued = l.wordOpen && l.toks[n-1].End == t.Start
	}
	l.toks = append(l.toks, t)
	k := t.Kind
	if k != TokNewline && k != TokComment {
		l.prevSignificant = k
		l.prevWasValue = k == TokVariable || k == TokNumber || k == TokString ||
			k == TokGeneric || k == TokRParen || k == TokRBracket || k == TokRBrace
	}
	l.setAtStart(k)
	switch k {
	case TokGeneric, TokVariable, TokNumber, TokParameter:
		l.wordOpen = true
	case TokString:
		// A quoted piece glued to an open word is part of that word, so the
		// next rune is not at a token boundary: a"b"#x is one word in pwsh.
		// A string that starts a token ends it: "b"#x is "b" then a comment.
		l.wordOpen = glued && (t.Str == StrSingle || t.Str == StrDouble)
		if l.wordOpen {
			l.atStart = false
		}
	case TokLBracket, TokRBracket:
		// In command arguments pwsh scans [int], a[# and .\a[1] as one generic
		// word, so a '#' glued after a bracket is word text, not a comment.
		l.wordOpen = l.stmtLead == TokGeneric
		if l.wordOpen {
			l.atStart = false
		}
	default:
		l.wordOpen = false
	}
	switch k {
	case TokLParen, TokLBrace, TokDollarParen, TokAtParen, TokAtBrace:
		l.leadStack = append(l.leadStack, l.stmtLead)
		l.stmtLead = TokEOF
	case TokRParen, TokRBrace:
		if n := len(l.leadStack); n > 0 {
			l.stmtLead = l.leadStack[n-1]
			l.leadStack = l.leadStack[:n-1]
		}
	case TokNewline, TokSemi, TokPipe, TokPipePipe, TokAmpAmp:
		l.stmtLead = TokEOF
	case TokComment:
	case TokOperator:
		if l.stmtLead == TokVariable && isAssignOp(t.Value) {
			// $x = ...: the right side is a new pipeline that starts at a
			// token boundary ($x =# c and $x =<# c #> are comments in pwsh).
			l.atStart = true
			l.stmtLead = TokEOF
			break
		}
		if l.stmtLead == TokEOF {
			l.stmtLead = k
		}
	default:
		if l.stmtLead == TokEOF {
			l.stmtLead = k
		}
	}
}

// isAssignOp reports whether an operator token value is an assignment.
func isAssignOp(v string) bool {
	switch v {
	case "=", "+=", "-=", "*=", "/=", "%=", "??=":
		return true
	}
	return false
}

// setAtStart records whether the next token begins at a token boundary (after a
// separator, opener or comment/newline), which decides whether a '#' starts a
// line comment or is part of a generic token.
func (l *lexer) setAtStart(k TokenKind) {
	switch k {
	case TokNewline, TokComment, TokSemi, TokPipe, TokPipePipe, TokAmpAmp, TokAmp,
		TokLParen, TokLBrace, TokLBracket, TokComma, TokAtParen, TokAtBrace,
		TokString, TokRParen, TokRBrace, TokRBracket:
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
			l.wordOpen = false
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
			l.wordOpen = false
		case r == '\n':
			a := l.i
			l.i++
			l.emit(TokNewline, a, l.i)
		case r == '#' && l.atStart:
			l.lexLineComment()
		case r == '<' && l.peek(1) == '#' && l.atStart:
			l.lexBlockComment()
		case isSingleQuote(r):
			l.lexSingleString()
		case isDoubleQuote(r):
			l.lexDoubleString()
		case r == '@' && (isDoubleQuote(l.peek(1)) || isSingleQuote(l.peek(1))):
			l.lexHereString()
		case r == '@' && l.peek(1) == '(':
			a := l.i
			l.i += 2
			l.emit(TokAtParen, a, l.i)
		case r == '@' && l.peek(1) == '{':
			a := l.i
			l.i += 2
			l.emit(TokAtBrace, a, l.i)
			l.braceStack = append(l.braceStack, 'h')
		case r == '@' && isNameStart(l.peek(1)):
			l.lexSplatVariable()
		case r == '$':
			l.lexDollar()
		case isDash(r):
			l.lexDash()
		case r == '*' && l.peek(1) == '>' && l.atStart:
			a := l.i
			l.i++ // consume *
			l.scanRedirectFromHere(a, "*")
		case r >= '1' && r <= '6' && l.peek(1) == '>' && l.atStart:
			a := l.i
			l.i++ // consume the stream digit
			l.scanRedirectFromHere(a, string(r))
		case r >= '0' && r <= '9':
			l.lexNumber()
		case r == '.' && l.peek(1) >= '0' && l.peek(1) <= '9' && l.atStart:
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
	quote := l.peek(1) // ' or " (straight or smart)
	kind := StrHereDouble
	if isSingleQuote(quote) {
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
	body := l.i
	// Terminator: a line that begins with  "@  (or '@), i.e. the quote then @
	// at the start of a line. In an expandable here-string pwsh reads a $( )
	// as code up to its matching ), and a "@ line inside it does not end the
	// string: @"<nl>$(@"<nl>x<nl>"@)<nl>"@ is one string (GAP-1853). The
	// code reading respects backtick escapes, quotes, nested strings and
	// comments, so a `$( or a quoted '$(' does not open a group.
	end, ok := scanHereBody(l.runes, body, kind == StrHereDouble, kind == StrHereDouble)
	if !ok && kind == StrHereDouble {
		// A $( ) that never closes: pwsh rejects the script. Fall back to the
		// 1.0.10 reading (the first terminator line ends the string), so the
		// text after it is still read, and record the parse error: a here-string
		// must never swallow the rest of a script as a clean parse.
		if end, ok = scanHereBody(l.runes, body, true, false); ok {
			l.diags = append(l.diags, Diagnostic{span: span{l.byteAt(a), l.byteAt(end)}, Reason: ReasonUnterminated,
				Detail: "here-string $( ) not closed; read to the first terminator line", Lexical: true})
		}
	}
	if ok {
		l.i = end
		t := Token{Kind: TokString, Str: kind, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)}
		t.Value = t.Raw
		l.push(t)
		return
	}
	l.i = len(l.runes)
	l.push(Token{Kind: TokError, Str: kind, Value: ReasonUnterminated, Raw: l.slice(a, l.i), Start: l.byteAt(a), End: l.byteAt(l.i)})
}

// scanHereBody returns the rune index just past the terminator of the
// here-string body that starts at rune i: a line that begins with the closing
// quote class (double or single) then @. With expand, a backtick escapes the
// next rune and a $( is read as code up to its matching ), so a terminator
// line inside it does not end the body. ok is false when no terminator is
// found (or a $( never closes).
func scanHereBody(rs []rune, i int, double, expand bool) (int, bool) {
	return scanNested(rs, i, scanFrame{kind: frameHere, double: double, expand: expand})
}

// scanSubexpr reads the code of a $( ) group that starts at rune i (just past
// the opening "$(") and returns the index just past its matching ).
func scanSubexpr(rs []rune, i int) (int, bool) {
	return scanNested(rs, i, scanFrame{kind: frameCode, atStart: true})
}

type scanFrameKind uint8

const (
	frameHere scanFrameKind = iota // a here-string body
	frameCode                      // the code of a $( ) group
	frameDQ                        // a "..." string inside code
)

type scanFrame struct {
	kind           scanFrameKind
	double, expand bool // frameHere: the quote class, and whether $( ) expands
	parens         int  // frameCode: open ( ) inside the group
	atStart        bool // frameCode: at a token boundary ('#' and '<#' begin comments)
}

// scanNested finds the end of the construct start opens at rune i, the way
// pwsh's tokenizer does: in code, parens nest, single-quoted strings,
// comments and backtick escapes are skipped whole, and "..." strings and
// here-strings nest with their own $( ) groups, so a ) or $( inside a quote,
// a comment or after a backtick does not count. It returns the index just
// past the construct's end; ok is false at the end of input. The frames are
// an explicit stack, so the scan is linear in the input at any nesting depth
// (the nested parse of the text carries the depth bound, ps_depth_limit).
func scanNested(rs []rune, i int, start scanFrame) (int, bool) {
	n := len(rs)
	stack := []scanFrame{start}
	pop := func() bool { stack = stack[:len(stack)-1]; return len(stack) == 0 }
	for i < n {
		top := &stack[len(stack)-1]
		r := rs[i]
		switch top.kind {
		case frameHere:
			if i > 0 && rs[i-1] == '\n' && i+1 < n && rs[i+1] == '@' &&
				((top.double && isDoubleQuote(r)) || (!top.double && isSingleQuote(r))) {
				i += 2
				if pop() {
					return i, true
				}
				continue
			}
			if top.expand {
				// A backtick before a line break does not hide the next line's
				// terminator: ending early keeps the rest of the script read.
				if r == '`' && i+1 < n && rs[i+1] != '\n' && rs[i+1] != '\r' {
					i += 2
					continue
				}
				if r == '$' && i+1 < n && rs[i+1] == '(' {
					stack = append(stack, scanFrame{kind: frameCode, atStart: true})
					i += 2
					continue
				}
			}
			i++
		case frameDQ:
			switch {
			case r == '`':
				i += 2
			case r == '$' && i+1 < n && rs[i+1] == '(':
				stack = append(stack, scanFrame{kind: frameCode, atStart: true})
				i += 2
			case isDoubleQuote(r) && i+1 < n && isDoubleQuote(rs[i+1]):
				i += 2 // a doubled quote escapes one
			case isDoubleQuote(r):
				i++
				if pop() {
					return i, true
				}
			default:
				i++
			}
		case frameCode:
			switch {
			case r == '`':
				i += 2
				top.atStart = false
			case r == '(':
				top.parens++
				top.atStart = true
				i++
			case r == ')' && top.parens == 0:
				i++
				if pop() {
					return i, true
				}
				stack[len(stack)-1].atStart = false
			case r == ')':
				top.parens--
				top.atStart = false
				i++
			case isSingleQuote(r):
				end, ok := scanSingleBody(rs, i+1)
				if !ok {
					return 0, false
				}
				i, top.atStart = end, false
			case isDoubleQuote(r):
				top.atStart = false
				stack = append(stack, scanFrame{kind: frameDQ})
				i++
			case r == '@' && i+1 < n && (isDoubleQuote(rs[i+1]) || isSingleQuote(rs[i+1])) && blankToLineEnd(rs, i+2):
				double := isDoubleQuote(rs[i+1])
				top.atStart = false
				for i < n && rs[i] != '\n' {
					i++
				}
				stack = append(stack, scanFrame{kind: frameHere, double: double, expand: double})
				i++
			case r == '#' && top.atStart:
				for i < n && rs[i] != '\n' {
					i++
				}
			case r == '<' && i+1 < n && rs[i+1] == '#' && top.atStart:
				j := i + 2
				for j+1 < n && (rs[j] != '#' || rs[j+1] != '>') {
					j++
				}
				if j+1 >= n {
					return 0, false
				}
				i, top.atStart = j+2, true
			case isSpace(r) || r == '\n' || r == ';' || r == '|' || r == '{' || r == '}' || r == '=' || r == ',':
				top.atStart = true
				i++
			default:
				top.atStart = false
				i++
			}
		}
	}
	return 0, false
}

// scanSingleBody returns the index just past the closing quote of a
// single-quoted string whose text starts at rune i (” escapes one quote).
func scanSingleBody(rs []rune, i int) (int, bool) {
	for n := len(rs); i < n; i++ {
		if isSingleQuote(rs[i]) {
			if i+1 < n && isSingleQuote(rs[i+1]) {
				i++
				continue
			}
			return i + 1, true
		}
	}
	return 0, false
}

// blankToLineEnd reports whether only blanks follow rune i up to the end of
// its line (the rest of a here-string opening line must be blank).
func blankToLineEnd(rs []rune, i int) bool {
	for n := len(rs); i < n && rs[i] != '\n'; i++ {
		if !isSpace(rs[i]) {
			return false
		}
	}
	return true
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
	// --% stop-parsing: a standalone --% (at a token boundary) makes the rest
	// of the logical line verbatim; the tail ends at a newline or an unquoted
	// pipe or &&/|| (a ; and redirects are verbatim). --%glued is a bareword.
	if isDash(l.peek(1)) && l.peek(2) == '%' {
		n := l.peek(3)
		boundary := n == -1 || n == '\n' || isSpace(n) || n == '|' || n == '&' || n == ';'
		if !boundary {
			l.lexBareword() // --%foo is a single bareword, not stop-parsing
			return
		}
		a := l.i
		l.i += 3
		l.emit(TokStopParse, a, l.i)
		for l.i < len(l.runes) && isSpace(l.cur()) {
			l.i++
		}
		vs := l.i
		var q rune
		for l.i < len(l.runes) {
			c := l.cur()
			if c == '\n' {
				break
			}
			if q == 0 && c == '|' { // unquoted | or || ends the tail
				break
			}
			if q == 0 && c == '&' && l.peek(1) == '&' { // && ends the tail; a lone & (2>&1) is verbatim
				break
			}
			if q == 0 && (c == '\'' || c == '"') {
				q = c
			} else if q != 0 && c == q {
				q = 0
			}
			l.i++
		}
		raw := l.slice(vs, l.i)
		// always emit the verbatim tail token (possibly empty) so the parser
		// can surface --% and its tail as two command elements.
		l.push(Token{Kind: TokGeneric, Str: StrBare, Raw: raw, Value: raw, Start: l.byteAt(vs), End: l.byteAt(l.i)})
		return
	}
	// '--name' is a double-dash bareword argument in PowerShell, not an
	// operator; only a bare '--' (decrement / no following name) is the operator.
	// Unicode dashes (en/em/horizontal-bar) count as dashes too, so '––x' is a
	// single bareword argument '––x', matching pwsh.
	if isDash(l.peek(1)) {
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
		for l.i < len(l.runes) {
			if isNameChar(l.cur()) {
				l.i++
				continue
			}
			if l.cur() == '`' && l.i+1 < len(l.runes) {
				// a backtick escape inside a parameter name keeps the token
				// whole (pwsh does), so -W`indowStyle is one parameter; the
				// host parser then treats it as an unknown option and fails
				// closed instead of reading its value as the script (review 4
				// R4-5).
				l.i += 2
				continue
			}
			break
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
	} else if l.cur() == '0' && (l.peek(1) == 'b' || l.peek(1) == 'B') {
		l.i += 2
		for l.i < len(l.runes) && (l.cur() == '0' || l.cur() == '1') {
			l.i++
		}
	} else {
		for l.i < len(l.runes) && ((l.cur() >= '0' && l.cur() <= '9') || l.cur() == '.') {
			l.i++
		}
		if l.cur() == 'e' || l.cur() == 'E' {
			l.i++
			if l.cur() == '+' || l.cur() == '-' {
				l.i++
			}
			for l.i < len(l.runes) && l.cur() >= '0' && l.cur() <= '9' {
				l.i++
			}
		}
	}
	// multiplier / numeric type suffix (kb mb gb tb pb, l u y s n d ...)
	letterStart := l.i
	for l.i < len(l.runes) && isLetter(l.cur()) {
		l.i++
	}
	raw := l.slice(a, l.i)
	suffix := string(l.runes[letterStart:l.i])
	// Not a number if it has more than one dot (an IP/version) or a trailing
	// letter run that is not a valid numeric suffix (7z, 1.txt): re-lex as a
	// bareword, which at statement start is a command (F14).
	if strings.Count(raw, ".") > 1 || !validNumberSuffix(suffix) {
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
		l.braceStack = append(l.braceStack, 'b')
		return
	case '}':
		l.i++
		l.emit(TokRBrace, a, l.i)
		if len(l.braceStack) > 0 {
			l.braceStack = l.braceStack[:len(l.braceStack)-1]
		}
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
	// redirections (> >> 2> *> n> n>&m, input <) are operators only at a token
	// boundary; glued to a word (a2>x, a<<b) they are part of the bareword.
	if (r == '>' || r == '<') && !l.atStart {
		l.lexBareword()
		return
	}
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
		if l.cur() >= '0' && l.cur() <= '9' {
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
	escBracket := false // an escaped `[ / `] turns off bracket-breaking for the rest of the word
	for l.i < len(l.runes) {
		r := l.cur()
		if r == '`' {
			if l.peek(1) == 'u' && l.peek(2) == '{' { // `u{hex} escape stays in the word
				escBracket = true // `u{5B}/`u{5D} may be a bracket; keep the word whole
				l.i += 3
				for l.i < len(l.runes) && l.cur() != '}' {
					l.i++
				}
				if l.cur() == '}' {
					l.i++
				}
				continue
			}
			if l.peek(1) == '[' || l.peek(1) == ']' {
				// an escaped bracket is a literal part of the bareword; keep the
				// whole token together so C:\tmp\`[a]\..\x stays one argument
				// (non-static via the Static allowlist) and the tail does not
				// become a spurious command (review 3 R1).
				escBracket = true
			}
			l.i += 2
			continue
		}
		if isSpace(r) || r == '\n' || r == -1 {
			break
		}
		if (r == '[' || r == ']') && !escBracket {
			break
		}
		if r == '=' && len(l.braceStack) > 0 && l.braceStack[len(l.braceStack)-1] == 'h' {
			// inside @{ }, '=' separates a key from its value; end the key (and
			// any bareword) here so the value's commands are parsed, not glued
			// into the key token (review 4 R4-1).
			break
		}
		if strings.ContainsRune(";,|&(){}", r) || isSingleQuote(r) || isDoubleQuote(r) {
			break
		}
		if r == '$' && dollarStartsVar(l.peek(1)) {
			break // a variable / ${ } / $( ) starts here; the bareword ends
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

// validNumberSuffix reports whether the trailing letters of a numeric literal
// form a valid PowerShell multiplier and/or type suffix. Anything else means
// the token is a bareword, not a number.
func validNumberSuffix(s string) bool {
	if s == "" {
		return true
	}
	s = strings.ToLower(s)
	// pwsh order is <type suffix><multiplier>: 1lkb = 1L then kb (valid);
	// 1kbl = kb then l is not a number (a bareword). Strip an optional type
	// suffix first, then an optional multiplier (review 4 R11).
	for _, t := range []string{"ul", "lu", "uy", "us", "l", "u", "y", "s", "n", "d"} {
		if strings.HasPrefix(s, t) {
			s = s[len(t):]
			break
		}
	}
	for _, m := range []string{"kb", "mb", "gb", "tb", "pb"} {
		if s == m {
			s = ""
			break
		}
	}
	return s == ""
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
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
