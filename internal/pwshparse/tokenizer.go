// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

type tokenizerMode uint8

const (
	modeCommand tokenizerMode = iota
	modeExpression
	modeTypeName
	modeSignature
)

const invalidChar char = 0xffff
const maxUnicodeHexDigits = 6

var keywordTable = map[string]TokenKind{}
var operatorTable = map[string]TokenKind{}

func init() {
	kw := []string{"elseif", "if", "else", "switch", "foreach", "from", "in", "for", "while", "until", "do", "try",
		"catch", "finally", "trap", "data", "return", "continue", "break", "exit", "throw", "begin", "process", "end",
		"dynamicparam", "function", "filter", "param", "class", "define", "var", "using", "workflow", "parallel",
		"sequence", "inlinescript", "configuration", "public", "private", "static", "interface", "enum", "namespace",
		"module", "type", "assembly", "command", "hidden", "base", "default", "clean"}
	kk := []TokenKind{TkElseIf, TkIf, TkElse, TkSwitch, TkForeach, TkFrom, TkIn, TkFor, TkWhile, TkUntil, TkDo, TkTry,
		TkCatch, TkFinally, TkTrap, TkData, TkReturn, TkContinue, TkBreak, TkExit, TkThrow, TkBegin, TkProcess, TkEnd,
		TkDynamicparam, TkFunction, TkFilter, TkParam, TkClass, TkDefine, TkVar, TkUsing, TkWorkflow, TkParallel,
		TkSequence, TkInlineScript, TkConfiguration, TkPublic, TkPrivate, TkStatic, TkInterface, TkEnum, TkNamespace,
		TkModule, TkType, TkAssembly, TkCommand, TkHidden, TkBase, TkDefault, TkClean}
	for i := range kw {
		keywordTable[kw[i]] = kk[i]
	}
	op := []string{"bnot", "not", "eq", "ieq", "ceq", "ne", "ine", "cne", "ge", "ige", "cge", "gt", "igt", "cgt", "lt",
		"ilt", "clt", "le", "ile", "cle", "like", "ilike", "clike", "notlike", "inotlike", "cnotlike", "match", "imatch",
		"cmatch", "notmatch", "inotmatch", "cnotmatch", "replace", "ireplace", "creplace", "contains", "icontains",
		"ccontains", "notcontains", "inotcontains", "cnotcontains", "in", "iin", "cin", "notin", "inotin", "cnotin",
		"split", "isplit", "csplit", "isnot", "is", "as", "f", "and", "band", "or", "bor", "xor", "bxor", "join", "shl", "shr"}
	ok := []TokenKind{TkBnot, TkNot, TkIeq, TkIeq, TkCeq, TkIne, TkIne, TkCne, TkIge, TkIge, TkCge, TkIgt, TkIgt, TkCgt,
		TkIlt, TkIlt, TkClt, TkIle, TkIle, TkCle, TkIlike, TkIlike, TkClike, TkInotlike, TkInotlike, TkCnotlike, TkImatch,
		TkImatch, TkCmatch, TkInotmatch, TkInotmatch, TkCnotmatch, TkIreplace, TkIreplace, TkCreplace, TkIcontains,
		TkIcontains, TkCcontains, TkInotcontains, TkInotcontains, TkCnotcontains, TkIin, TkIin, TkCin, TkInotin,
		TkInotin, TkCnotin, TkIsplit, TkIsplit, TkCsplit, TkIsNot, TkIs, TkAs, TkFormat, TkAnd, TkBand, TkOr, TkBor,
		TkXor, TkBxor, TkJoin, TkShl, TkShr}
	for i := range op {
		operatorTable[op[i]] = ok[i]
	}
}

// lookupKeyword is s_keywordTable (case-insensitive).
func lookupKeyword(s string) (TokenKind, bool) {
	k, ok := keywordTable[strings.ToLower(s)]
	return k, ok
}

// lookupKeywordChars is lookupKeyword over UTF-16 text; ASCII text of keyword length is looked up without allocating.
func lookupKeywordChars(cs []char) (TokenKind, bool) {
	const maxKeywordLen = 13 // "configuration"
	if len(cs) == 0 || len(cs) > maxKeywordLen {
		if len(cs) > maxKeywordLen {
			for _, c := range cs {
				if c >= 0x80 {
					return lookupKeyword(fromUTF16(cs))
				}
			}
		}
		return 0, false
	}
	var buf [maxKeywordLen]byte
	for i, c := range cs {
		if c >= 0x80 {
			return lookupKeyword(fromUTF16(cs))
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = byte(c)
	}
	k, ok := keywordTable[string(buf[:len(cs)])]
	return k, ok
}

func lookupOperator(s string) (TokenKind, bool) {
	k, ok := operatorTable[strings.ToLower(s)]
	return k, ok
}

type tokenizerState struct {
	nestedAdj  int
	script     []char
	tokenStart int
	curIndex   int
	first      *Token
	last       *Token
	skipped    *bitSet
	tokenList  []*Token
	hasList    bool
}

// tokenizer is the PowerShell lexer. It is driven by the parser, which sets
// the mode before each token request.
type tokenizer struct {
	p *Parser

	mode                   tokenizerMode
	allowSignedNumbers     bool
	forceEndNumberOnTernOp bool
	wantSimpleName         bool
	inWorkflowContext      bool

	script     []char
	nestedAdj  int
	skipped    *bitSet
	tokenStart int
	curIndex   int

	// tokenList is nil when the caller does not want the token stream.
	tokenList  []*Token
	wantTokens bool
	// slab hands out Tokens in chunks (one allocation per chunk instead of one per token).
	slab       []Token
	slabGrow   uint8
	firstToken *Token
	lastToken  *Token
}

func initTokenizer(t *tokenizer, p *Parser, src []char, wantTokens bool) {
	t.p, t.script, t.wantTokens = p, src, wantTokens
	if wantTokens {
		t.tokenList = make([]*Token, 0, len(src)/3+4)
	}
	t.mode = modeCommand
}

func (t *tokenizer) inCommandMode() bool    { return t.mode == modeCommand }
func (t *tokenizer) inExpressionMode() bool { return t.mode == modeExpression }
func (t *tokenizer) inTypeNameMode() bool   { return t.mode == modeTypeName }
func (t *tokenizer) inSignatureMode() bool  { return t.mode == modeSignature }

func (t *tokenizer) startNestedScan(nested *Token) tokenizerState {
	ts := tokenizerState{
		nestedAdj: t.nestedAdj, script: t.script, tokenStart: t.tokenStart, curIndex: t.curIndex,
		first: t.firstToken, last: t.lastToken, skipped: t.skipped, tokenList: t.tokenList, hasList: t.wantTokens,
	}
	t.curIndex = 0
	t.nestedAdj = nested.Start
	if p := t.p; p != nil {
		if p.nestedWork += len(nested.Value); p.nestedWork > p.nestedBudget {
			if !p.Unsupported {
				p.markUnsupported()
				p.reportError(extent{nested.Start, nested.Start}, "ParseTooDeep")
			}
			t.script = nil
			t.tokenStart = 0
			t.skipped = nil
			if t.wantTokens {
				t.tokenList = nil
			}
			return ts
		}
	}
	t.script = toUTF16(nested.Value)
	t.tokenStart = 0
	if nested.x != nil {
		t.skipped = nested.x.skipped
	} else {
		t.skipped = nil
	}
	if t.wantTokens {
		t.tokenList = nil
	}
	return ts
}

func (t *tokenizer) finishNestedScan(ts tokenizerState) {
	t.curIndex = ts.curIndex
	t.nestedAdj = ts.nestedAdj
	t.script = ts.script
	t.tokenStart = ts.tokenStart
	t.firstToken = ts.first
	t.lastToken = ts.last
	t.skipped = ts.skipped
	t.tokenList = ts.tokenList
}

func (t *tokenizer) getChar() char {
	cur := t.curIndex
	t.curIndex++
	if cur >= len(t.script) {
		return 0
	}
	return t.script[cur]
}

func (t *tokenizer) ungetChar() { t.curIndex-- }

func (t *tokenizer) peekChar() char {
	if t.curIndex >= len(t.script) {
		return 0
	}
	return t.script[t.curIndex]
}

func (t *tokenizer) skipChar() { t.curIndex++ }

func (t *tokenizer) atEOF() bool { return t.curIndex > len(t.script) }

func (t *tokenizer) skipNewlines(skipSemis bool) {
again:
	c := t.getChar()
	switch c {
	case ' ', '\t', '\f', '\v', noBreakSpace, nextLine:
		t.skipWhiteSpace()
		goto again
	case '\r', '\n':
		t.scanNewline(c)
		goto again
	case ';':
		if skipSemis {
			t.scanSemicolon()
			goto again
		}
	case '#':
		t.tokenStart = t.curIndex - 1
		t.scanLineComment()
		goto again
	case '<':
		if t.peekChar() == '#' {
			t.tokenStart = t.curIndex - 1
			t.skipChar()
			t.scanBlockComment()
			goto again
		}
	case '`':
		c1 := t.getChar()
		if c1 == '\n' || c1 == '\r' {
			t.scanLineContinuation(c1)
			goto again
		}
		if isWhitespace(c1) {
			t.skipWhiteSpace()
			goto again
		}
		t.ungetChar()
	default:
		if isWhitespace(c) {
			t.skipWhiteSpace()
			goto again
		}
	}
	t.ungetChar()
}

func (t *tokenizer) skipWhiteSpace() {
	for isWhitespace(t.peekChar()) {
		t.skipChar()
	}
}

func (t *tokenizer) scanNewline(c char) {
	t.tokenStart = t.curIndex - 1
	t.normalizeCRLF(c)
	if t.wantTokens {
		t.newToken(TkNewLine)
	}
}

func (t *tokenizer) scanSemicolon() {
	t.tokenStart = t.curIndex - 1
	if t.wantTokens {
		t.newToken(TkSemi)
	}
}

func (t *tokenizer) scanLineContinuation(c char) {
	t.tokenStart = t.curIndex - 2
	t.normalizeCRLF(c)
	if t.wantTokens {
		t.newToken(TkLineContinuation)
	}
}

func (t *tokenizer) normalizeCRLF(c char) {
	if c == '\r' && t.peekChar() == '\n' {
		t.skipChar()
	}
}

// getRestorePoint returns the current start offset so the parser can resync.
func (t *tokenizer) getRestorePoint() int {
	t.tokenStart = t.curIndex
	return t.currentExtent().Start
}

func (t *tokenizer) resyncToken(tok *Token) { t.resync(tok.Start) }

func (t *tokenizer) resync(start int) {
	adjustment := t.nestedAdj
	if t.skipped != nil {
		for i := t.nestedAdj; i < start-1 && i < t.skipped.length(); i++ {
			if t.skipped.get(i) {
				adjustment++
			}
		}
	}
	t.curIndex = start - adjustment
	if t.curIndex > len(t.script)+1 {
		t.curIndex = len(t.script) + 1
	} else if t.curIndex < 0 {
		t.curIndex = 0
	}
	if t.firstToken != nil && t.curIndex <= t.firstToken.Start {
		t.firstToken = nil
	}
	if t.wantTokens && len(t.tokenList) > 0 {
		t.tokenList = removeTokensDuringResync(t.tokenList, start)
	}
}

func removeTokensDuringResync(list []*Token, start int) []*Token {
	removeFrom := 0
	i := len(list) - 1
	if i >= 0 && list[i].Kind == TkEndOfInput {
		i--
	}
	for ; i >= 0; i-- {
		if list[i].End <= start {
			removeFrom = i + 1
			break
		}
	}
	return list[:removeFrom]
}

func (t *tokenizer) reportError(start int, id string) {
	t.p.reportError(extent{start + t.nestedAdj, start + 1 + t.nestedAdj}, id)
}

func (t *tokenizer) reportErrorExtent(e extent, id string) { t.p.reportError(e, id) }

func (t *tokenizer) reportIncomplete(start int, id string) {
	t.p.reportIncomplete(extent{start + t.nestedAdj, t.curIndex + t.nestedAdj}, id)
}

func (t *tokenizer) newExtent(start, end int) extent {
	return extent{start + t.nestedAdj, end + t.nestedAdj}
}

func (t *tokenizer) currentExtent() extent {
	start := t.tokenStart + t.nestedAdj
	end := t.curIndex + t.nestedAdj
	if t.skipped != nil {
		i := t.nestedAdj
		for ; i < start && i < t.skipped.length(); i++ {
			if t.skipped.get(i) {
				start++
				end++
			}
		}
		for ; i < end && i < t.skipped.length(); i++ {
			if t.skipped.get(i) {
				end++
			}
		}
	}
	return extent{start, end}
}

func (t *tokenizer) scriptExtent() extent { return t.newExtent(0, len(t.script)) }

func (t *tokenizer) saveToken(tok *Token) *Token {
	if t.wantTokens {
		t.tokenList = append(t.tokenList, tok)
	}
	switch tok.Kind {
	case TkNewLine, TkLineContinuation, TkComment, TkEndOfInput:
	default:
		if t.firstToken == nil {
			t.firstToken = tok
		}
		t.lastToken = tok
	}
	return tok
}

func (t *tokenizer) mkToken(kind TokenKind, flags TokenFlags) *Token {
	e := t.currentExtent()
	if len(t.slab) == 0 {
		n := 8 << t.slabGrow
		if t.slabGrow < 4 {
			t.slabGrow++
		}
		t.slab = make([]Token, n)
	}
	tok := &t.slab[0]
	t.slab = t.slab[1:]
	tok.Kind, tok.Flags, tok.Start, tok.End = kind, flags|staticTokenFlags[kind], e.Start, e.End
	return tok
}

func (t *tokenizer) newCommentToken() *Token { return t.saveToken(t.mkToken(TkComment, 0)) }
func (t *tokenizer) newToken(kind TokenKind) *Token {
	return t.saveToken(t.mkToken(kind, 0))
}

func (t *tokenizer) newNumberToken(v *NumberValue) *Token {
	tok := t.mkToken(TkNumber, 0)
	tok.Num = v
	tok.class = tcNumber
	return t.saveToken(tok)
}

func (t *tokenizer) newParameterToken(name string, sawColon bool) *Token {
	tok := t.mkToken(TkParameter, 0)
	tok.Value = name
	tok.UsedColon = sawColon
	tok.class = tcParameter
	return t.saveToken(tok)
}

func (t *tokenizer) newVariableToken(path *VariablePath, splatted bool) *Token {
	kind := TkVariable
	if splatted {
		kind = TkSplattedVariable
	}
	tok := t.mkToken(kind, 0)
	tok.Path = path
	tok.class = tcVariable
	return t.saveToken(tok)
}

func (t *tokenizer) newStringLiteralToken(value string, kind TokenKind, flags TokenFlags) *Token {
	tok := t.mkToken(kind, flags)
	tok.Value = value
	tok.class = tcString
	return t.saveToken(tok)
}

func (t *tokenizer) newStringExpandableToken(value string, kind TokenKind, nested []*Token, flags TokenFlags) *Token {
	if nested != nil && len(nested) == 0 {
		nested = nil
	} else if flags&tfTokenInError == 0 {
		for _, n := range nested {
			if n.hasError() {
				flags |= tfTokenInError
				break
			}
		}
	}
	tok := t.mkToken(kind, flags)
	tok.Value = value
	if len(nested) > 0 {
		tok.extra().Nested = nested
	}
	tok.class = tcString
	return t.saveToken(tok)
}

func (t *tokenizer) newGenericExpandableToken(value string, nested []*Token) *Token {
	return t.newStringExpandableToken(value, TkGeneric, nested, 0)
}

func (t *tokenizer) newGenericToken(value string) *Token {
	return t.newStringLiteralToken(value, TkGeneric, 0)
}

func (t *tokenizer) newInputRedirectionToken() *Token {
	tok := t.mkToken(TkRedirectInStd, 0)
	tok.extra().redirKind = 1
	return t.saveToken(tok)
}

func (t *tokenizer) newFileRedirectionToken(from int, appendMode, fromExplicit bool) *Token {
	if fromExplicit && t.inExpressionMode() {
		t.ungetChar()
		if appendMode {
			t.ungetChar()
		}
		return t.newNumberToken(&NumberValue{Type: "Int32", Text: itoa(from)})
	}
	tok := t.mkToken(TkRedirection, 0)
	x := tok.extra()
	x.redirKind = 3
	x.FromStream = RedirectionStream(from)
	x.Append = appendMode
	return t.saveToken(tok)
}

func (t *tokenizer) newMergingRedirectionToken(from, to int) *Token {
	tok := t.mkToken(TkRedirection, 0)
	x := tok.extra()
	x.redirKind = 2
	x.FromStream = RedirectionStream(from)
	x.ToStream = RedirectionStream(to)
	return t.saveToken(tok)
}

func (t *tokenizer) newLabelToken(value string) *Token {
	tok := t.mkToken(TkLabel, 0)
	tok.Value = value
	tok.class = tcLabel
	return t.saveToken(tok)
}

func itoa(n int) string { return utf16Itoa(n) }

func (t *tokenizer) isAtEndOfScript(e extent, checkCommentsAndWhitespace bool) bool {
	return e.End >= len(t.script) || (checkCommentsAndWhitespace && t.onlyWhitespaceOrCommentsAfter(e))
}

func (t *tokenizer) onlyWhitespaceOrCommentsAfter(e extent) bool {
	for i := e.End; i < len(t.script); i++ {
		if t.script[i] == '#' {
			i = t.skipLineComment(i+1) - 1
			continue
		}
		if t.script[i] == '<' && i+1 < len(t.script) && t.script[i+1] == '#' {
			i = t.skipBlockComment(i+2) - 1
			continue
		}
		if !isWhitespace(t.script[i]) {
			return false
		}
	}
	return true
}

func (t *tokenizer) isPipeContinuation(e extent) bool {
	return e.End < len(t.script) && t.continuationAfterExtent(e, '|')
}

func (t *tokenizer) continuationAfterExtent(e extent, cont char) bool {
	lastNonWSIsNewline := true
	i := e.End
	for i < len(t.script)-1 {
		c := t.script[i]
		if isWhitespace(c) {
			i++
			continue
		}
		if c == '\n' {
			if lastNonWSIsNewline {
				return false
			}
			lastNonWSIsNewline = true
			i++
			continue
		} else if c == '\r' {
			if lastNonWSIsNewline {
				return false
			}
			lastNonWSIsNewline = true
			if t.script[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			continue
		}
		lastNonWSIsNewline = false
		if c == '#' {
			i = t.skipLineComment(i + 1)
			continue
		}
		if c == '<' && t.script[i+1] == '#' {
			i = t.skipBlockComment(i + 2)
			continue
		}
		return c == cont
	}
	return t.script[len(t.script)-1] == cont
}

func (t *tokenizer) skipLineComment(i int) int {
	for ; i < len(t.script); i++ {
		if t.script[i] == '\r' || t.script[i] == '\n' {
			break
		}
	}
	return i
}

func (t *tokenizer) skipBlockComment(i int) int {
	for ; i < len(t.script); i++ {
		if t.script[i] == '#' && i+1 < len(t.script) && t.script[i+1] == '>' {
			return i + 2
		}
	}
	return i
}

// backtick returns the character a backtick escape stands for. The second
// result is the low surrogate of a \u{...} escape above U+FFFF, or invalidChar.
func (t *tokenizer) backtick(c char) (char, char) {
	switch c {
	case '0':
		return 0, invalidChar
	case 'a':
		return 7, invalidChar
	case 'b':
		return 8, invalidChar
	case 'e':
		return 0x1b, invalidChar
	case 'f':
		return '\f', invalidChar
	case 'n':
		return '\n', invalidChar
	case 'r':
		return '\r', invalidChar
	case 't':
		return '\t', invalidChar
	case 'u':
		return t.scanUnicodeEscape()
	case 'v':
		return '\v', invalidChar
	}
	return c, invalidChar
}

func (t *tokenizer) scanUnicodeEscape() (char, char) {
	escStart := t.curIndex - 2
	c := t.getChar()
	if c != '{' {
		t.ungetChar()
		t.reportErrorExtent(t.newExtent(escStart, t.curIndex), "InvalidUnicodeEscapeSequence")
		return invalidChar, invalidChar
	}
	var hex []char
	for i := 0; i < maxUnicodeHexDigits+1; i++ {
		c = t.getChar()
		if c == '}' {
			if i == 0 {
				t.reportErrorExtent(t.newExtent(escStart, t.curIndex), "InvalidUnicodeEscapeSequence")
				return invalidChar, invalidChar
			}
			break
		} else if !isHexDigit(c) {
			t.ungetChar()
			if i < maxUnicodeHexDigits {
				t.reportError(t.curIndex, "InvalidUnicodeEscapeSequence")
			} else {
				t.reportError(t.curIndex, "MissingUnicodeEscapeSequenceTerminator")
			}
			return invalidChar, invalidChar
		} else if i == maxUnicodeHexDigits {
			t.ungetChar()
			t.reportError(t.curIndex, "TooManyDigitsInUnicodeEscapeSequence")
			return invalidChar, invalidChar
		}
		hex = append(hex, c)
	}
	var v uint32
	for _, h := range hex {
		v = v*16 + hexVal(h)
	}
	if v <= 0xffff {
		return char(v), invalidChar
	} else if v <= 0x10ffff {
		return char((v-0x10000)/0x400 + 0xd800), char((v-0x10000)%0x400 + 0xdc00)
	}
	t.reportErrorExtent(t.newExtent(escStart+3, t.curIndex-1), "InvalidUnicodeEscapeSequenceValue")
	return invalidChar, invalidChar
}

func hexVal(c char) uint32 {
	switch {
	case c >= '0' && c <= '9':
		return uint32(c - '0')
	case c >= 'a' && c <= 'f':
		return uint32(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return uint32(c-'A') + 10
	}
	return 0
}

func (t *tokenizer) scanLineComment() {
	for {
		c := t.getChar()
		if c == '\r' || c == '\n' || (c == 0 && t.atEOF()) {
			t.ungetChar()
			break
		}
	}
	t.newCommentToken()
}

func (t *tokenizer) scanBlockComment() {
	errorIndex := t.curIndex - 2
	for {
		c := t.getChar()
		if c == '#' && t.peekChar() == '>' {
			t.skipChar()
			break
		}
		if c == '\r' {
			t.normalizeCRLF(c)
		} else if c == 0 && t.atEOF() {
			t.ungetChar()
			t.reportIncomplete(errorIndex, "MissingTerminatorMultiLineComment")
			break
		}
	}
	t.newCommentToken()
}
