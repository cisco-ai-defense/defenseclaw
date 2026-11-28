// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import "strings"

// extent is a half-open UTF-16 offset range. Start < 0 is the empty extent.
type extent struct{ Start, End int }

func (e extent) empty() bool { return e.Start < 0 }

var emptyExtent = extent{-1, -1}

func extentOf(first, last extent) extent {
	if first.empty() {
		return last
	}
	if last.empty() {
		return first
	}
	return extent{first.Start, last.End}
}

func before(e extent) extent {
	o := e.Start - 1
	if o < 0 {
		o = 0
	}
	return extent{o, o}
}

func after(e extent) extent { return extent{e.End, e.End} }

func tokExt(t *Token) extent { return extent{t.Start, t.End} }

// ParseError is one parser diagnostic (the message text is not reproduced).
type ParseError struct {
	ErrorID    string
	Start, End int
	Incomplete bool
}

// Parser is the PowerShell parser. Use Parse.
type Parser struct {
	tz           *tokenizer
	src          []char
	ungot        *Token
	disableComma bool
	errors       []ParseError
	errorSeen    map[errorKey]struct{}
	tokens       []*Token
	depth        int
	// asciiSrc is the input text when it is pure ASCII (UTF-16 offsets equal byte offsets): textOf slices it.
	asciiSrc string
	ascii    bool
	// Unsupported is set when the input used a construct the port does not parse (configuration, dynamic keywords) or nested deeper than the budget.
	Unsupported bool
	// rejected collects the redirections reported StreamAlreadyRedirected (Result.Rejected).
	rejected []*Node
	// nestedWork counts the characters handed to nested scans (the text of a $( ) or a nested string that is
	// tokenized again); past nestedBudget the parse is Unsupported and nested scans see no text. Every level
	// of "$("$(..." nesting rescans the text inside it, so an unbounded parse is quadratic in the input
	// (a 100 KB nest took 3 s on the hook path; the legacy reader stops at a linear budget too).
	nestedWork, nestedBudget int
	// declineEarly stops the parse at the first construct that makes it Unsupported (ParseTreeOrDecline).
	declineEarly bool
}

// errDeclined unwinds a ParseTreeOrDecline parse from the point it became Unsupported.
type errDeclined struct{}

// markUnsupported flags the result Unsupported and, for ParseTreeOrDecline, stops the parse there.
func (p *Parser) markUnsupported() {
	p.Unsupported = true
	if p.declineEarly {
		panic(errDeclined{})
	}
}

const maxParseDepth = 16000

// nestedWorkFactor and nestedWorkSlack size the nested-scan budget: nestedWorkFactor full rescans of the
// input plus nestedWorkSlack characters, far above real scripts (a few levels over a few KiB).
const (
	nestedWorkFactor = 16
	nestedWorkSlack  = 1 << 16
)

func (p *Parser) tooDeep() {
	p.markUnsupported()
	p.reportError(extent{p.tz.curIndex, p.tz.curIndex}, "ParseTooDeep")
}

const verbatimArgument = "--%"

// Result is the output of Parse: the AST root, the token stream and the errors.
type Result struct {
	Root   *Node
	Tokens []*Token
	Errors []ParseError
	Source []char
	// Unsupported: see Parser.Unsupported.
	Unsupported bool
	// Rejected holds the redirections the parser read but did not attach to
	// their command, in source order: a second redirection of a stream that is
	// already redirected (StreamAlreadyRedirected, a parse error in pwsh). They
	// are not part of the tree (the tree is pwsh's own AST); a reader that must
	// still see every target the text names (the effects frontend) uses them.
	Rejected []*Node
}

// Parse parses PowerShell source text (the equivalent of Parser.ParseInput).
// parseState holds everything one Parse call allocates up front (one allocation instead of three).
type parseState struct {
	p   Parser
	tz  tokenizer
	res Result
}

func Parse(input string) *Result { return parse(input, true, false) }

// ParseTree parses like Parse but does not keep the token stream (Result.Tokens is nil); the tree and the
// errors are identical. This is the entry point for readers that only walk the tree.
func ParseTree(input string) *Result { return parse(input, false, false) }

// ParseTreeOrDecline parses like ParseTree but stops at the first construct that makes the result Unsupported
// (a construct the port does not parse, nesting past its depth or nested-scan budget) and returns only
// Result{Unsupported: true}. A reader that falls back to another parser on Unsupported uses it, so a give-up
// costs the parse up to that point instead of a full parse before the fallback's own (GAP-1947).
func ParseTreeOrDecline(input string) *Result { return parse(input, false, true) }

func parse(input string, wantTokens, declineEarly bool) (out *Result) {
	src := toUTF16(input)
	ps := &parseState{}
	p := &ps.p
	p.src = src
	if declineEarly {
		p.declineEarly = true
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(errDeclined); !ok {
					panic(r)
				}
				out = &Result{Source: src, Unsupported: true}
			}
		}()
	}
	p.nestedBudget = nestedWorkFactor*len(src) + nestedWorkSlack
	if isASCII(input) {
		p.ascii, p.asciiSrc = true, input
	}
	initTokenizer(&ps.tz, p, src, wantTokens)
	p.tz = &ps.tz
	root := p.scriptBlockRule(nil, false, nil)
	p.tokens = p.tz.tokenList
	p.semanticChecks(root)
	ps.res = Result{Root: root, Tokens: p.tokens, Errors: p.errors, Source: src, Unsupported: p.Unsupported, Rejected: p.rejected}
	return &ps.res
}

func (p *Parser) textOf(e extent) string {
	if p.ascii {
		return p.asciiSrc[e.Start:e.End]
	}
	return fromUTF16(p.src[e.Start:e.End])
}

func (p *Parser) skipNewlines() {
	if p.ungot == nil || p.ungot.Kind == TkNewLine {
		p.ungot = nil
		p.tz.skipNewlines(false)
	}
}

func (p *Parser) skipNewlinesAndSemicolons() {
	if p.ungot == nil || p.ungot.Kind == TkNewLine || p.ungot.Kind == TkSemi {
		p.ungot = nil
		p.tz.skipNewlines(true)
	}
}

func containsKind(ks []TokenKind, k TokenKind) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func (p *Parser) syncOnError(consumeClosing bool, sync ...TokenKind) {
	parens, curlies, braces := 0, 0, 0
	if containsKind(sync, TkRParen) {
		parens = 1
	}
	if containsKind(sync, TkRCurly) {
		curlies = 1
	}
	if containsKind(sync, TkRBracket) {
		braces = 1
	}
	for {
		tok := p.nextToken()
		switch tok.Kind {
		case TkLParen:
			parens++
		case TkRParen:
			parens--
			if parens == 0 && containsKind(sync, TkRParen) {
				if !consumeClosing {
					p.ungetToken(tok)
				}
				return
			}
		case TkLCurly:
			curlies++
		case TkRCurly:
			curlies--
			if curlies == 0 && containsKind(sync, TkRCurly) {
				if !consumeClosing {
					p.ungetToken(tok)
				}
				return
			}
		case TkLBracket:
			braces++
		case TkRBracket:
			braces--
			if braces == 0 && containsKind(sync, TkRBracket) {
				if !consumeClosing {
					p.ungetToken(tok)
				}
				return
			}
		case TkEndOfInput:
			p.ungetToken(tok)
			return
		}
		if containsKind(sync, tok.Kind) && parens == 0 && curlies == 0 && braces == 0 {
			break
		}
	}
}

func (p *Parser) nextToken() *Token {
	tok := p.ungot
	if tok == nil {
		tok = p.tz.nextToken()
	}
	p.ungot = nil
	return tok
}

func (p *Parser) peekToken() *Token {
	tok := p.ungot
	if tok == nil {
		tok = p.tz.nextToken()
	}
	if p.ungot == nil {
		p.ungot = tok
	}
	return tok
}

func (p *Parser) nextMemberAccessToken(allowLBracket bool) *Token {
	if p.ungot != nil {
		return nil
	}
	return p.tz.getMemberAccessOperator(allowLBracket)
}

func (p *Parser) nextInvokeMemberToken() *Token {
	if p.ungot != nil {
		return nil
	}
	return p.tz.getInvokeMemberOpenParen()
}

func (p *Parser) nextLBracket() *Token {
	if p.ungot != nil {
		if p.ungot.Kind == TkLBracket {
			return p.nextToken()
		}
		return nil
	}
	return p.tz.getLBracket()
}

func (p *Parser) getVerbatimCommandArgumentToken() *Token {
	if p.ungot == nil || p.ungot.Kind == TkParameter {
		p.ungot = nil
		return p.tz.getVerbatimCommandArgument()
	}
	return nil
}

func (p *Parser) skipToken() { p.ungot = nil }

func (p *Parser) ungetToken(t *Token) { p.ungot = t }

func (p *Parser) setTokenizerMode(mode tokenizerMode) {
	if mode != p.tz.mode && p.ungot != nil {
		if !p.ungot.Kind.hasTrait(tfParseModeInvariant) {
			p.resyncToken(p.ungot)
		}
	}
	p.tz.mode = mode
}

func (p *Parser) resyncToken(t *Token) {
	p.ungot = nil
	p.tz.resyncToken(t)
}

func (p *Parser) resync(point int) {
	p.ungot = nil
	p.tz.resync(point)
}

func isSpecificParameter(t *Token, parameter string) bool {
	return len(parameter) >= len(t.Value) && strings.EqualFold(parameter[:len(t.Value)], t.Value)
}

func (p *Parser) requireStatementTerminator() {
	t := p.peekToken()
	if t.Kind == TkNewLine || t.Kind == TkSemi {
		p.skipToken()
	} else if t.Kind != TkEndOfInput {
		p.reportIncomplete(tokExt(t), "MissingStatementTerminator")
	}
}

// saveError keeps the first error of each (extent, id), as SaveError does. Past errorScanMax errors the
// duplicate check is a set instead of a scan of the list: an input of thousands of unclosed "${`" or
// "$(" reports an error per level, and the scan made the parse quadratic (fixture row 39003, 12 KB:
// 30 ms in the effects frontend, the legacy reader 0.07 ms).
func (p *Parser) saveError(e extent, id string, incomplete bool) {
	if p.errorSeen == nil {
		for _, last := range p.errors {
			if last.Start == e.Start && last.End == e.End && last.ErrorID == id {
				return
			}
		}
		if len(p.errors) >= errorScanMax {
			p.errorSeen = make(map[errorKey]struct{}, 2*len(p.errors))
			for _, last := range p.errors {
				p.errorSeen[errorKey{last.Start, last.End, last.ErrorID}] = struct{}{}
			}
		}
	}
	if p.errorSeen != nil {
		k := errorKey{e.Start, e.End, id}
		if _, dup := p.errorSeen[k]; dup {
			return
		}
		p.errorSeen[k] = struct{}{}
	}
	p.errors = append(p.errors, ParseError{ErrorID: id, Start: e.Start, End: e.End, Incomplete: incomplete})
}

// errorKey is the duplicate key of saveError; errorScanMax is the list length up to which a scan is cheaper.
type errorKey struct {
	start, end int
	id         string
}

const errorScanMax = 32

func (p *Parser) reportError(e extent, id string) { p.saveError(e, id, false) }

// reportIncomplete reports an error that may only mean the input stopped early.
func (p *Parser) reportIncomplete(e extent, id string) bool {
	inc := p.tz.isAtEndOfScript(e, true)
	p.saveError(e, id, inc)
	return inc
}

// reportIncompleteAt is the overload with a separate error position and detection position.
func (p *Parser) reportIncompleteAt(errPos, detected extent, id string) bool {
	inc := p.tz.isAtEndOfScript(detected, true)
	p.saveError(errPos, id, inc)
	return inc
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
