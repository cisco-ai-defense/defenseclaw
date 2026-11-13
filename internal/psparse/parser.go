// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// Options controls a parse.
type Options struct {
	Dialect Dialect
}

const maxDepth = 200

// rawSpan returns the exact source text of [s0,end) (or "" if out of range).
func (p *parser) rawSpan(s0, end int) string {
	if s0 >= 0 && end <= len(p.src) && end >= s0 {
		return p.src[s0:end]
	}
	return ""
}

// parser is a recursive-descent parser over the token slice. It is
// unknown-tolerant: on any construct it cannot structure it records a
// Diagnostic and resynchronises to the next statement boundary rather than
// failing. It never panics.
type parser struct {
	toks      []Token
	i         int
	diags     []Diagnostic
	dialect   Dialect
	depth     int
	topParams []*Variable
	exprMode  bool   // true inside (), $(), @{} values, [], method args
	forHeader int    // >0 while inside a for/foreach header, so 'in' is a keyword
	budget    *int   // shared remaining work budget for nested string re-parses (F12)
	src       string // source text, for slicing greedy command-name spans
}

// Parse parses PowerShell source into a Script. It always returns a non-nil
// Script; err is reserved for future use and is currently always nil.
func Parse(src string, opts Options) (*Script, error) {
	l := newLexer(src)
	toks := l.lex()
	p := &parser{toks: toks, dialect: opts.Dialect, src: src}
	budget := 8*len(src) + 4096
	p.budget = &budget
	sc := &Script{Dialect: opts.Dialect}
	sc.start = 0
	sc.end = len(src)
	if len(src) >= maxInput {
		p.diag(0, len(src), ReasonTruncated, "input exceeded byte budget")
	}
	sc.Statements = p.parseStatementList(stopTop)
	sc.Params = p.topParams
	sc.Diagnostics = p.diags
	return sc, nil
}

// subParse parses nested script text found inside an expandable string ($( )).
// It shares one work budget and the recursion depth with the outer parse so
// deeply nested "$( "$( ... )" )" strings cannot blow up (F12); when the budget
// or depth is exhausted it returns a ps_depth_limit diagnostic rather than
// re-lexing the remaining text at every level.
func (p *parser) subParse(src string) ([]Statement, []Diagnostic) {
	if p.overDepth() || p.budget == nil || *p.budget <= 0 {
		return nil, []Diagnostic{{Reason: ReasonDepthLimit, Detail: "nested string parse budget/depth exhausted"}}
	}
	*p.budget -= len(src)
	l := newLexer(src)
	sub := &parser{toks: l.lex(), dialect: p.dialect, depth: p.depth + 1, budget: p.budget, src: src}
	sts := sub.parseStatementList(stopTop)
	return sts, sub.diags
}

// topParams accumulates names from a top-level param() block.
// (stored on the parser to thread through parseStatementList)
func (p *parser) cur() Token { return p.toks[p.i] }
func (p *parser) kind() TokenKind {
	return p.toks[p.i].Kind
}
func (p *parser) peekKind(n int) TokenKind {
	j := p.i + n
	if j < 0 || j >= len(p.toks) {
		return TokEOF
	}
	return p.toks[j].Kind
}
func (p *parser) advance() Token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}
func (p *parser) at(k TokenKind) bool { return p.kind() == k }

func (p *parser) diag(start, end int, reason, detail string) {
	p.diags = append(p.diags, Diagnostic{span: span{start, end}, Reason: reason, Detail: detail})
}

// skipComments advances past comment tokens (the lexer surfaces them but the
// parser ignores them everywhere).
func (p *parser) skipComments() {
	for p.at(TokComment) {
		p.advance()
	}
}

// skipSeparators consumes newlines, semicolons and comments.
func (p *parser) skipSeparators() {
	for {
		p.skipComments()
		if p.at(TokNewline) || p.at(TokSemi) {
			p.advance()
			continue
		}
		return
	}
}

// skipNewlines consumes newlines and comments but not semicolons.
func (p *parser) skipNewlines() {
	for {
		p.skipComments()
		if p.at(TokNewline) {
			p.advance()
			continue
		}
		return
	}
}

// stop sets: which closing tokens terminate a statement list.
type stopSet int

const (
	stopTop stopSet = iota
	stopBrace
	stopParen
)

func (p *parser) atStop(s stopSet) bool {
	switch p.kind() {
	case TokEOF:
		return true
	case TokRBrace:
		return s == stopBrace
	case TokRParen:
		return s == stopParen
	}
	return false
}

// parseStatementList parses statements until the stop token or EOF.
func (p *parser) parseStatementList(s stopSet) []Statement {
	var out []Statement
	for {
		p.skipSeparators()
		if p.atStop(s) {
			return out
		}
		before := p.i
		st := p.parseStatement(s)
		if st != nil {
			out = append(out, st)
		}
		if p.i == before {
			// no progress: consume one token into an unknown statement to
			// guarantee termination.
			t := p.advance()
			out = append(out, &UnknownStatement{span: span{t.Start, t.End}, Reason: ReasonUnknownToken, Text: t.Raw})
		}
	}
}

// keyword sets
var controlKeywords = map[string]bool{
	"if": true, "elseif": true, "else": true, "while": true, "for": true,
	"foreach": true, "do": true, "switch": true, "try": true, "catch": true,
	"finally": true, "trap": true, "data": true,
}
var namedBlockKeywords = map[string]bool{
	"begin": true, "process": true, "end": true, "dynamicparam": true, "clean": true,
}
var flowKeywords = map[string]bool{
	"return": true, "throw": true, "exit": true, "break": true, "continue": true,
}

func (p *parser) bareword() (string, bool) {
	t := p.cur()
	if t.Kind == TokGeneric && t.Str == StrBare {
		return t.Raw, true
	}
	return "", false
}

func (p *parser) parseStatement(s stopSet) Statement {
	p.skipComments()
	// optional leading label  :outer
	if p.at(TokLabel) {
		p.advance()
		p.skipNewlines()
	}
	if w, ok := p.bareword(); ok {
		lw := strings.ToLower(w)
		if lw == "in" && p.forHeader > 0 {
			// the 'in' of a foreach header is a keyword, not a command
			p.advance()
			return nil
		}
		switch {
		case lw == "param":
			return p.parseParamBlock(s)
		case lw == "function" || lw == "filter" || lw == "workflow" || lw == "configuration":
			return p.parseFunction(lw)
		case controlKeywords[lw]:
			return p.parseControl(lw)
		case namedBlockKeywords[lw] && p.peekKind(1) == TokLBrace:
			return p.parseNamedBlock(lw)
		case flowKeywords[lw]:
			return p.parseFlow(lw)
		case lw == "class" || lw == "enum":
			return p.parseClassLike(lw)
		case lw == "using":
			return p.parseUsing()
		}
	}
	return p.parsePipelineChainOrAssignment(s)
}

// parseParamBlock reads param ( ... ) capturing the variable names.
func (p *parser) parseParamBlock(s stopSet) Statement {
	start := p.cur().Start
	p.advance() // param
	p.skipNewlines()
	blk := &Block{Keyword: "param"}
	var vars []*Variable
	if p.at(TokLParen) {
		p.advance()
		depthSave := p.enter()
		guard := 0
		for !p.at(TokRParen) && !p.at(TokEOF) && guard < 1<<16 {
			guard++
			p.skipSeparators()
			switch {
			case p.at(TokRParen):
				goto doneParams
			case p.at(TokLBracket):
				// a [Type] or [Attribute(...)]: recurse into attribute args so
				// nested commands / script blocks are found (F15).
				blk.Conditions = append(blk.Conditions, p.exprStmt(p.parseBracketAttr()))
			case p.at(TokVariable):
				t := p.advance()
				v := &Variable{span: span{t.Start, t.End}, Name: t.VarName, Scope: t.VarScope, Splat: t.Splat}
				vars = append(vars, v)
				blk.Conditions = append(blk.Conditions, p.exprStmt(v))
				p.skipNewlines()
				if p.at(TokOperator) && p.cur().Value == "=" {
					p.advance()
					p.skipNewlines()
					em := p.exprMode
					p.exprMode = true
					def := p.parseExpression()
					p.exprMode = em
					blk.Conditions = append(blk.Conditions, p.exprStmt(def))
				}
			case p.at(TokComma):
				p.advance()
			default:
				p.advance()
			}
		}
	doneParams:
		if p.at(TokRParen) {
			p.advance()
		}
		p.leave(depthSave)
	}
	if p.topParams == nil {
		p.topParams = vars
	}
	blk.start, blk.end = start, p.prevEnd()
	return blk
}

// parseBracketAttr parses a [Type] or [Attribute(args)] leniently, recursing
// into any ( ) argument list so nested commands and script blocks are walked.
func (p *parser) parseBracketAttr() Expr {
	start := p.cur().Start
	p.advance() // [
	var args []Expr
	save := p.enter()
	depth := 1
	guard := 0
	for !p.at(TokEOF) && depth > 0 && guard < 1<<16 {
		guard++
		switch p.kind() {
		case TokLBracket:
			depth++
			p.advance()
		case TokRBracket:
			depth--
			p.advance()
		case TokLParen:
			args = append(args, p.parseParenExpr())
		default:
			p.advance()
		}
	}
	p.leave(save)
	return &TypeExpr{span: span{start, p.prevEnd()}, Name: "attr", Args: args}
}

func (p *parser) exprStmt(e Expr) Statement {
	s0, s1 := 0, p.prevEnd()
	if e != nil {
		s0, s1 = e.Span()
	}
	return &ExprStatement{span: span{s0, s1}, Expr: e}
}

func (p *parser) parseFunction(kw string) Statement {
	start := p.cur().Start
	p.advance() // function/filter/...
	p.skipNewlines()
	name := ""
	if w, ok := p.bareword(); ok {
		name = w
		p.advance()
	} else if p.at(TokString) {
		name = p.advance().Raw
	}
	var conds []Statement
	p.skipNewlines()
	if p.at(TokLParen) { // function with an explicit param list
		conds = append(conds, p.parseParenExprStatement())
	}
	var bodies []*ScriptBlockExpr
	p.skipNewlines()
	if p.at(TokLBrace) {
		bodies = append(bodies, p.parseScriptBlock())
	}
	return &Block{span: span{start, p.prevEnd()}, Keyword: kw, Name: name, Conditions: conds, Bodies: bodies}
}

func (p *parser) parseClassLike(kw string) Statement {
	start := p.cur().Start
	p.advance()
	name := ""
	if w, ok := p.bareword(); ok {
		name = w
		p.advance()
	}
	// skip optional base list up to the opening brace
	for !p.at(TokLBrace) && !p.at(TokEOF) && !p.at(TokNewline) {
		p.advance()
	}
	var bodies []*ScriptBlockExpr
	if p.at(TokLBrace) {
		if kw == "enum" {
			p.skipBalancedBraces() // enum members are not commands
		} else {
			bodies = append(bodies, p.parseScriptBlock())
		}
	}
	return &Block{span: span{start, p.prevEnd()}, Keyword: kw, Name: name, Bodies: bodies}
}

// parseUsing consumes a `using namespace|module|assembly ...` statement, which
// is a declaration, not a command.
func (p *parser) parseUsing() Statement {
	start := p.cur().Start
	p.advance() // using
	for !p.at(TokEOF) && !p.at(TokNewline) && !p.at(TokSemi) {
		p.advance()
	}
	return &Block{span: span{start, p.prevEnd()}, Keyword: "using"}
}

// skipBalancedBraces consumes a { ... } group without parsing its contents.
func (p *parser) skipBalancedBraces() {
	if !p.at(TokLBrace) {
		return
	}
	depth := 0
	for !p.at(TokEOF) {
		switch p.kind() {
		case TokLBrace:
			depth++
		case TokRBrace:
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) parseNamedBlock(kw string) Statement {
	start := p.cur().Start
	p.advance() // begin/process/end/...
	var bodies []*ScriptBlockExpr
	p.skipNewlines()
	if p.at(TokLBrace) {
		bodies = append(bodies, p.parseScriptBlock())
	}
	return &Block{span: span{start, p.prevEnd()}, Keyword: kw, Bodies: bodies}
}

// parseControl captures conditions and bodies of a control-flow statement
// leniently: it alternates over parenthesised conditions, brace bodies, and
// sub-keywords (elseif/else/catch/finally/until/while) so that every nested
// script block is recursed into even when the precise grammar is not modelled.
func (p *parser) parseControl(kw string) Statement {
	start := p.cur().Start
	p.advance()
	if kw == "for" || kw == "foreach" {
		p.forHeader++
		defer func() { p.forHeader-- }()
	}
	blk := &Block{Keyword: kw}
	guard := 0
	for guard < 4096 {
		guard++
		p.skipNewlines()
		switch {
		case p.at(TokLParen):
			blk.Conditions = append(blk.Conditions, p.parseParenExprStatement())
		case kw == "switch" && (p.at(TokDollarParen) || p.at(TokAtParen)):
			// switch $(...) / @(...): an evaluated condition, walk its commands
			blk.Conditions = append(blk.Conditions, p.exprStmt(p.parsePrimary()))
		case p.at(TokLBrace):
			if kw == "switch" {
				p.parseSwitchBody(blk)
				blk.start, blk.end = start, p.prevEnd()
				return blk
			}
			blk.Bodies = append(blk.Bodies, p.parseScriptBlock())
		case p.at(TokParameter):
			// a control option such as switch -regex / -wildcard / -file
			p.advance()
		case p.isSubKeyword():
			p.advance() // consume elseif/else/catch/finally/until/while/in etc
		case p.at(TokLBracket):
			// a trap/catch type filter like  catch [IOException] { }
			p.skipBracketType()
		case p.at(TokEOF):
			blk.start, blk.end = start, p.prevEnd()
			return blk
		case kw == "switch" && (p.at(TokString) || p.at(TokGeneric) || p.at(TokVariable) || p.at(TokNumber)):
			// the switch condition or an option value (-File <path>, a
			// -File "...$( )..." string, or $x[$( )]): parse it as an expression
			// so a nested $( ) / index subexpression runs its commands. A bare
			// literal path parses to a StringLit and emits no command of its own
			// (review 3 R2). -File is still never taken as an opaque literal.
			blk.Conditions = append(blk.Conditions, p.exprStmt(p.parsePostfix(p.parsePrimary())))
		case kw == "switch":
			// any other condition token (an operator, etc.): consume silently so
			// the body { } is reached without leaking a top-level command.
			p.advance()
		default:
			blk.start, blk.end = start, p.prevEnd()
			return blk
		}
	}
	blk.start, blk.end = start, p.prevEnd()
	return blk
}

// parseSwitchBody parses a switch body { <pattern> { block } ... }. Clause
// patterns that are bare labels ('a', default, a number) are not commands and
// are skipped; a ( ) or { } pattern (an evaluated condition) and every clause
// block are parsed and walked.
func (p *parser) parseSwitchBody(blk *Block) {
	if !p.at(TokLBrace) {
		return
	}
	p.advance() // {
	save := p.enter()
	guard := 0
	for !p.at(TokRBrace) && !p.at(TokEOF) && guard < 1<<16 {
		guard++
		p.skipSeparators()
		switch {
		case p.at(TokRBrace):
			goto done
		case p.at(TokLBrace):
			blk.Bodies = append(blk.Bodies, p.parseScriptBlock())
		case p.at(TokLParen):
			blk.Conditions = append(blk.Conditions, p.parseParenExprStatement())
		case p.at(TokDollarParen), p.at(TokAtParen):
			blk.Conditions = append(blk.Conditions, p.exprStmt(p.parsePrimary()))
		case p.at(TokString):
			// a clause pattern that is an (expandable) string may embed $( ) or
			// subexpressions that run commands; parse it so they are walked.
			blk.Conditions = append(blk.Conditions, p.exprStmt(p.parsePrimary()))
		default:
			p.advance() // a bare clause label / separator
		}
	}
done:
	p.leave(save)
	if p.at(TokRBrace) {
		p.advance()
	}
}

func (p *parser) isSubKeyword() bool {
	w, ok := p.bareword()
	if !ok {
		return false
	}
	switch strings.ToLower(w) {
	case "elseif", "else", "catch", "finally", "until", "while", "in":
		return true
	}
	return false
}

func (p *parser) skipBracketType() {
	if !p.at(TokLBracket) {
		return
	}
	depth := 0
	for !p.at(TokEOF) {
		switch p.kind() {
		case TokLBracket:
			depth++
		case TokRBracket:
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) parseFlow(kw string) Statement {
	start := p.cur().Start
	p.advance()
	blk := &Block{Keyword: kw}
	// optional label for break/continue
	if (kw == "break" || kw == "continue") && p.at(TokLabel) {
		p.advance()
	}
	// a trailing value / pipeline on the same logical line
	if !p.at(TokNewline) && !p.at(TokSemi) && !p.at(TokEOF) && !p.at(TokRBrace) && !p.at(TokRParen) {
		blk.Conditions = append(blk.Conditions, p.parsePipelineChainOrAssignment(stopTop))
	}
	blk.start, blk.end = start, p.prevEnd()
	return blk
}

// parseParenExprStatement parses a ( ... ) group as a statement (used for
// conditions and function param lists), recursing into its contents.
func (p *parser) parseParenExprStatement() Statement {
	start := p.cur().Start
	if !p.at(TokLParen) {
		return &UnknownStatement{span: span{start, start}, Reason: ReasonUnbalanced}
	}
	p.advance() // (
	save := p.enter()
	stmts := p.parseStatementList(stopParen)
	p.leave(save)
	if p.at(TokRParen) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing )")
	}
	inner := &ScriptBlockExpr{span: span{start, p.prevEnd()}, Statements: stmts}
	return &ExprStatement{span: inner.span, Expr: &Paren{span: inner.span, Inner: blockToStmt(inner)}}
}

func blockToStmt(b *ScriptBlockExpr) Statement {
	// Wrap the paren body as a single pipeline-ish statement container.
	if len(b.Statements) == 1 {
		return b.Statements[0]
	}
	return &Block{span: b.span, Keyword: "(group)", Bodies: []*ScriptBlockExpr{b}}
}

// parseScriptBlock parses { ... }, including any leading param() and named
// begin/process/end blocks, returning a ScriptBlockExpr.
func (p *parser) parseScriptBlock() *ScriptBlockExpr {
	start := p.cur().Start
	if !p.at(TokLBrace) {
		return &ScriptBlockExpr{span: span{start, start}}
	}
	p.advance() // {
	save := p.enter()
	sb := &ScriptBlockExpr{}
	// optional leading param()
	p.skipSeparators()
	if w, ok := p.bareword(); ok && strings.EqualFold(w, "param") {
		st := p.parseParamBlock(stopBrace)
		if b, isBlk := st.(*Block); isBlk {
			sb.Params = variablesFromStmts(b.Conditions)
		}
		// keep the param block as a statement so its default-value and
		// attribute commands are walked (F15).
		sb.Statements = append(sb.Statements, st)
	}
	sb.Statements = append(sb.Statements, p.parseStatementList(stopBrace)...)
	p.leave(save)
	if p.at(TokRBrace) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing }")
	}
	sb.start, sb.end = start, p.prevEnd()
	return sb
}

func variablesFromStmts(sts []Statement) []*Variable {
	var vs []*Variable
	for _, s := range sts {
		if es, ok := s.(*ExprStatement); ok {
			if v, ok := es.Expr.(*Variable); ok {
				vs = append(vs, v)
			}
		}
	}
	return vs
}

// enter/leave maintain the recursion depth guard.
func (p *parser) enter() int {
	p.depth++
	return p.depth
}
func (p *parser) leave(saved int) { p.depth = saved - 1 }

func (p *parser) overDepth() bool { return p.depth > maxDepth }

func (p *parser) prevEnd() int {
	if p.i == 0 {
		return 0
	}
	return p.toks[p.i-1].End
}
