// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// Word operators that act as binary operators in expression context. They are
// lexed as TokParameter (dash + name) and reinterpreted here.
var binaryWordOps = map[string]bool{
	"eq": true, "ne": true, "gt": true, "ge": true, "lt": true, "le": true,
	"like": true, "notlike": true, "match": true, "notmatch": true,
	"contains": true, "notcontains": true, "in": true, "notin": true,
	"is": true, "isnot": true, "as": true, "and": true, "or": true, "xor": true,
	"band": true, "bor": true, "bxor": true, "shl": true, "shr": true,
	"replace": true, "split": true, "join": true, "f": true,
	"ceq": true, "cne": true, "clike": true, "cmatch": true, "creplace": true,
	"ieq": true, "ine": true, "ilike": true, "imatch": true, "ireplace": true,
}

var unaryWordOps = map[string]bool{
	"not": true, "bnot": true, "split": true, "join": true,
}

func (p *parser) parseExpression() Expr {
	return p.parseArrayLiteral()
}

func (p *parser) parseArrayLiteral() Expr {
	first := p.parseBinaryExpr()
	if !p.at(TokComma) {
		return first
	}
	arr := &ArrayLit{Elements: []Expr{first}}
	for p.at(TokComma) {
		p.advance()
		p.skipNewlines()
		arr.Elements = append(arr.Elements, p.parseBinaryExpr())
	}
	if len(arr.Elements) > 0 {
		s0, _ := arr.Elements[0].Span()
		_, s1 := arr.Elements[len(arr.Elements)-1].Span()
		arr.start, arr.end = s0, s1
	}
	return arr
}

func (p *parser) isBinaryOp() bool {
	if !p.exprMode {
		return false
	}
	switch p.kind() {
	case TokOperator:
		switch p.cur().Value {
		case "+", "-", "*", "/", "%":
			return true
		}
	case TokParameter:
		return binaryWordOps[strings.ToLower(p.cur().Value)]
	}
	return false
}

func (p *parser) parseBinaryExpr() Expr {
	lhs := p.parseUnary()
	guard := 0
	for p.isBinaryOp() && guard < 1<<16 {
		guard++
		op := p.advance().Value
		p.skipNewlines()
		rhs := p.parseUnary()
		s0, _ := lhs.Span()
		_, s1 := rhs.Span()
		lhs = &Binary{span: span{s0, s1}, Op: op, LHS: lhs, RHS: rhs}
	}
	return lhs
}

func (p *parser) parseUnary() Expr {
	t := p.cur()
	if t.Kind == TokOperator && p.exprMode {
		switch t.Value {
		case "-", "+", "!", "++", "--":
			p.advance()
			operand := p.parseUnary()
			s0 := t.Start
			s1 := s0
			if operand != nil {
				_, s1 = operand.Span()
			}
			return &Unary{span: span{s0, s1}, Op: t.Value, Operand: operand}
		}
	}
	if t.Kind == TokParameter && p.exprMode && unaryWordOps[strings.ToLower(t.Value)] {
		// Only treat as unary when not obviously a parameter in command mode;
		// in expression context (where parseUnary runs) this is an operator.
		p.advance()
		operand := p.parseUnary()
		s1 := t.End
		if operand != nil {
			_, s1 = operand.Span()
		}
		return &Unary{span: span{t.Start, s1}, Op: "-" + t.Value, Operand: operand}
	}
	return p.parsePostfix(p.parsePrimary())
}

func (p *parser) parsePostfix(e Expr) Expr {
	if !p.exprMode {
		if sl, ok := e.(*StringLit); ok && sl.Bare {
			// a bareword command argument does not take . or [ ] postfixes;
			// those characters are literal in command mode.
			return e
		}
	}
	guard := 0
	for guard < 1<<16 {
		guard++
		switch {
		case p.at(TokDot):
			e = p.parseMember(e, false)
		case p.at(TokOperator) && p.cur().Value == "::":
			p.advance()
			e = p.parseMember(e, true)
		case p.at(TokLBracket):
			e = p.parseIndex(e)
		case p.at(TokOperator) && (p.cur().Value == "++" || p.cur().Value == "--"):
			t := p.advance()
			s0, _ := e.Span()
			e = &Unary{span: span{s0, t.End}, Op: t.Value, Operand: e, Postfix: true}
		default:
			return e
		}
	}
	return e
}

func (p *parser) parseMember(target Expr, static bool) Expr {
	// consume the '.' for instance access (static already consumed the '::')
	if !static {
		p.advance()
	}
	s0 := 0
	if target != nil {
		s0, _ = target.Span()
	}
	// member name
	name := ""
	dynamic := false
	switch p.kind() {
	case TokGeneric, TokParameter:
		name = p.cur().Value
		if p.kind() == TokGeneric {
			name = p.cur().Raw
		}
		p.advance()
	case TokString:
		name = p.advance().Raw
	case TokVariable, TokDollarParen, TokLBrace:
		dynamic = true
		p.parsePrimary()
	default:
		dynamic = true
	}
	if p.at(TokLParen) {
		args := p.parseInvokeArgs()
		inv := &Invoke{span: span{s0, p.prevEnd()}, Target: target, Name: name, Static: static, Args: args}
		if dynamic {
			inv.Reason = ReasonDynamicMember
			p.diag(s0, inv.end, ReasonDynamicMember, "method name is computed")
		}
		return inv
	}
	m := &Member{span: span{s0, p.prevEnd()}, Target: target, Name: name, Static: static}
	if dynamic {
		m.Reason = ReasonDynamicMember
		p.diag(s0, m.end, ReasonDynamicMember, "member name is computed")
	}
	return m
}

func (p *parser) parseInvokeArgs() []Expr {
	p.advance() // (
	save := p.enter()
	em := p.exprMode
	p.exprMode = true
	defer func() { p.exprMode = em }()
	var args []Expr
	p.skipNewlines()
	for !p.at(TokRParen) && !p.at(TokEOF) {
		args = append(args, p.parseBinaryExpr())
		p.skipNewlines()
		if p.at(TokComma) {
			p.advance()
			p.skipNewlines()
			continue
		}
		break
	}
	p.leave(save)
	if p.at(TokRParen) {
		p.advance()
	} else {
		p.diag(p.cur().Start, p.cur().End, ReasonUnbalanced, "missing ) in method call")
	}
	return args
}

func (p *parser) parseIndex(target Expr) Expr {
	p.advance() // [
	save := p.enter()
	em := p.exprMode
	p.exprMode = true
	idx := p.parseExpression()
	p.exprMode = em
	p.leave(save)
	s0 := 0
	if target != nil {
		s0, _ = target.Span()
	}
	if p.at(TokRBracket) {
		p.advance()
	} else {
		p.diag(s0, p.prevEnd(), ReasonUnbalanced, "missing ]")
	}
	return &Index{span: span{s0, p.prevEnd()}, Target: target, Index: idx}
}

func (p *parser) parsePrimary() Expr {
	if p.overDepth() {
		t := p.advance()
		return &ErrorExpr{span: span{t.Start, t.End}, Reason: ReasonDepthLimit, Text: t.Raw}
	}
	t := p.cur()
	switch p.kind() {
	case TokVariable:
		p.advance()
		return &Variable{span: span{t.Start, t.End}, Name: t.VarName, Scope: t.VarScope, Splat: t.Splat}
	case TokString:
		return p.stringLit(p.advance())
	case TokNumber:
		p.advance()
		return numberLit(t)
	case TokGeneric:
		p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true}
	case TokLParen:
		return p.parseParenExpr()
	case TokDollarParen:
		return p.parseSubExpr(TokDollarParen)
	case TokAtParen:
		return p.parseArrayExpr()
	case TokAtBrace:
		return p.parseHashtable()
	case TokLBrace:
		return p.parseScriptBlock()
	case TokLBracket:
		return p.parseTypeOrCast()
	case TokAmp, TokDot:
		// a call operator appearing in expression position: parse as a nested
		// command so its target/args are captured.
		cmd := p.parseCommand(callOp(p.kind()))
		return &scriptExprWrap{span: cmd.span, cmd: cmd}
	}
	p.advance()
	return &ErrorExpr{span: span{t.Start, t.End}, Reason: ReasonNonLiteral, Text: t.Raw}
}

func callOp(k TokenKind) string {
	if k == TokDot {
		return "."
	}
	return "&"
}

// scriptExprWrap lets a Command appear where an Expr is expected (e.g. a call
// operator used inside parentheses). It is transparent to effect walking.
type scriptExprWrap struct {
	span
	cmd *Command
}

func (*scriptExprWrap) expr() {}

func (p *parser) parseParenExpr() Expr {
	start := p.cur().Start
	p.advance() // (
	save := p.enter()
	stmts := p.parseStatementList(stopParen)
	p.leave(save)
	if p.at(TokRParen) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing )")
	}
	var inner Statement
	switch len(stmts) {
	case 0:
	case 1:
		inner = stmts[0]
	default:
		inner = &Block{span: span{start, p.prevEnd()}, Keyword: "(group)", Bodies: []*ScriptBlockExpr{{span: span{start, p.prevEnd()}, Statements: stmts}}}
	}
	return &Paren{span: span{start, p.prevEnd()}, Inner: inner}
}

func (p *parser) parseSubExpr(open TokenKind) Expr {
	start := p.cur().Start
	p.advance() // $(
	save := p.enter()
	stmts := p.parseStatementList(stopParen)
	p.leave(save)
	if p.at(TokRParen) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing ) in $( )")
	}
	return &SubExpr{span: span{start, p.prevEnd()}, Statements: stmts}
}

func (p *parser) parseArrayExpr() Expr {
	start := p.cur().Start
	p.advance() // @(
	save := p.enter()
	stmts := p.parseStatementList(stopParen)
	p.leave(save)
	if p.at(TokRParen) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing ) in @( )")
	}
	return &ArrayExpr{span: span{start, p.prevEnd()}, Statements: stmts}
}

func (p *parser) parseHashtable() Expr {
	start := p.cur().Start
	p.advance() // @{
	save := p.enter()
	ht := &Hashtable{}
	guard := 0
	for !p.at(TokRBrace) && !p.at(TokEOF) && guard < 1<<16 {
		guard++
		p.skipSeparators()
		if p.at(TokRBrace) {
			break
		}
		key := p.parseBinaryExpr()
		if p.at(TokOperator) && p.cur().Value == "=" {
			p.advance()
			p.skipNewlines()
			val := p.parseHashValue()
			ht.Keys = append(ht.Keys, key)
			ht.Values = append(ht.Values, val)
		} else {
			// malformed entry; keep the key, resync
			ht.Keys = append(ht.Keys, key)
			ht.Values = append(ht.Values, nil)
			p.skipToHashBoundary()
		}
		p.skipSeparators()
	}
	p.leave(save)
	if p.at(TokRBrace) {
		p.advance()
	} else {
		p.diag(start, p.prevEnd(), ReasonUnbalanced, "missing } in @{ }")
	}
	ht.start, ht.end = start, p.prevEnd()
	return ht
}

// parseHashValue parses a hashtable value, which may be a pipeline/command
// (e.g. ScriptBlock = { ... }) or an expression.
func (p *parser) parseHashValue() Expr {
	if p.at(TokLBrace) {
		return p.parseScriptBlock()
	}
	em := p.exprMode
	p.exprMode = true
	e := p.parseExpression()
	p.exprMode = em
	return e
}

func (p *parser) skipToHashBoundary() {
	for !p.at(TokRBrace) && !p.at(TokSemi) && !p.at(TokNewline) && !p.at(TokEOF) {
		p.advance()
	}
}

// parseTypeOrCast parses a [type] literal, which may be a cast [type]expr or a
// base for a ::static member.
func (p *parser) parseTypeOrCast() Expr {
	start := p.cur().Start
	name := p.scanBracketText()
	te := &TypeExpr{span: span{start, p.prevEnd()}, Name: name}
	// a cast binds a following expression-lead token
	if p.castFollows() {
		operand := p.parseUnary()
		s1 := te.end
		if operand != nil {
			_, s1 = operand.Span()
		}
		return &Convert{span: span{start, s1}, Type: name, Operand: operand}
	}
	return te
}

func (p *parser) castFollows() bool {
	switch p.kind() {
	case TokVariable, TokString, TokNumber, TokLParen, TokDollarParen, TokAtParen, TokGeneric:
		return true
	}
	return false
}

// scanBracketText consumes a balanced [ ... ] and returns the inner text
// (used for type names, which may contain nested brackets for generics).
func (p *parser) scanBracketText() string {
	var b strings.Builder
	p.advance() // [
	depth := 1
	for !p.at(TokEOF) && depth > 0 {
		switch p.kind() {
		case TokLBracket:
			depth++
			p.advance()
		case TokRBracket:
			depth--
			p.advance()
			if depth == 0 {
				return b.String()
			}
		default:
			b.WriteString(p.advance().Raw)
		}
	}
	p.diag(0, p.prevEnd(), ReasonUnbalanced, "missing ] in type literal")
	return b.String()
}
