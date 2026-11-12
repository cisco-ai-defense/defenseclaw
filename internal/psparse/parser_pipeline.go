// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// parsePipelineChainOrAssignment parses a statement that is a pipeline, a
// pipeline chain (&& / ||), a background job (trailing &), or an assignment.
func (p *parser) parsePipelineChainOrAssignment(s stopSet) Statement {
	// Assignment is only possible when the statement begins in expression
	// mode (a variable / index target). Try it speculatively.
	if p.expressionLead() {
		save := p.i
		lhs := p.parseExpression()
		if p.isAssignOp() {
			op := p.advance().Value
			p.skipNewlines()
			rhs := p.parseStatement(s)
			lstart, _ := lhs.Span()
			return &Assignment{span: span{lstart, p.prevEnd()}, LHS: lhs, Op: op, RHS: rhs}
		}
		// not an assignment: rewind and parse as a pipeline so command and
		// redirection semantics apply uniformly.
		p.i = save
	}
	return p.parsePipelineChain()
}

func (p *parser) isAssignOp() bool {
	if p.at(TokOperator) {
		switch p.cur().Value {
		case "=", "+=", "-=", "*=", "/=", "%=", "??=":
			return true
		}
	}
	return false
}

// expressionLead reports whether the current token begins an expression (as
// opposed to a command name). Used to decide assignment vs command.
func (p *parser) expressionLead() bool {
	switch p.kind() {
	case TokVariable, TokLParen, TokLBracket, TokNumber, TokDollarParen, TokAtParen, TokAtBrace:
		return true
	}
	return false
}

func (p *parser) parsePipelineChain() Statement {
	head := p.parsePipeline()
	cur := head
	guard := 0
	for (p.at(TokAmpAmp) || p.at(TokPipePipe)) && guard < 1<<16 {
		guard++
		op := "&&"
		if p.at(TokPipePipe) {
			op = "||"
		}
		if p.dialect == DialectWindowsPS51 {
			p.diag(p.cur().Start, p.cur().End, ReasonUnknownToken, "&& / || not valid in Windows PowerShell 5.1")
		}
		p.advance()
		p.skipNewlines()
		right := p.parsePipeline()
		cur.ChainOp = op
		cur.ChainRHS = right
		cur = right
	}
	return head
}

func (p *parser) parsePipeline() *Pipeline {
	start := p.cur().Start
	pl := &Pipeline{}
	el := p.parsePipelineElement()
	if el != nil {
		pl.Elements = append(pl.Elements, el)
	}
	for p.at(TokPipe) {
		p.advance()
		p.skipNewlines()
		e := p.parsePipelineElement()
		if e != nil {
			pl.Elements = append(pl.Elements, e)
		}
	}
	for p.at(TokRedir) {
		pl.Redirs = append(pl.Redirs, p.parseRedirection())
	}
	if p.at(TokAmp) {
		pl.Background = true
		p.advance()
	}
	pl.start, pl.end = start, p.prevEnd()
	return pl
}

func (p *parser) parsePipelineElement() PipelineElement {
	p.skipNewlines()
	switch p.kind() {
	case TokAmp:
		return p.parseCommand("&")
	case TokDot:
		// dot-source only when followed by a command name token
		if p.peekKind(1) == TokGeneric || p.peekKind(1) == TokString || p.peekKind(1) == TokVariable {
			return p.parseCommand(".")
		}
	}
	if w, ok := p.bareword(); ok {
		_ = w
		return p.parseCommand("")
	}
	// % (ForEach-Object) and ? (Where-Object) are command aliases when they
	// appear in command position.
	if p.at(TokOperator) && (p.cur().Value == "%" || p.cur().Value == "?") {
		return p.parseCommand("")
	}
	// expression element (command-expression): parse in expression mode so
	// operators like -eq / + bind here (unlike command arguments).
	em := p.exprMode
	p.exprMode = true
	e := p.parseExpression()
	p.exprMode = em
	est := &ExprStatement{Expr: e}
	if e != nil {
		s0, s1 := e.Span()
		est.start, est.end = s0, s1
	}
	return est
}

// parseCommand parses a command invocation starting at the command name.
func (p *parser) parseCommand(invokeOp string) *Command {
	start := p.cur().Start
	cmd := &Command{InvokeOp: invokeOp}
	if invokeOp != "" {
		p.advance() // consume & or .
		p.skipNewlines()
		// the command name is a single primary expression
		cmd.Name = p.parseCommandName()
	} else {
		cmd.Name = p.parseCommandName()
	}
	guard := 0
	for guard < 1<<16 {
		guard++
		switch p.kind() {
		case TokEOF, TokNewline, TokSemi, TokPipe, TokAmpAmp, TokPipePipe, TokRParen, TokRBrace, TokRBracket:
			goto done
		case TokAmp:
			goto done
		case TokStopParse:
			p.advance()
			cmd.StopParsing = p.consumeStopParsingTail()
			p.diag(start, p.prevEnd(), ReasonStopParsing, "verbatim --% tail not structured")
			goto done
		case TokRedir:
			cmd.Redirs = append(cmd.Redirs, p.parseRedirection())
		case TokParameter:
			cmd.Elements = append(cmd.Elements, p.parseParameter())
		case TokComma:
			// a comma in command args ties the previous arg into an array;
			// consume and continue (arguments remain individually visible).
			p.advance()
		default:
			a := p.parseCommandArg()
			if a == nil {
				goto done
			}
			cmd.Elements = append(cmd.Elements, a)
		}
	}
done:
	cmd.start, cmd.end = start, p.prevEnd()
	return cmd
}

// parseCommandName reads the command name: a bareword, a quoted string, a
// variable, or a parenthesised / $() expression (for & (..) / & $var).
func (p *parser) parseCommandName() Expr {
	switch p.kind() {
	case TokGeneric:
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true}
	case TokString:
		return p.stringLit(p.advance())
	case TokVariable, TokLParen, TokDollarParen:
		e := p.parsePrimary()
		if _, ok := e.(*Variable); ok {
			p.diag0(e, ReasonDynamicName, "call target is a variable")
		}
		return e
	case TokOperator:
		if v := p.cur().Value; v == "%" || v == "?" {
			t := p.advance()
			return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true}
		}
	}
	// no recognisable name
	t := p.cur()
	return &ErrorExpr{span: span{t.Start, t.End}, Reason: ReasonDynamicName, Text: t.Raw}
}

func (p *parser) parseParameter() CommandElement {
	t := p.advance()
	par := &Parameter{span: span{t.Start, t.End}, Name: t.Value, HasColon: t.HasColon}
	if t.HasColon {
		// -Name:value  — the value is the immediately following token
		if !p.at(TokNewline) && !p.at(TokEOF) && p.cur().Start == t.End {
			if a, ok := p.parseCommandArg().(*Arg); ok && a != nil {
				par.Colon = a.Value
				_, par.end = a.Span()
			}
		}
	}
	return par
}

// parseCommandArg parses one positional argument in command mode. It routes
// through the expression parser so a comma list groups into one ArrayLit (as
// the reference parser does), while binary/word operators stay disabled in
// command mode so a following -Name is treated as a parameter, not an operator.
func (p *parser) parseCommandArg() CommandElement {
	switch p.kind() {
	case TokGeneric, TokString, TokNumber, TokVariable, TokLParen, TokDollarParen,
		TokAtParen, TokAtBrace, TokLBrace, TokLBracket:
		e := p.parseExpression()
		if e == nil {
			return nil
		}
		e = p.fuseAdjacent(e)
		// If fusing consumed tokens up to a comma, continue the array literal so
		// a native-exe argument like  csv:"...":44,34,76  is one argument, as the
		// reference parser groups it.
		if p.at(TokComma) {
			arr := &ArrayLit{Elements: []Expr{e}}
			for p.at(TokComma) {
				p.advance()
				p.skipNewlines()
				arr.Elements = append(arr.Elements, p.fuseAdjacent(p.parseBinaryExpr()))
			}
			s0, _ := e.Span()
			_, s1 := arr.Elements[len(arr.Elements)-1].Span()
			arr.start, arr.end = s0, s1
			e = arr
		}
		s0, s1 := e.Span()
		return &Arg{span: span{s0, s1}, Value: e}
	case TokOperator:
		// an operator character used as an argument value (a lone '-', or a
		// glob lead like * in */*): keep it as a bareword and fuse any
		// adjacent glob/path characters into one argument.
		t := p.advance()
		lead := &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true}
		fused := p.fuseAdjacent(lead)
		s0, s1 := fused.Span()
		return &Arg{span: span{s0, s1}, Value: fused}
	}
	return nil
}

// fuseAdjacent joins a dynamic leading argument atom (a variable or $( )
// sub-expression) with immediately following value tokens that have no
// whitespace between them, as PowerShell forms one expandable-string argument
// (for example $env:TEMP\lsass.dmp or $(Get-Date).log). A space ends the arg.
func (p *parser) fuseAdjacent(e Expr) Expr {
	// Only a simple value lead fuses; compound leads (parens, arrays,
	// hashtables, script blocks, member access) stay standalone arguments.
	switch e.(type) {
	case *Variable, *SubExpr, *StringLit, *Number:
	default:
		return e
	}
	s0, end := e.Span()
	dynamic := isDynamicLead(e)
	fused := false
	for !p.at(TokEOF) {
		t := p.cur()
		if t.Start != end { // a space or other gap ends the argument
			break
		}
		if !adjacentFusable(t.Kind) {
			break
		}
		if t.Kind == TokVariable || t.Kind == TokDollarParen ||
			(t.Kind == TokString && (t.Str == StrDouble || t.Str == StrHereDouble)) {
			dynamic = true
		}
		p.advance()
		end = t.End
		fused = true
	}
	return finishFuse(e, s0, end, fused, dynamic)
}

func isDynamicLead(e Expr) bool {
	switch v := e.(type) {
	case *Variable, *SubExpr:
		return true
	case *StringLit:
		return !v.Static
	}
	return false
}

// adjacentFusable reports whether a token with no preceding whitespace extends
// the current command argument (PowerShell's generic-token concatenation).
func adjacentFusable(k TokenKind) bool {
	switch k {
	case TokGeneric, TokNumber, TokVariable, TokString, TokDollarParen, TokOperator, TokDot:
		return true
	}
	return false
}

func finishFuse(e Expr, s0, end int, fused, dynamic bool) Expr {
	if !fused {
		return e
	}
	// The leading piece is kept in Parts so the effects lane can read it; the
	// exact text is the source span [s0,end]. A dynamic piece makes the whole
	// argument an expandable string, otherwise a literal bareword.
	kind, static := StrBare, true
	if dynamic {
		kind, static = StrDouble, false
	}
	return &StringLit{span: span{s0, end}, Kind: kind, Static: static, Parts: []StringPart{{Expr: e}}}
}

func (p *parser) parseRedirection() *Redirection {
	t := p.advance()
	r := &Redirection{span: span{t.Start, t.End}, Op: t.Value, Merge: t.ColonArg}
	if t.ColonArg != "" { // stream merge like 2>&1
		return r
	}
	if t.Value == "<" {
		// input redirection target
	}
	// target is the next argument expression
	p.skipComments()
	if !p.at(TokNewline) && !p.at(TokEOF) && !p.at(TokSemi) && !p.at(TokPipe) {
		if a := p.parseCommandArg(); a != nil {
			if arg, ok := a.(*Arg); ok {
				r.Target = arg.Value
				_, e := arg.Value.Span()
				r.end = e
			}
		}
	}
	return r
}

// consumeStopParsingTail collects the verbatim remainder after --% up to the
// next newline (PowerShell treats the rest of the line as literal args).
func (p *parser) consumeStopParsingTail() string {
	var b strings.Builder
	for !p.at(TokNewline) && !p.at(TokEOF) && !p.at(TokSemi) {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(p.advance().Raw)
	}
	return b.String()
}

func (p *parser) diag0(e Expr, reason, detail string) {
	if e == nil {
		return
	}
	s0, s1 := e.Span()
	p.diag(s0, s1, reason, detail)
}
