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
		em := p.exprMode
		p.exprMode = true
		lhs := p.parseExpression()
		p.exprMode = em
		if p.isAssignOp() {
			op := p.advance().Value
			p.skipNewlines()
			rhs := p.parseStatement(s)
			lstart := p.prevEnd()
			if lhs != nil {
				lstart, _ = lhs.Span()
			}
			return &Assignment{span: span{lstart, p.prevEnd()}, LHS: lhs, Op: op, RHS: rhs}
		}
		seed := &ExprStatement{Expr: lhs}
		if lhs != nil {
			seed.start, seed.end = lhs.Span()
		}
		return p.parsePipelineChain(seed)
	}
	return p.parsePipelineChain(nil)
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

func (p *parser) parsePipelineChain(seed PipelineElement) Statement {
	head := p.parsePipeline(seed)
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
		right := p.parsePipeline(nil)
		cur.ChainOp = op
		cur.ChainRHS = right
		cur = right
	}
	return head
}

func (p *parser) parsePipeline(seed PipelineElement) *Pipeline {
	start := p.cur().Start
	pl := &Pipeline{}
	if seed != nil {
		pl.Elements = append(pl.Elements, seed)
		if s0, _ := seed.Span(); s0 >= 0 {
			start = s0
		}
	} else if el := p.parsePipelineElement(); el != nil {
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
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: decodeBareword(t.Raw), Static: true, Bare: true}
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

// parseCommandArg parses one positional argument in command mode: a run of
// no-whitespace-adjacent atoms fused into one value, optionally continued as a
// comma array literal (a,b or csv:"...":44,34,76).
func (p *parser) parseCommandArg() CommandElement {
	e := p.parseFusedArg()
	if e == nil {
		return nil
	}
	if p.at(TokComma) {
		arr := &ArrayLit{Elements: []Expr{e}}
		for p.at(TokComma) {
			p.advance()
			p.skipNewlines()
			if nxt := p.parseFusedArg(); nxt != nil {
				arr.Elements = append(arr.Elements, nxt)
			}
		}
		s0, _ := e.Span()
		_, s1 := arr.Elements[len(arr.Elements)-1].Span()
		arr.start, arr.end = s0, s1
		e = arr
	}
	s0, s1 := e.Span()
	return &Arg{span: span{s0, s1}, Value: e}
}

// parseFusedArg parses one argument value: a leading atom plus any immediately
// following (no-whitespace) atoms composed into one string. PowerShell fuses a
// bareword, variable or $( ) lead with trailing text, but a quoted-string lead
// is not fused ('C:\x'\y is two arguments).
func (p *parser) parseFusedArg() Expr {
	lead := p.parseArgAtom()
	if lead == nil {
		return nil
	}
	if !fusableLead(lead) {
		return lead
	}
	atoms := []Expr{lead}
	_, end := lead.Span()
	for !p.at(TokEOF) {
		t := p.cur()
		if t.Start != end || !adjacentFusable(t.Kind) {
			break
		}
		a := p.parseArgAtom()
		if a == nil {
			break
		}
		atoms = append(atoms, a)
		_, end = a.Span()
	}
	if len(atoms) == 1 {
		return lead
	}
	s0, _ := lead.Span()
	return composeAtoms(atoms, s0, end)
}

// parseArgAtom parses a single argument atom (no comma, no fusion).
func (p *parser) parseArgAtom() Expr {
	switch p.kind() {
	case TokGeneric, TokString, TokNumber, TokVariable, TokLParen, TokDollarParen,
		TokAtParen, TokAtBrace, TokLBrace, TokLBracket:
		return p.parsePostfix(p.parsePrimary())
	case TokOperator:
		// an operator character used as argument text (a lone '-', or a glob
		// lead such as * in */*).
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Value, Static: true, Bare: true}
	case TokDot:
		// a '.' at argument position is a bareword (Remove-Item . -Recurse).
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: ".", Static: true, Bare: true}
	}
	return nil
}

// fusableLead reports whether an atom may begin a fused argument: a bareword, a
// variable or a $( ) sub-expression (as PowerShell does).
func fusableLead(e Expr) bool {
	switch v := e.(type) {
	case *Variable, *SubExpr:
		return true
	case *StringLit:
		return v.Bare
	}
	return false
}

// composeAtoms joins adjacent atoms into one value: a static bareword when
// every atom resolves to a literal, otherwise an expandable string whose Parts
// are the atoms (Static=false). It never returns a static value the pieces
// disagree with.
func composeAtoms(atoms []Expr, s0, end int) Expr {
	var b strings.Builder
	static := true
	for _, a := range atoms {
		if v, ok := LiteralString(a); ok {
			b.WriteString(v)
		} else {
			static = false
			break
		}
	}
	if static {
		return &StringLit{span: span{s0, end}, Kind: StrBare, Value: b.String(), Static: true, Bare: true}
	}
	parts := make([]StringPart, 0, len(atoms))
	for _, a := range atoms {
		parts = append(parts, StringPart{Expr: a})
	}
	return &StringLit{span: span{s0, end}, Kind: StrDouble, Static: false, Parts: parts}
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
	for !p.at(TokNewline) && !p.at(TokEOF) && !p.at(TokSemi) &&
		!p.at(TokPipe) && !p.at(TokPipePipe) && !p.at(TokAmpAmp) {
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
