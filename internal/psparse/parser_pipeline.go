// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

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
	if _, ok := p.bareword(); ok {
		return p.parseCommand("")
	}
	// % (ForEach-Object) and ? (Where-Object) are command aliases when they
	// appear in command position.
	if p.at(TokOperator) && (p.cur().Value == "%" || p.cur().Value == "?") {
		return p.parseCommand("")
	}
	// a statement that starts with a -Parameter is a command in PowerShell
	// (-Value $x runs a command named -Value), not a stray parameter.
	if p.at(TokParameter) {
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
			sp := p.advance()
			cmd.Elements = append(cmd.Elements, &Arg{span: span{sp.Start, sp.End}, Value: &StringLit{span: span{sp.Start, sp.End}, Kind: StrBare, Value: "--%", Static: true, Bare: true, Raw: sp.Raw}})
			// the lexer always emits the verbatim tail token next
			tl := p.advance()
			cmd.StopParsing = tl.Raw
			cmd.Elements = append(cmd.Elements, &Arg{span: span{tl.Start, tl.End}, Value: &StringLit{span: span{tl.Start, tl.End}, Kind: StrBare, Value: tl.Raw, Static: true, Bare: true, Raw: tl.Raw}})
			p.diag(start, p.prevEnd(), ReasonStopParsing, "verbatim --% tail")
		case TokRedir:
			cmd.Redirs = append(cmd.Redirs, p.parseRedirection())
		case TokParameter:
			cmd.Elements = append(cmd.Elements, p.parseParameter())
		case TokComment:
			// a comment inside a command is whitespace; it does not end it (F13)
			p.advance()
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
// parseNameRun builds a command name as one greedy generic token: it swallows
// any adjacent $var, $( ), ( ), [ ], number, . or quoted string with no
// whitespace between them (a command name is literal — $(...) is not expanded),
// and yields one static value (C:\Tools\$env:NAME.exe and even bash-shaped
// k=$(cat x) are the literal strings PowerShell sees).
func (p *parser) parseNameRun(first Token) Expr {
	s0, end := first.Start, first.End
	for !p.at(TokEOF) {
		t := p.cur()
		if t.Start != end {
			break
		}
		switch t.Kind {
		case TokGeneric, TokVariable, TokNumber, TokDot, TokString, TokOperator:
			end = t.End
			p.advance()
		case TokDollarParen, TokLBracket:
			// a $( ) or [ ] glued into a name is literal (k=$(..), a[1<<2]=x);
			// a plain ( / @( / { / @{ starts a separate argument (`$( ) -> name "$").
			end = p.consumeBalancedEnd()
		default:
			goto doneName
		}
	}
doneName:
	raw := ""
	if s0 >= 0 && end <= len(p.src) && end >= s0 {
		raw = p.src[s0:end]
	}
	v, amb := p.decodeBacktick(raw, true)
	sl := &StringLit{span: span{s0, end}, Kind: StrBare, Bare: true, Static: !amb, Value: v, Raw: raw}
	if amb {
		p.diag(s0, end, ReasonDialectAmbiguous, "backtick escape in a name differs between PS 5.1 and 7")
	}
	return sl
}

// consumeBalancedEnd consumes a balanced ( ), [ ] or { } group (the current
// token is its opener) and returns the byte offset just past the matching
// close token.
func (p *parser) consumeBalancedEnd() int {
	closerFor := func(k TokenKind) TokenKind {
		switch k {
		case TokDollarParen, TokLParen, TokAtParen:
			return TokRParen
		case TokLBracket:
			return TokRBracket
		default:
			return TokRBrace
		}
	}
	var stack []TokenKind
	end := p.cur().End
	guard := 0
	for !p.at(TokEOF) && guard < 1<<18 {
		guard++
		t := p.cur()
		end = t.End
		switch t.Kind {
		case TokDollarParen, TokLParen, TokAtParen, TokLBracket, TokAtBrace, TokLBrace:
			stack = append(stack, closerFor(t.Kind))
			p.advance()
		case TokRParen, TokRBracket, TokRBrace:
			p.advance()
			if n := len(stack); n > 0 && stack[n-1] == t.Kind {
				stack = stack[:n-1]
				if len(stack) == 0 {
					return end
				}
			}
		default:
			p.advance()
		}
	}
	return end
}

func (p *parser) parseCommandName() Expr {
	switch p.kind() {
	case TokGeneric:
		return p.parseNameRun(p.advance())
	case TokString:
		return p.stringLit(p.advance())
	case TokVariable, TokLParen, TokDollarParen, TokLBrace:
		e := p.parsePrimary()
		if _, ok := e.(*Variable); ok {
			p.diag0(e, ReasonDynamicName, "call target is a variable")
		}
		return e
	case TokOperator:
		if v := p.cur().Value; v == "%" || v == "?" {
			t := p.advance()
			return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true, Raw: t.Raw}
		}
	case TokParameter:
		t := p.advance()
		name := "-" + t.Value
		if t.HasColon {
			name += ":"
		}
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: name, Static: true, Bare: true, Raw: t.Raw}
	}
	// no recognisable name
	t := p.cur()
	return &ErrorExpr{span: span{t.Start, t.End}, Reason: ReasonDynamicName, Text: t.Raw}
}

func (p *parser) parseParameter() CommandElement {
	t := p.advance()
	raw := t.Raw
	if t.HasColon && len(raw) > 0 && raw[len(raw)-1] == ':' {
		raw = raw[:len(raw)-1]
	}
	par := &Parameter{span: span{t.Start, t.End}, Name: t.Value, Raw: raw, HasColon: t.HasColon}
	if t.HasColon {
		adjacent := !p.at(TokNewline) && !p.at(TokEOF) && p.cur().Start == t.End
		// -Name:value (adjacent) or -Name: value (the next value across
		// whitespace, unless it is another parameter or a terminator).
		if adjacent || p.colonValueFollows() {
			if a, ok := p.parseCommandArg().(*Arg); ok && a != nil {
				par.Colon = a.Value
				_, par.end = a.Span()
			}
		}
	}
	return par
}

// colonValueFollows reports whether a value token (not a parameter, separator
// or closer) follows a "-Name:" colon parameter and binds as its argument.
func (p *parser) colonValueFollows() bool {
	switch p.kind() {
	case TokGeneric, TokString, TokNumber, TokVariable, TokLParen, TokDollarParen,
		TokAtParen, TokAtBrace, TokLBrace, TokLBracket:
		return true
	}
	return false
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
			if p.at(TokParameter) {
				// after a comma a -word is the next list element (an argument),
				// not a parameter: Remove-Item a,-b -> ["a","-b"] (review 5 R5-10)
				tk := p.advance()
				name := "-" + tk.Value
				if tk.HasColon {
					name += ":"
				}
				arr.Elements = append(arr.Elements, &StringLit{span: span{tk.Start, tk.End}, Kind: StrBare, Value: name, Static: true, Bare: true, Raw: tk.Raw})
				continue
			}
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
	return p.composeAtoms(atoms, s0, end)
}

// barewordExpr builds an argument bareword as an expandable string: it decodes
// backtick escapes and marks the value non-static when it contains a $var or
// $( ) (PowerShell parses such an argument as an ExpandableString).
func (p *parser) barewordExpr(t Token) Expr {
	parts, static, lit := p.expandable(t.Raw, t.Start)
	return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Bare: true, Static: static, Value: lit, Parts: parts, Raw: t.Raw}
}

// parseArgAtom parses a single argument atom (no comma, no fusion).
func (p *parser) parseArgAtom() Expr {
	switch p.kind() {
	case TokGeneric:
		// a bareword argument is an expandable string: a $var / $( ) inside it
		// makes it non-static (unlike a command name, which stays literal).
		return p.barewordExpr(p.advance())
	case TokString, TokNumber, TokVariable, TokLParen, TokDollarParen,
		TokAtParen, TokAtBrace, TokLBrace:
		return p.parsePostfix(p.parsePrimary())
	case TokOperator:
		// an operator character used as argument text (a lone '-', or a glob
		// lead such as * in */*).
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Value, Static: true, Bare: true, Raw: t.Raw}
	case TokDot:
		// a '.' at argument position is a bareword (Remove-Item . -Recurse).
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: ".", Static: true, Bare: true, Raw: t.Raw}
	case TokLabel:
		// a ':name' at argument position is a bareword (Remove-Item :x -Force).
		t := p.advance()
		return &StringLit{span: span{t.Start, t.End}, Kind: StrBare, Value: t.Raw, Static: true, Bare: true, Raw: t.Raw}
	case TokLBracket:
		// [..] at argument position is a literal bareword in command mode
		// (Write-Output [int] -> "[int]"), not a type literal or an index.
		start := p.cur().Start
		end := p.consumeBalancedEnd()
		raw := ""
		if start >= 0 && end <= len(p.src) && end >= start {
			raw = p.src[start:end]
		}
		v, amb := p.decodeBacktick(raw, true)
		sl := &StringLit{span: span{start, end}, Kind: StrBare, Value: v, Static: !amb, Bare: true, Raw: raw}
		if amb {
			p.diag(start, end, ReasonDialectAmbiguous, "backtick escape differs between PS 5.1 and 7")
		}
		return sl
	}
	return nil
}

// fusableLead reports whether an atom may begin a fused argument: a bareword, a
// variable or a $( ) sub-expression (as PowerShell does).
func fusableLead(e Expr) bool {
	switch v := e.(type) {
	case *Variable, *Number:
		return true // note: a $( ) sub-expression does NOT fuse with trailing text
	case *StringLit:
		return v.Bare
	}
	return false
}

// composeAtoms joins adjacent atoms into one value: a static bareword when
// every atom resolves to a literal, otherwise an expandable string whose Parts
// are the atoms (Static=false). It never returns a static value the pieces
// disagree with.
func (p *parser) composeAtoms(atoms []Expr, s0, end int) Expr {
	static := true
	for _, a := range atoms {
		if _, ok := LiteralString(a); !ok {
			static = false
			break
		}
	}
	if static {
		// A fused all-literal argument is a single generic token: its value is
		// the processed source span (quote delimiters dropped, backtick escapes
		// decoded, $(...) kept literal) -- not the per-atom values, so a glued
		// number keeps its source text (0x10-1 stays "0x10-1", not "16-1").
		val, amb := "", false
		if s0 >= 0 && end <= len(p.src) && end >= s0 {
			val, amb = p.decodeBacktick(p.src[s0:end], true)
		}
		if amb {
			p.diag(s0, end, ReasonDialectAmbiguous, "backtick escape differs between PS 5.1 and 7")
		}
		return &StringLit{span: span{s0, end}, Kind: StrBare, Value: val, Static: !amb, Bare: true, Raw: p.rawSpan(s0, end), Fused: true}
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
	case TokGeneric, TokNumber, TokVariable, TokString, TokDollarParen, TokOperator, TokDot, TokLBracket:
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
	// "<" input redirection and > / >> / 2> ... all take the next argument
	// expression (parsed below) as the target.
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

func (p *parser) diag0(e Expr, reason, detail string) {
	if e == nil {
		return
	}
	s0, s1 := e.Span()
	p.diag(s0, s1, reason, detail)
}
