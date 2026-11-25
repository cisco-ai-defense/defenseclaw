// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/pwshparse"
)

// FromPwshparse parses src with the pure-Go port of the Microsoft PowerShell
// parser (internal/pwshparse) and builds the same *Script that Parse builds, so
// the effects frontend reads one AST shape from either parser. It reports false
// when pwshparse declines the input (Unsupported: a construct the port does not
// parse, or nesting beyond its depth budget); the caller then uses Parse.
//
// Conventions kept from Parse: offsets are byte offsets (pwshparse reports
// UTF-16 units); a command name is a literal StringLit (no $ expansion); a
// bareword argument and a quoted string get the value rules of stringLit /
// expandable / decodeBacktick, so a backtick-e or a u{} escape under
// DialectUnknown is not static.
func FromPwshparse(src string, opts Options) (*Script, bool) {
	// The port reads the same input as Parse (GAP-1947): a truncated input
	// (truncatedInput, the one byte bound of both readers, GAP-2086) or one
	// nested past maxPortNesting declines before it parses, and Parse reads the
	// call (its first maxInput bytes, a truncated row; its depth guard). A
	// construct the port does not parse stops the port where it is found
	// (ParseTreeOrDecline), so a give-up never pays for two full parses.
	if truncatedInput(src) || nestingOver(src, maxPortNesting) {
		return nil, false
	}
	res := pwshparse.ParseTreeOrDecline(src)
	if res == nil || res.Root == nil || res.Unsupported {
		return nil, false
	}
	a := &pwAdapter{src: src, res: res, p: &parser{dialect: opts.Dialect, src: src}}
	budget := 8*len(src) + 4096
	a.p.budget = &budget
	a.buildOffsets()
	sc := &Script{Dialect: opts.Dialect}
	sc.start, sc.end = 0, len(src)
	sb := a.scriptBlock(res.Root)
	sc.Statements = sb.Statements
	sc.Params = sb.Params
	for _, e := range res.Errors {
		if e.ErrorID == "StreamAlreadyRedirected" ||
			(e.ErrorID == "RedirectionNotSupported" && strings.Contains(a.src[a.off(e.Start):a.off(e.End)], ">&")) {
			// The redirection is kept on its command (a second one of a
			// stream through rejectedIn; a merge to a stream pwsh does not
			// support, 1>&2, as its MergingRedirectionAst) and Parse reads it
			// without a diagnostic: the construct is fully read (GAP-1915).
			continue
		}
		a.p.diag(a.off(e.Start), a.off(e.End), pwErrorReason(e.ErrorID), e.ErrorID)
		a.p.diags[len(a.p.diags)-1].Syntax = true
	}
	sc.Diagnostics = a.p.diags
	return sc, true
}

// legacyFrontend is the differential seam of ParseEffects, never a runtime
// switch: when it is "psparse" ParseEffects reads with Parse only (the 1.0.10
// reader). Package tests set it directly; tests of other packages and the
// scripts/pwshoracle tools set it at link time:
//
//	go test -ldflags=-X=github.com/defenseclaw/defenseclaw/internal/psparse.legacyFrontend=psparse ...
//
// Shipped binaries never set it. It replaces the old PS_FRONTEND
// environment read (GAP-1924, DET111 ruling 05:55Z): an undocumented knob back
// to the older frontend would be a production downgrade switch.
var legacyFrontend string

// ParseEffects is the PowerShell reader of the effects frontend. It parses
// with FromPwshparse and falls back to Parse when the port declines the input
// (a construct it does not parse, or nesting past its depth budget), so every
// input still gets a Script. With the legacyFrontend seam set it is Parse.
// port reports that FromPwshparse built the Script (its elements are the
// PowerShell parser's own: a native program's argv follows them exactly).
func ParseEffects(src string, opts Options) (sc *Script, port bool, err error) {
	if legacyFrontend != "psparse" {
		if sc, ok := FromPwshparse(src, opts); ok {
			return sc, true, nil
		}
	}
	sc, err = Parse(src, opts)
	return sc, false, err
}

// maxPortNesting bounds the bracket nesting the port parses (GAP-1947): far
// above real scripts, and a deeper input is read by Parse, whose own depth
// guard (maxDepth) stops it early. The port's recursion guard is much deeper,
// so without it a run of 64 KiB of { cost the port eight times Parse.
const maxPortNesting = 8192

// nestingOver reports whether the brackets of src nest deeper than limit at
// some point: ( { [ in code, and the $( ) of an expandable string. Brackets in
// a comment, in a verbatim string or here-string, or in the literal text of an
// expandable string do not nest in the real parser and are not counted
// (GAP-2085): 8193 ( in a comment no longer make the port decline. One linear
// pass, and still an upper bound of the parse depth: a form it does not take
// apart (a '#' glued to a word, a braced variable) has its brackets counted.
func nestingOver(src string, limit int) bool {
	type resumePoint struct {
		depth int
		in    nestText
	}
	var resume []resumePoint // a $( ) of an expandable string: its ')' goes back into the string
	depth, in, tokenStart := 0, nestCode, true
	for i := 0; i < len(src); {
		r, w := utf8.DecodeRuneInString(src[i:])
		if in != nestCode {
			switch {
			case r == '`':
				_, next := utf8.DecodeRuneInString(src[i+w:])
				w += next
			case r == '$' && strings.HasPrefix(src[i+w:], "("):
				if depth++; depth > limit {
					return true
				}
				resume = append(resume, resumePoint{depth, in})
				in, tokenStart, w = nestCode, true, w+1
			case in == nestDQ && isDoubleQuote(r):
				if r2, w2 := utf8.DecodeRuneInString(src[i+w:]); isDoubleQuote(r2) {
					w += w2 // a doubled quote is one quote of the text
				} else {
					in, tokenStart = nestCode, false
				}
			case in == nestHereDQ && r == '\n':
				if n := hereStringClose(src[i+w:], isDoubleQuote); n > 0 {
					in, tokenStart, w = nestCode, false, w+n
				}
			}
			i += w
			continue
		}
		switch {
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\f' || r == 0xA0:
			tokenStart = true
		case r == '(' || r == '{' || r == '[':
			if depth++; depth > limit {
				return true
			}
			tokenStart = r != '['
		case r == ')' || r == '}' || r == ']':
			if n := len(resume); n > 0 && r == ')' && resume[n-1].depth == depth {
				in = resume[n-1].in
				resume = resume[:n-1]
			}
			if depth > 0 {
				depth--
			}
			tokenStart = r != ']'
		case r == ';' || r == '|' || r == ',' || r == '&':
			tokenStart = true
		case r == '=':
			// An = that starts a token is an operator, so the next rune starts one
			// too ($x =# c is a comment); one glued to a word is word text (a=#b):
			// tokenStart stays as it was.
		case r == '`':
			_, next := utf8.DecodeRuneInString(src[i+w:])
			w += next
			tokenStart = false
		case r == '#' && tokenStart:
			if end := strings.IndexByte(src[i:], '\n'); end >= 0 {
				w = end
			} else {
				w = len(src) - i
			}
		case r == '<' && tokenStart && strings.HasPrefix(src[i+w:], "#"):
			if end := strings.Index(src[i+w+1:], "#>"); end >= 0 {
				w += 1 + end + 2
			} else {
				w = len(src) - i
			}
		case r == '@' && hereStringOpen(src[i+w:]) > 0:
			q, _ := utf8.DecodeRuneInString(src[i+w:])
			w += hereStringOpen(src[i+w:])
			if isDoubleQuote(q) {
				in = nestHereDQ
				break
			}
			end := len(src) - i
			for j := i + w; j < len(src); j++ {
				if src[j] == '\n' {
					if n := hereStringClose(src[j+1:], isSingleQuote); n > 0 {
						end = j + 1 + n - i
						break
					}
				}
			}
			w, tokenStart = end, false
		case isSingleQuote(r):
			end := len(src) - i
			for j := i + w; j < len(src); {
				q, qw := utf8.DecodeRuneInString(src[j:])
				if isSingleQuote(q) {
					if q2, qw2 := utf8.DecodeRuneInString(src[j+qw:]); isSingleQuote(q2) {
						j += qw + qw2 // a doubled quote is one quote of the text
						continue
					}
					end = j + qw - i
					break
				}
				j += qw
			}
			w, tokenStart = end, false
		case isDoubleQuote(r):
			in = nestDQ
		default:
			tokenStart = false
		}
		i += w
	}
	return false
}

// nestText is where nestingOver is: in code, or in the text of an expandable
// string or here-string.
type nestText uint8

const (
	nestCode nestText = iota
	nestDQ
	nestHereDQ
)

// hereStringOpen is the byte length of a here-string header after its '@' (a
// quote, then blanks to the end of the line, the newline included), or 0.
func hereStringOpen(s string) int {
	q, w := utf8.DecodeRuneInString(s)
	if !isDoubleQuote(q) && !isSingleQuote(q) {
		return 0
	}
	for j := w; j < len(s); j++ {
		switch s[j] {
		case ' ', '\t', '\r':
		case '\n':
			return j + 1
		default:
			return 0
		}
	}
	return 0
}

// hereStringClose is the byte length of a here-string close at the start of
// line s (a quote of the here-string's kind, then '@'), or 0.
func hereStringClose(s string, quote func(rune) bool) int {
	q, w := utf8.DecodeRuneInString(s)
	if quote(q) && strings.HasPrefix(s[w:], "@") {
		return w + 1
	}
	return 0
}

// pwErrorReason maps a pwshparse error id to the Reason code Parse uses.
func pwErrorReason(id string) string {
	switch {
	case strings.Contains(id, "String") || strings.Contains(id, "Comment"):
		return ReasonUnterminated
	case strings.HasPrefix(id, "Missing") || strings.HasPrefix(id, "Unexpected") || strings.Contains(id, "Unbalanced"):
		return ReasonUnbalanced
	case id == "ParseTooDeep":
		return ReasonDepthLimit
	}
	return ReasonUnknownToken
}

type pwAdapter struct {
	src string
	res *pwshparse.Result
	p   *parser // only for its string / escape readers and its diagnostics
	u2b []int   // UTF-16 unit -> byte offset; nil when the source is ASCII
}

func (a *pwAdapter) buildOffsets() {
	for i := 0; i < len(a.src); i++ {
		if a.src[i] >= utf8.RuneSelf {
			goto multi
		}
	}
	return
multi:
	a.u2b = make([]int, 0, len(a.src)+1)
	for i, r := range a.src {
		a.u2b = append(a.u2b, i)
		if r >= 0x10000 {
			a.u2b = append(a.u2b, i)
		}
	}
	a.u2b = append(a.u2b, len(a.src))
}

func (a *pwAdapter) off(u int) int {
	if a.u2b == nil {
		if u > len(a.src) {
			return len(a.src)
		}
		return u
	}
	if u < 0 {
		return 0
	}
	if u >= len(a.u2b) {
		return len(a.src)
	}
	return a.u2b[u]
}

func (a *pwAdapter) sp(n *pwshparse.Node) span { return span{a.off(n.Start), a.off(n.End)} }
func (a *pwAdapter) raw(n *pwshparse.Node) string {
	s, e := a.off(n.Start), a.off(n.End)
	if s > e || e > len(a.src) {
		return ""
	}
	return a.src[s:e]
}

// ---- statements ----

// scriptBlock flattens a ScriptBlockAst: the param block (names), the unnamed
// end block's statements, and one Block per explicit begin/process/end/clean.
func (a *pwAdapter) scriptBlock(n *pwshparse.Node) *ScriptBlockExpr {
	sb := &ScriptBlockExpr{span: a.sp(n)}
	for _, k := range n.Kids {
		switch k.Type {
		case "ParamBlockAst":
			for _, pk := range k.Kids {
				if pk.Type == "ParameterAst" {
					for _, v := range pk.Kids {
						if v.Type == "VariableExpressionAst" {
							sb.Params = append(sb.Params, a.variable(v))
						}
					}
				}
			}
			sb.Statements = append(sb.Statements, a.generic(k, "param", ""))
		case "NamedBlockAst":
			if k.Prop("Unnamed") == "true" {
				sb.Statements = append(sb.Statements, a.statements(k.Kids)...)
				continue
			}
			inner := &ScriptBlockExpr{span: a.sp(k), Statements: a.statements(k.Kids)}
			sb.Statements = append(sb.Statements, &Block{span: a.sp(k), Keyword: strings.ToLower(k.Prop("BlockKind")), Bodies: []*ScriptBlockExpr{inner}})
		default:
			sb.Statements = append(sb.Statements, a.statements([]*pwshparse.Node{k})...)
		}
	}
	return sb
}

func (a *pwAdapter) statements(kids []*pwshparse.Node) []Statement {
	var out []Statement
	for _, k := range kids {
		out = append(out, a.statement(k))
	}
	return out
}

var pwKeyword = map[string]string{
	"IfStatementAst": "if", "WhileStatementAst": "while", "DoWhileStatementAst": "do", "DoUntilStatementAst": "do",
	"ForStatementAst": "for", "ForEachStatementAst": "foreach", "SwitchStatementAst": "switch", "TryStatementAst": "try",
	"TrapStatementAst": "trap", "ReturnStatementAst": "return", "ThrowStatementAst": "throw", "BreakStatementAst": "break",
	"ContinueStatementAst": "continue", "ExitStatementAst": "exit", "UsingStatementAst": "using", "DataStatementAst": "data",
	"TypeDefinitionAst": "class", "BlockStatementAst": "block", "ParamBlockAst": "param",
}

func (a *pwAdapter) statement(n *pwshparse.Node) Statement {
	switch n.Type {
	case "PipelineAst", "PipelineChainAst":
		return a.pipelineChain(n)
	case "AssignmentStatementAst":
		if len(n.Kids) < 2 {
			break
		}
		return &Assignment{span: a.sp(n), LHS: a.expr(n.Kids[0]), Op: pwAssignOp(n.Prop("Operator")), RHS: a.statement(n.Kids[1])}
	case "ErrorStatementAst":
		return &UnknownStatement{span: a.sp(n), Reason: ReasonUnknownToken, Text: a.raw(n)}
	case "FunctionDefinitionAst":
		kw := "function"
		if n.Prop("IsFilter") == "true" {
			kw = "filter"
		} else if n.Prop("IsWorkflow") == "true" {
			kw = "workflow"
		}
		return a.generic(n, kw, n.Prop("Name"))
	case "StatementBlockAst", "NamedBlockAst":
		return &Block{span: a.sp(n), Keyword: "(group)", Bodies: []*ScriptBlockExpr{a.block(n)}}
	}
	if kw, ok := pwKeyword[n.Type]; ok {
		return a.generic(n, kw, "")
	}
	if n.Type == "CommandExpressionAst" || n.Type == "CommandAst" {
		return a.pipelineChain(n)
	}
	if strings.HasSuffix(n.Type, "StatementAst") || strings.HasSuffix(n.Type, "DefinitionAst") {
		return a.generic(n, strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(n.Type, "Ast"), "Statement")), "")
	}
	if isExprNode(n) {
		return &ExprStatement{span: a.sp(n), Expr: a.expr(n)}
	}
	return a.generic(n, strings.ToLower(strings.TrimSuffix(n.Type, "Ast")), "")
}

// generic builds a Block for a control, function or declaration node: nested
// statement blocks become Bodies, every other statement or expression a
// Condition (so every nested command is still walked).
func (a *pwAdapter) generic(n *pwshparse.Node, kw, name string) *Block {
	b := &Block{span: a.sp(n), Keyword: kw, Name: name}
	a.fill(b, n)
	return b
}

func (a *pwAdapter) fill(b *Block, n *pwshparse.Node) {
	for _, k := range n.Kids {
		switch k.Type {
		case "StatementBlockAst", "ScriptBlockAst", "NamedBlockAst":
			b.Bodies = append(b.Bodies, a.block(k))
		case "CatchClauseAst", "ParameterAst", "ParamBlockAst", "AttributeAst", "NamedAttributeArgumentAst", "TypeConstraintAst",
			"MemberAst", "FunctionMemberAst", "PropertyMemberAst", "SwitchClauseAst":
			a.fill(b, k)
		default:
			b.Conditions = append(b.Conditions, a.statement(k))
		}
	}
}

// block reads a StatementBlockAst / NamedBlockAst / ScriptBlockAst as a body.
func (a *pwAdapter) block(n *pwshparse.Node) *ScriptBlockExpr {
	if n.Type == "ScriptBlockAst" {
		return a.scriptBlock(n)
	}
	return &ScriptBlockExpr{span: a.sp(n), Statements: a.statements(n.Kids)}
}

func pwAssignOp(op string) string {
	switch op {
	case "Equals", "":
		return "="
	case "PlusEquals":
		return "+="
	case "MinusEquals":
		return "-="
	case "MultiplyEquals":
		return "*="
	case "DivideEquals":
		return "/="
	case "RemainderEquals":
		return "%="
	case "QuestionQuestionEquals":
		return "??="
	}
	return op
}

// pipelineChain flattens a left-nested PipelineChainAst into a Pipeline linked by
// ChainOp / ChainRHS, and a one-expression pipeline into an ExprStatement.
func (a *pwAdapter) pipelineChain(n *pwshparse.Node) Statement {
	var segs []*pwshparse.Node
	var ops []string
	var walk func(x *pwshparse.Node)
	walk = func(x *pwshparse.Node) {
		if x.Type == "PipelineChainAst" && len(x.Kids) == 2 {
			walk(x.Kids[0])
			if strings.Contains(x.Prop("Operator"), "And") {
				ops = append(ops, "&&")
			} else {
				ops = append(ops, "||")
			}
			segs = append(segs, x.Kids[1])
			return
		}
		segs = append(segs, x)
	}
	walk(n)
	pls := make([]*Pipeline, len(segs))
	for i, s := range segs {
		pls[i] = a.pipeline(s)
	}
	for i := 0; i+1 < len(pls); i++ {
		pls[i].ChainOp, pls[i].ChainRHS = ops[i], pls[i+1]
	}
	if len(pls) == 1 && len(pls[0].Elements) == 1 && len(pls[0].Redirs) == 0 && !pls[0].Background {
		if es, ok := pls[0].Elements[0].(*ExprStatement); ok {
			return es
		}
	}
	pls[0].end = pls[len(pls)-1].end
	return pls[0]
}

func (a *pwAdapter) pipeline(n *pwshparse.Node) *Pipeline {
	pl := &Pipeline{span: a.sp(n)}
	elems := []*pwshparse.Node{n}
	if n.Type == "PipelineAst" {
		elems = n.Kids
		pl.Background = n.Prop("Background") == "true"
	}
	for _, e := range elems {
		switch e.Type {
		case "CommandAst":
			pl.Elements = append(pl.Elements, a.command(e))
		case "CommandExpressionAst":
			var ex Expr
			var redirs []*pwshparse.Node
			for _, k := range e.Kids {
				if isRedirNode(k) {
					redirs = append(redirs, k)
				} else if ex == nil {
					ex = a.expr(k)
				}
			}
			for _, r := range sortByStart(append(redirs, a.rejectedIn(e)...)) {
				pl.Redirs = append(pl.Redirs, a.redirection(r))
			}
			if ex == nil {
				ex = &ErrorExpr{span: a.sp(e), Reason: ReasonIncompleteExpr}
			}
			pl.Elements = append(pl.Elements, &ExprStatement{span: a.sp(e), Expr: ex})
		case "ErrorStatementAst":
			pl.Elements = append(pl.Elements, &UnknownStatement{span: a.sp(e), Reason: ReasonUnknownToken, Text: a.raw(e)})
		default:
			if st, ok := a.statement(e).(PipelineElement); ok {
				pl.Elements = append(pl.Elements, st)
			} else {
				pl.Elements = append(pl.Elements, &ExprStatement{span: a.sp(e), Expr: a.expr(e)})
			}
		}
	}
	return pl
}

// ---- commands ----

func isRedirNode(n *pwshparse.Node) bool {
	return n.Type == "FileRedirectionAst" || n.Type == "MergingRedirectionAst"
}

// bareWord reports whether n is a bareword constant or bareword expandable
// string (the generic-token forms).
func bareWord(n *pwshparse.Node) bool {
	return (n.Type == "StringConstantExpressionAst" || n.Type == "ExpandableStringExpressionAst") && n.Prop("StringConstantType") == "BareWord"
}

// command builds a Command the way parseCommand does: the first element is the
// name (a greedy literal for a generic token), then parameters, arguments and
// redirections in source order, and a --% verbatim tail.
func (a *pwAdapter) command(n *pwshparse.Node) *Command {
	cmd := &Command{span: a.sp(n)}
	switch n.Prop("InvocationOperator") {
	case "Ampersand":
		cmd.InvokeOp = "&"
	case "Dot":
		cmd.InvokeOp = "."
	}
	var elems, redirs []*pwshparse.Node
	for _, k := range n.Kids {
		if isRedirNode(k) {
			redirs = append(redirs, k)
		} else {
			elems = append(elems, k)
		}
	}
	redirs = append(redirs, a.rejectedIn(n)...)
	if len(elems) > 0 {
		cmd.Name = a.commandName(elems[0])
		elems = elems[1:]
	} else {
		cmd.Name = &ErrorExpr{span: a.sp(n), Reason: ReasonDynamicName}
	}
	for i := 0; i < len(elems); i++ {
		k := elems[i]
		switch {
		case k.Type == "CommandParameterAst":
			cmd.Elements = append(cmd.Elements, a.parameter(k))
		case k.Type == "StringConstantExpressionAst" && bareWord(k) && k.Str == "--%" && a.raw(k) == "--%":
			s := a.sp(k)
			cmd.Elements = append(cmd.Elements, &Arg{span: s, Value: &StringLit{span: s, Kind: StrBare, Value: "--%", Static: true, Bare: true, Raw: "--%"}})
			if i+1 < len(elems) {
				i++
				t := elems[i]
				ts, tail := a.sp(t), a.raw(t)
				cmd.StopParsing = tail
				cmd.Elements = append(cmd.Elements, &Arg{span: ts, Value: &StringLit{span: ts, Kind: StrBare, Value: tail, Static: true, Bare: true, Raw: tail}})
			}
			a.p.diag(cmd.start, cmd.end, ReasonStopParsing, "verbatim --% tail")
		default:
			v := a.argExpr(k)
			s, e := v.Span()
			cmd.Elements = append(cmd.Elements, &Arg{span: span{s, e}, Value: v})
		}
	}
	// pwshparse keeps one redirection per stream ordered by stream; Parse keeps
	// source order.
	for _, r := range sortByStart(redirs) {
		cmd.Redirs = append(cmd.Redirs, a.redirection(r))
	}
	return cmd
}

// sortByStart orders redirection nodes by source offset (insertion sort: a
// command has a handful).
func sortByStart(rs []*pwshparse.Node) []*pwshparse.Node {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Start < rs[j-1].Start; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
	return rs
}

// rejectedIn returns the redirections pwshparse read for command n but did not
// attach (Result.Rejected: a second redirection of one stream, which pwsh
// reports as StreamAlreadyRedirected). Parse keeps every redirection, and the
// effects reader must see each target the text names even when pwsh would
// refuse the script (GAP-1915: `... 1>&2 >> authorized_keys` lost its append),
// so each one goes to the command it was read for: n contains it and none of
// n's elements does (a redirection of a nested command lies inside an element).
func (a *pwAdapter) rejectedIn(n *pwshparse.Node) []*pwshparse.Node {
	var out []*pwshparse.Node
	for _, r := range a.res.Rejected {
		if r.Start < n.Start || r.End > n.End {
			continue
		}
		nested := false
		for _, k := range n.Kids {
			if k.Start <= r.Start && r.End <= k.End {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, r)
		}
	}
	return out
}

// commandName mirrors parseCommandName: a generic token is one literal name
// (no $ expansion, backtick escapes decoded); a quoted name uses the string
// rules; anything else is an expression (a variable target is dynamic).
func (a *pwAdapter) commandName(n *pwshparse.Node) Expr {
	if bareWord(n) {
		s := a.sp(n)
		raw := a.raw(n)
		v, amb := a.p.decodeBacktick(raw, true)
		if amb {
			a.p.diag(s.start, s.end, ReasonDialectAmbiguous, "backtick escape in a name differs between PS 5.1 and 7")
		}
		return &StringLit{span: s, Kind: StrBare, Bare: true, Static: !amb, Value: v, Raw: raw}
	}
	e := a.expr(n)
	if _, ok := e.(*Variable); ok {
		s, en := e.Span()
		a.p.diag(s, en, ReasonDynamicName, "call target is a variable")
	}
	return e
}

func (a *pwAdapter) parameter(n *pwshparse.Node) *Parameter {
	s := a.sp(n)
	par := &Parameter{span: s, Name: n.Prop("ParameterName")}
	var arg *pwshparse.Node
	if len(n.Kids) > 0 {
		arg = n.Kids[0]
	}
	head := a.raw(n)
	if arg != nil {
		as := a.off(arg.Start)
		if as >= s.start && as <= s.end {
			head = a.src[s.start:as]
		}
		par.Colon = a.argExpr(arg)
	}
	head = strings.TrimRight(head, " \t\r\n`")
	if strings.HasSuffix(head, ":") {
		par.HasColon = true
		head = head[:len(head)-1]
	}
	par.Raw = head
	return par
}

// redirection reads the operator text from the source, as the psparse lexer
// does: an optional stream prefix (digit or *), > or >>, and &N for a merge.
func (a *pwAdapter) redirection(n *pwshparse.Node) *Redirection {
	s := a.sp(n)
	raw := a.raw(n)
	i := 0
	for i < len(raw) && (raw[i] == '*' || (raw[i] >= '0' && raw[i] <= '9')) {
		i++
	}
	op := raw[:i]
	if i < len(raw) && raw[i] == '>' {
		i++
		op += ">"
		if i < len(raw) && raw[i] == '>' {
			i++
			op += ">"
		}
	}
	r := &Redirection{span: s, Op: op}
	if n.Type == "MergingRedirectionAst" {
		if i+1 < len(raw) && raw[i] == '&' && raw[i+1] >= '0' && raw[i+1] <= '9' {
			r.Merge = raw[i+1 : i+2]
		}
		return r
	}
	if len(n.Kids) > 0 {
		r.Target = a.argExpr(n.Kids[0])
	}
	return r
}

// argExpr reads a command argument with the bareword rules of barewordExpr and
// composeAtoms; other expressions go through expr.
func (a *pwAdapter) argExpr(n *pwshparse.Node) Expr {
	if !bareWord(n) {
		if n.Type == "ArrayLiteralAst" {
			arr := &ArrayLit{span: a.sp(n)}
			for _, k := range n.Kids {
				arr.Elements = append(arr.Elements, a.argExpr(k))
			}
			return arr
		}
		return a.expr(n)
	}
	s := a.sp(n)
	raw := a.raw(n)
	if n.Type == "ExpandableStringExpressionAst" {
		// a word with an expansion ($x\y, C:\$(f)): Parse composes its atoms
		// into one non-static expandable string (composeAtoms).
		return &StringLit{span: s, Kind: StrDouble, Static: false, Parts: a.wordParts(n)}
	}
	if strings.ContainsAny(raw, "'\"‘’‚‛“”„") {
		// the value is the token value pwsh computes (inner quotes of the other kind stay);
		// decodeBacktick still decides whether an escape is dialect-ambiguous.
		_, amb := a.p.decodeBacktick(raw, true)
		v := n.Str
		if amb {
			a.p.diag(s.start, s.end, ReasonDialectAmbiguous, "backtick escape differs between PS 5.1 and 7")
		}
		return &StringLit{span: s, Kind: StrBare, Value: v, Static: !amb, Bare: true, Raw: raw, Fused: true}
	}
	return a.p.barewordExpr(Token{Kind: TokGeneric, Raw: raw, Value: raw, Start: s.start, End: s.end})
}

// wordParts splits an expandable bareword into atoms as composeAtoms keeps
// them: the literal text between expansions and each expansion as its
// expression. Quote delimiters inside the word are not part of its value:
// pwsh reads $HOME'\x' as the word $HOME\x (the oracle value), so each quoted
// run is a string literal of its kind with the delimiters dropped, and a
// quote opened before an expansion stays open after it (-o"$v"x).
func (a *pwAdapter) wordParts(n *pwshparse.Node) []StringPart {
	var out []StringPart
	s := a.sp(n)
	pos := s.start
	var q rune // the open quote kind: 0, '\'' or '"'
	lit := func(e int) {
		if e > pos && e <= len(a.src) {
			out = append(out, a.quotedRuns(pos, e, &q)...)
		}
	}
	for _, k := range n.Kids {
		ks, ke := a.off(k.Start), a.off(k.End)
		if ks < pos || ke > s.end {
			continue
		}
		lit(ks)
		out = append(out, StringPart{Expr: a.expr(k)})
		pos = ke
	}
	lit(s.end)
	return out
}

// quotedRuns reads src[s:e], a piece of a generic word between expansions:
// an unquoted run is a bareword atom, a single- or double-quoted run is a
// string literal without its delimiters (a doubled quote is one quote, a
// backtick escapes the next character). *q carries an open quote across an
// expansion.
func (a *pwAdapter) quotedRuns(s, e int, q *rune) []StringPart {
	var out []StringPart
	start := s
	flush := func(end int) {
		if end <= start {
			return
		}
		raw := a.src[start:end]
		switch *q {
		case '\'':
			out = append(out, StringPart{Expr: &StringLit{span: span{start, end}, Kind: StrSingle, Raw: raw, Value: collapseDoubled(raw, isSingleQuote), Static: true}})
		case '"':
			out = append(out, StringPart{Expr: a.p.stringLit(Token{Kind: TokString, Raw: `"` + raw + `"`, Start: start - 1, End: end + 1, Str: StrDouble})})
		default:
			out = append(out, StringPart{Expr: a.p.barewordExpr(Token{Kind: TokGeneric, Raw: raw, Value: raw, Start: start, End: end})})
		}
	}
	for i := s; i < e; {
		r, sz := utf8.DecodeRuneInString(a.src[i:e])
		next := func() (rune, int) {
			if i+sz >= e {
				return 0, 0
			}
			return utf8.DecodeRuneInString(a.src[i+sz : e])
		}
		switch {
		case r == '`' && *q != '\'':
			_, nsz := next()
			i += sz + nsz
			continue
		case *q == 0 && isSingleQuote(r):
			flush(i)
			*q, start = '\'', i+sz
		case *q == 0 && isDoubleQuote(r):
			flush(i)
			*q, start = '"', i+sz
		case (*q == '\'' && isSingleQuote(r)) || (*q == '"' && isDoubleQuote(r)):
			if nr, nsz := next(); (*q == '\'' && isSingleQuote(nr)) || (*q == '"' && isDoubleQuote(nr)) {
				i += sz + nsz // a doubled quote is one literal quote
				continue
			}
			flush(i)
			*q, start = 0, i+sz
		}
		i += sz
	}
	flush(e)
	return out
}

// ---- expressions ----

func (a *pwAdapter) kid(n *pwshparse.Node, i int) *pwshparse.Node {
	if i < len(n.Kids) {
		return n.Kids[i]
	}
	return nil
}

func (a *pwAdapter) exprOrErr(n *pwshparse.Node, parent *pwshparse.Node) Expr {
	if n == nil {
		return &ErrorExpr{span: a.sp(parent), Reason: ReasonIncompleteExpr}
	}
	return a.expr(n)
}

func (a *pwAdapter) expr(n *pwshparse.Node) Expr {
	s := a.sp(n)
	switch n.Type {
	case "StringConstantExpressionAst", "ExpandableStringExpressionAst":
		raw := a.raw(n)
		switch n.Prop("StringConstantType") {
		case "SingleQuoted":
			// the value pwsh computes: a doubled curly quote collapses to its
			// first character, which collapseDoubled does not reproduce
			sl := a.p.stringLit(Token{Kind: TokString, Raw: raw, Start: s.start, End: s.end, Str: StrSingle})
			sl.Value = n.Str
			return sl
		case "DoubleQuoted":
			return a.p.stringLit(Token{Kind: TokString, Raw: raw, Start: s.start, End: s.end, Str: StrDouble})
		case "SingleQuotedHereString":
			return a.p.stringLit(Token{Kind: TokString, Raw: raw, Start: s.start, End: s.end, Str: StrHereSingle})
		case "DoubleQuotedHereString":
			return a.p.stringLit(Token{Kind: TokString, Raw: raw, Start: s.start, End: s.end, Str: StrHereDouble})
		}
		return a.argExpr(n)
	case "ConstantExpressionAst":
		return numberLit(Token{Kind: TokNumber, Raw: a.raw(n), Value: a.raw(n), Start: s.start, End: s.end})
	case "VariableExpressionAst":
		return a.variable(n)
	case "UsingExpressionAst":
		if k := a.kid(n, 0); k != nil {
			e := a.expr(k)
			if v, ok := e.(*Variable); ok && v.Scope == "" {
				v.Scope = "using"
			}
			return e
		}
	case "ScriptBlockExpressionAst":
		if k := a.kid(n, 0); k != nil && k.Type == "ScriptBlockAst" {
			sb := a.scriptBlock(k)
			sb.span = s
			return sb
		}
		return &ScriptBlockExpr{span: s}
	case "SubExpressionAst", "ArrayExpressionAst":
		var st []Statement
		if k := a.kid(n, 0); k != nil {
			st = a.statements(k.Kids)
		}
		if n.Type == "SubExpressionAst" {
			return &SubExpr{span: s, Statements: st}
		}
		return &ArrayExpr{span: s, Statements: st}
	case "ParenExpressionAst":
		p := &Paren{span: s}
		if k := a.kid(n, 0); k != nil {
			p.Inner = a.statement(k)
		}
		return p
	case "HashtableAst":
		h := &Hashtable{span: s}
		for i := 0; i+1 < len(n.Kids); i += 2 {
			h.Keys = append(h.Keys, a.expr(n.Kids[i]))
			h.Values = append(h.Values, a.valueExpr(n.Kids[i+1]))
		}
		return h
	case "ArrayLiteralAst":
		arr := &ArrayLit{span: s}
		for _, k := range n.Kids {
			arr.Elements = append(arr.Elements, a.expr(k))
		}
		return arr
	case "IndexExpressionAst":
		return &Index{span: s, Target: a.exprOrErr(a.kid(n, 0), n), Index: a.exprOrErr(a.kid(n, 1), n)}
	case "MemberExpressionAst", "InvokeMemberExpressionAst", "BaseCtorInvokeMemberExpressionAst":
		static := n.Prop("Static") == "true"
		name, reason := "", ""
		if m := a.kid(n, 1); m != nil && m.Type == "StringConstantExpressionAst" {
			name = m.Str
		} else {
			reason = ReasonDynamicMember
		}
		target := a.exprOrErr(a.kid(n, 0), n)
		if n.Type == "MemberExpressionAst" {
			mb := &Member{span: s, Target: target, Name: name, Static: static, Reason: reason}
			if reason != "" && a.kid(n, 1) != nil {
				// keep a computed member walked: $x.$(cmd)
				return &ArrayLit{span: s, Elements: []Expr{mb, a.expr(n.Kids[1])}}
			}
			return mb
		}
		inv := &Invoke{span: s, Target: target, Name: name, Static: static, Reason: reason}
		for _, k := range n.Kids[min(2, len(n.Kids)):] {
			inv.Args = append(inv.Args, a.expr(k))
		}
		if reason != "" && a.kid(n, 1) != nil {
			inv.Args = append(inv.Args, a.expr(n.Kids[1]))
		}
		return inv
	case "BinaryExpressionAst":
		return &Binary{span: s, Op: pwBinaryOp(n.Prop("Operator")), LHS: a.exprOrErr(a.kid(n, 0), n), RHS: a.exprOrErr(a.kid(n, 1), n)}
	case "UnaryExpressionAst":
		tk := n.Prop("TokenKind")
		return &Unary{span: s, Op: pwUnaryOp(tk), Operand: a.exprOrErr(a.kid(n, 0), n), Postfix: strings.HasPrefix(tk, "Postfix")}
	case "ConvertExpressionAst", "AttributedExpressionAst":
		ty := ""
		if t := a.kid(n, 0); t != nil {
			ty = t.Prop("TypeName")
		}
		return &Convert{span: s, Type: ty, Operand: a.exprOrErr(a.kid(n, 1), n)}
	case "TypeExpressionAst":
		return &TypeExpr{span: s, Name: n.Prop("TypeName")}
	case "ErrorExpressionAst":
		if len(n.Kids) == 0 {
			return &ErrorExpr{span: s, Reason: ReasonIncompleteExpr, Text: a.raw(n)}
		}
	case "CommandAst", "CommandExpressionAst", "PipelineAst", "PipelineChainAst", "AssignmentStatementAst":
		return &Paren{span: s, Inner: a.statement(n)}
	}
	// any other node (ternary, an error node with children, a statement in
	// expression position): keep its children walked.
	arr := &ArrayLit{span: s}
	for _, k := range n.Kids {
		if isExprNode(k) {
			arr.Elements = append(arr.Elements, a.expr(k))
		} else {
			arr.Elements = append(arr.Elements, &Paren{span: a.sp(k), Inner: a.statement(k)})
		}
	}
	return arr
}

// valueExpr reads a hashtable value statement: a one-expression pipeline is
// that expression, anything else a Paren around the statement.
func (a *pwAdapter) valueExpr(n *pwshparse.Node) Expr {
	st := a.statement(n)
	if es, ok := st.(*ExprStatement); ok {
		return es.Expr
	}
	return &Paren{span: a.sp(n), Inner: st}
}

func (a *pwAdapter) variable(n *pwshparse.Node) *Variable {
	path := n.Prop("VariablePath")
	v := &Variable{span: a.sp(n), Name: path, Splat: n.Prop("Splatted") == "true"}
	if i := strings.IndexByte(path, ':'); i > 0 {
		v.Scope, v.Name = strings.ToLower(path[:i]), path[i+1:]
	}
	return v
}

func isExprNode(n *pwshparse.Node) bool {
	switch n.Type {
	case "ErrorExpressionAst", "TernaryExpressionAst", "BinaryExpressionAst", "UnaryExpressionAst",
		"AttributedExpressionAst", "ConvertExpressionAst", "MemberExpressionAst",
		"InvokeMemberExpressionAst", "BaseCtorInvokeMemberExpressionAst", "TypeExpressionAst",
		"VariableExpressionAst", "ConstantExpressionAst", "StringConstantExpressionAst",
		"ExpandableStringExpressionAst", "ScriptBlockExpressionAst", "ArrayLiteralAst",
		"HashtableAst", "ArrayExpressionAst", "ParenExpressionAst", "SubExpressionAst",
		"UsingExpressionAst", "IndexExpressionAst":
		return true
	}
	return false
}

var pwBinOps = map[string]string{
	"Plus": "+", "Minus": "-", "Multiply": "*", "Divide": "/", "Rem": "%", "DotDot": "..", "Format": "-f",
	"And": "-and", "Or": "-or", "Xor": "-xor", "Band": "-band", "Bor": "-bor", "Bxor": "-bxor", "Shl": "-shl", "Shr": "-shr",
	"Join": "-join", "QuestionQuestion": "??", "Is": "-is", "IsNot": "-isnot", "As": "-as",
}

// pwBinaryOp spells a pwshparse operator token kind the way Parse does
// ("Ieq" -> "-eq", "Creplace" -> "-creplace", "Plus" -> "+").
func pwBinaryOp(k string) string {
	if op, ok := pwBinOps[k]; ok {
		return op
	}
	if len(k) > 1 && k[0] == 'I' {
		return "-" + strings.ToLower(k[1:])
	}
	return "-" + strings.ToLower(k)
}

func pwUnaryOp(k string) string {
	switch k {
	case "Exclaim":
		return "!"
	case "Minus":
		return "-"
	case "Plus":
		return "+"
	case "PlusPlus", "PostfixPlusPlus":
		return "++"
	case "MinusMinus", "PostfixMinusMinus":
		return "--"
	case "Comma":
		return ","
	}
	return "-" + strings.ToLower(k)
}
