// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// parsePowerShell lowers a PowerShell command into the neutral IR using the
// full-grammar parser in internal/psparse (lane s7-pwsh). It replaces the
// former hand tokenizer: the extractor and program table are unchanged; this
// adapter maps psparse's AST onto IR Cmds/Words at the dialect seam
// (EFFECTS.md "PowerShell AST"). Anything psparse could not resolve statically
// is a diagnostic -> a structural unknown; a dynamic value is a dynamic Word;
// a static nested script (-Command, iex 'lit', cmd /c) is expanded one level.
func parsePowerShell(command string, o Options) *Script {
	return lowerPSScript(command, o, true)
}

func lowerPSScript(command string, o Options, expandNested bool) *Script {
	s := &Script{Dialect: DialectPowerShell}
	// The PowerShell edition is unknown unless the connector proves it, so a
	// dialect-divergent escape (backtick-e, \u{}) is not treated as static
	// (psparse review 3 / R4). A future caller that knows the host edition can
	// pass DialectPwsh7 / DialectWindowsPS51.
	sc, err := psparse.Parse(command, psparse.Options{Dialect: psparse.DialectUnknown})
	if err != nil || sc == nil {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonInvalidSyntax})
		return s
	}
	for _, d := range sc.Diagnostics {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: psReason(d.Reason)})
	}
	lw := &psLower{out: s, o: o}
	lw.statements(sc.Statements, false)
	if expandNested {
		// Start-Process launching powershell/pwsh/cmd: psparse joins/splits the
		// -ArgumentList wrongly (quotes, prefixes, dynamic elements), so the
		// extracted nested text is never trusted -- the child runs opaque code
		// (psparse delta review 5 (a)). Collect those host commands so we can both
		// drop their nested expansion and record the opacity.
		spShell := map[psparse.Node]bool{}
		collectPSCommands(sc.Statements, 0, func(c *psparse.Command) {
			if psStartProcessShellTarget(c) {
				spShell[c] = true
			}
		})
		for range spShell {
			s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
		}
		for _, ns := range psparse.ExtractNestedScripts(sc) {
			if spShell[ns.Source] {
				continue // never use a Start-Process-into-shell nested text (review 5 (a))
			}
			// A powershell/pwsh host carrying -EncodedArguments: psparse decodes
			// the CLIXML args blob as if it were the script (and misses the real
			// -EncodedCommand), so never re-parse it. The payload is opaque; the
			// walker also emits an opaque exec for the host (psparse delta review
			// 4 (c)).
			if cmd, ok := ns.Source.(*psparse.Command); ok && psHostHasEncodedArgs(cmd) {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			// A -Command / -EncodedCommand payload whose source carries a " is not
			// trusted under DialectUnknown / 5.1: the child drops the quotes (legacy
			// native argument passing), so the static parse can miss a command
			// inside the quoted span (psparse delta review 5 (b)).
			if ns.Static && ns.Dialect == "powershell" &&
				(ns.Kind == psparse.KindPowerShellCommand || ns.Kind == psparse.KindEncodedCommand) &&
				strings.Contains(ns.Text, `"`) {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			if !ns.Static {
				s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonOpaqueCode})
				continue
			}
			var inner *Script
			if ns.Dialect == "cmd" {
				inner = parseCMD(ns.Text, o)
			} else {
				inner = lowerPSScript(ns.Text, o, false)
			}
			s.Funcs = append(s.Funcs, inner.Funcs...)
			s.Stmts = append(s.Stmts, inner.Stmts...)
			s.Unknowns = append(s.Unknowns, inner.Unknowns...)
		}
	}
	return s
}

// psLeaf lower-cases a command/file name and strips its directory and a trailing
// .exe, so "C:\\WINDOWS\\System32\\cmd.exe" and "cmd" compare equal.
func psLeaf(name string) string {
	b := strings.ToLower(name)
	if i := strings.LastIndexAny(b, `\/`); i >= 0 {
		b = b[i+1:]
	}
	return strings.TrimSuffix(b, ".exe")
}

// isShellName reports a program that runs code from its arguments: powershell,
// pwsh or cmd.
func isShellName(name string) bool {
	switch psLeaf(name) {
	case "powershell", "pwsh", "cmd":
		return true
	}
	return false
}

// psStartProcessShellTarget reports a Start-Process (saps) command whose child
// is powershell/pwsh/cmd in any argument form -- the child's -ArgumentList is
// run as code we cannot reconstruct, so it is opaque (psparse delta review 5
// (a)). The child is the -FilePath value, else the first positional argument.
func psStartProcessShellTarget(c *psparse.Command) bool {
	if n := psBaseNameOf(c); n != "start-process" && n != "saps" {
		return false
	}
	var target, firstPos psparse.Expr
	els := c.Elements
	for i := 0; i < len(els); i++ {
		switch e := els[i].(type) {
		case *psparse.Parameter:
			n := strings.ToLower(e.Name)
			if n != "" && strings.HasPrefix("filepath", n) { // -F.. -> -FilePath (unique prefix)
				if e.HasColon && e.Colon != nil {
					target = e.Colon
				} else if i+1 < len(els) {
					if a, ok := els[i+1].(*psparse.Arg); ok {
						target = a.Value
						i++
					}
				}
			}
		case *psparse.Arg:
			if firstPos == nil {
				firstPos = e.Value
			}
		}
	}
	if target == nil {
		target = firstPos
	}
	if target == nil {
		return false
	}
	s, ok := psparse.LiteralString(target)
	// A shell child, or a launcher (wt/conhost/start) that itself starts a shell,
	// runs an opaque payload (psparse delta review 5 (a) / review 6 (c)).
	return ok && (isShellName(s) || isLauncherName(s))
}

// psBaseNameOf returns the leaf name of a command, or "" when it is not a literal.
func psBaseNameOf(c *psparse.Command) string {
	if name, ok := psparse.LiteralString(c.Name); ok {
		return psLeaf(name)
	}
	return ""
}

// collectPSCommands calls fn for every command in the statements, descending one
// level into script-block arguments and block bodies, bounded by depth.
func collectPSCommands(sts []psparse.Statement, depth int, fn func(*psparse.Command)) {
	if depth > maxNestedDepth {
		return
	}
	for _, st := range sts {
		switch v := st.(type) {
		case *psparse.Pipeline:
			for seg := v; seg != nil; seg = seg.ChainRHS {
				for _, el := range seg.Elements {
					c, ok := el.(*psparse.Command)
					if !ok {
						continue
					}
					fn(c)
					for _, ce := range c.Elements {
						if a, ok := ce.(*psparse.Arg); ok {
							if sb, ok := a.Value.(*psparse.ScriptBlockExpr); ok {
								collectPSCommands(sb.Statements, depth+1, fn)
							}
						}
					}
				}
			}
		case *psparse.Block:
			collectPSCommands(v.Conditions, depth+1, fn)
			for _, b := range v.Bodies {
				if b != nil {
					collectPSCommands(b.Statements, depth+1, fn)
				}
			}
		}
	}
}

// psHostHasEncodedArgs reports a powershell/pwsh host command that carries an
// -EncodedArguments (/-encodeda/-ea) parameter, so its nested payload must not
// be re-parsed (psparse delta review 4 (c)).
func psHostHasEncodedArgs(c *psparse.Command) bool {
	if b := psBaseNameOf(c); b != "powershell" && b != "pwsh" {
		return false
	}
	for _, el := range c.Elements {
		p, ok := el.(*psparse.Parameter)
		if !ok {
			continue
		}
		n := strings.ToLower(p.Name)
		if n == "ea" || (strings.HasPrefix(n, "encodeda") && strings.HasPrefix("encodedarguments", n)) {
			return true
		}
	}
	return false
}

func psReason(code string) ReasonCode {
	switch code {
	case psparse.ReasonDynamicName, psparse.ReasonDynamicMember, psparse.ReasonNonLiteral:
		return ReasonDynamicExpansion
	case psparse.ReasonStopParsing:
		return ReasonOpaqueCode
	case psparse.ReasonDepthLimit, psparse.ReasonTruncated:
		return ReasonLimit
	default:
		return ReasonUnparsedConstruct
	}
}

type psLower struct {
	out *Script
	o   Options
}

func (lw *psLower) statements(sts []psparse.Statement, cond bool) {
	for _, st := range sts {
		lw.statement(st, cond)
	}
}

func (lw *psLower) statement(st psparse.Statement, cond bool) {
	switch v := st.(type) {
	case *psparse.Pipeline:
		lw.pipeline(v, cond)
	case *psparse.Assignment:
		lw.assignment(v, cond)
	case *psparse.Block:
		// A function (or filter) defined here shadows a cmdlet of the same name for
		// the rest of the script: the walker must not treat that name as the
		// cmdlet (round 8 H, rv7-B48). Names are case-insensitive.
		if v.Name != "" {
			switch strings.ToLower(v.Keyword) {
			case "function", "filter", "workflow":
				lw.out.Funcs = append(lw.out.Funcs, strings.ToLower(v.Name))
			}
		}
		lw.statements(v.Conditions, cond)
		for _, b := range v.Bodies {
			if b != nil {
				lw.statements(b.Statements, true)
			}
		}
	case *psparse.ExprStatement:
		// a bare expression: recurse for any nested commands via its sub-exprs.
		lw.exprCommands(v.Expr, cond)
	case *psparse.UnknownStatement:
		lw.out.Unknowns = append(lw.out.Unknowns, UnknownNode{Reason: psReason(v.Reason)})
	}
}

func (lw *psLower) pipeline(p *psparse.Pipeline, cond bool) {
	first := true
	for seg := p; seg != nil; seg = seg.ChainRHS {
		segCond := cond || !first
		var lastCmd *Cmd
		// A command is pipeline-fed when any element precedes it, including a
		// bare expression/string stage (review N5 S3/S4).
		for idx, el := range seg.Elements {
			switch e := el.(type) {
			case *psparse.Command:
				c := lw.command(e, segCond, idx > 0)
				lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: segCond})
				lastCmd = c
			case *psparse.ExprStatement:
				lw.exprCommands(e.Expr, segCond)
			}
		}
		// pipeline redirections attach to the last stage's output.
		if lastCmd != nil {
			for _, r := range seg.Redirs {
				lw.addRedir(lastCmd, r)
			}
		} else if len(seg.Redirs) > 0 {
			c := &Cmd{Cond: segCond}
			for _, r := range seg.Redirs {
				lw.addRedir(c, r)
			}
			lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: segCond})
		}
		first = false
	}
}

func (lw *psLower) assignment(a *psparse.Assignment, cond bool) {
	// $env:NAME = value updates the running environment (review PS-7).
	if v, ok := a.LHS.(*psparse.Variable); ok && strings.EqualFold(v.Scope, "env") {
		c := &Cmd{Cond: cond, Assigns: []Assign{{Name: v.Name, ValueWord: lw.exprWord(rhsExpr(a.RHS))}}}
		lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond})
		return
	}
	// any command on the RHS still runs.
	lw.statement(a.RHS, cond)
}

func (lw *psLower) command(c *psparse.Command, cond, pipeIn bool) *Cmd {
	out := &Cmd{Cond: cond, PipeIn: pipeIn}
	// program name
	if name, ok := psparse.LiteralString(c.Name); ok && c.InvokeOp != "." {
		out.Words = append(out.Words, Word{Value: name, Static: true, Segs: []WordSeg{{Lit: name}}})
	} else {
		out.Words = append(out.Words, Word{Reason: ReasonDynamicExpansion})
	}
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *psparse.Parameter:
			out.Words = append(out.Words, Word{Value: "-" + e.Name, Static: true, Segs: []WordSeg{{Lit: "-" + e.Name}}})
			if e.HasColon && e.Colon != nil {
				// -Path:a,b,c : a comma list is several operands, never one path.
				out.Words = append(out.Words, lw.argWords(e.Colon)...)
				lw.exprCommands(e.Colon, true)
			}
		case *psparse.Arg:
			// A comma list / @( ) argument is several operands, one per element
			// (each static element its own, a non-static element UNKNOWN); it is
			// never collapsed into one path (psparse delta review 4 (a)).
			out.Words = append(out.Words, lw.argWords(e.Value)...)
			// a script-block / sub-expression argument (& { ... },
			// Invoke-Command -ScriptBlock { ... }) runs its inner commands
			// (review N20 H1/H2).
			lw.exprCommands(e.Value, true)
		case psparse.Expr:
			out.Words = append(out.Words, lw.argWords(e)...)
			lw.exprCommands(e, true)
		}
	}
	// `& { ... }` / `. { ... }`: the command name itself is a script block.
	lw.exprCommands(c.Name, true)
	for _, r := range c.Redirs {
		lw.addRedir(out, r)
	}
	return out
}

func (lw *psLower) addRedir(c *Cmd, r *psparse.Redirection) {
	if r == nil || r.Merge != "" || r.Target == nil {
		return // a stream merge (2>&1) is not a file write
	}
	red := Redir{FD: 1, Target: lw.exprWord(r.Target)}
	switch r.Op {
	case ">", "*>", "1>":
		red.Op = RedirWrite
	case ">>", "*>>", "1>>":
		red.Op = RedirAppend
	case "<":
		red.Op = RedirRead
	default:
		red.Op = RedirWrite
	}
	c.Redirs = append(c.Redirs, red)
}

// argWords lowers a command argument to one or more Words. A comma list
// (ArrayLit a,b,c) or an array sub-expression (@( ... )) becomes one Word per
// element, so the extractor never treats a multi-element argument as a single
// path; a non-literal element stays dynamic (UNKNOWN). A scalar lowers to one
// Word, unchanged (psparse delta review 4 (a)).
func (lw *psLower) argWords(e psparse.Expr) []Word {
	switch v := e.(type) {
	case *psparse.ArrayLit:
		var ws []Word
		for _, el := range v.Elements {
			ws = append(ws, lw.argWords(el)...)
		}
		if len(ws) == 0 {
			return []Word{{Reason: ReasonDynamicExpansion}}
		}
		return ws
	case *psparse.ArrayExpr:
		var ws []Word
		for _, st := range v.Statements {
			if es, ok := st.(*psparse.ExprStatement); ok {
				ws = append(ws, lw.argWords(es.Expr)...)
			} else {
				ws = append(ws, Word{Reason: ReasonDynamicExpansion})
			}
		}
		if len(ws) == 0 {
			return []Word{{Reason: ReasonDynamicExpansion}}
		}
		return ws
	default:
		return []Word{lw.exprWord(e)}
	}
}

// exprWord lowers a PowerShell expression to a Word: a static literal, an
// $env:VAR reference (resolved by the walker against the running env), else a
// dynamic word (review PS-3: a parenthesised/operator expression is dynamic).
func (lw *psLower) exprWord(e psparse.Expr) Word {
	if e == nil {
		return Word{Reason: ReasonDynamicExpansion}
	}
	if v, ok := e.(*psparse.Variable); ok && strings.EqualFold(v.Scope, "env") {
		return Word{Segs: []WordSeg{{Var: v.Name}}}
	}
	if s, ok := psparse.LiteralString(e); ok {
		return Word{Value: s, Static: true, Segs: []WordSeg{{Lit: s}}}
	}
	return Word{Reason: ReasonDynamicExpansion}
}

// exprCommands recurses into an expression for nested commands (script blocks,
// sub-expressions) so their effects are seen.
// exprCommands recurses into the sub-statements of an expression (script
// blocks, sub-expressions, arrays, parens, hashtable values) exactly once, so
// a nested $( ) / & { } is linear, not exponential (review R3-1). It does NOT
// use WalkCommands, which re-walks each command's whole subtree.
func (lw *psLower) exprCommands(e psparse.Expr, cond bool) {
	switch v := e.(type) {
	case nil:
	case *psparse.ScriptBlockExpr:
		lw.statements(v.Statements, true)
	case *psparse.SubExpr:
		lw.statements(v.Statements, true)
	case *psparse.ArrayExpr:
		lw.statements(v.Statements, true)
	case *psparse.Paren:
		lw.statement(v.Inner, true)
	case *psparse.Hashtable:
		for _, val := range v.Values {
			lw.exprCommands(val, cond)
		}
	case *psparse.ArrayLit:
		for _, el := range v.Elements {
			lw.exprCommands(el, cond)
		}
	case *psparse.Index:
		lw.exprCommands(v.Target, cond)
		lw.exprCommands(v.Index, cond)
	case *psparse.Member:
		lw.exprCommands(v.Target, cond)
	case *psparse.Invoke:
		lw.exprCommands(v.Target, cond)
		for _, a := range v.Args {
			lw.exprCommands(a, cond)
		}
	case *psparse.Binary:
		lw.exprCommands(v.LHS, cond)
		lw.exprCommands(v.RHS, cond)
	case *psparse.Unary:
		lw.exprCommands(v.Operand, cond)
	case *psparse.Convert:
		lw.exprCommands(v.Operand, cond)
	case *psparse.StringLit:
		for _, pt := range v.Parts {
			lw.exprCommands(pt.Expr, cond)
		}
	}
}

func rhsExpr(st psparse.Statement) psparse.Expr {
	switch v := st.(type) {
	case *psparse.ExprStatement:
		return v.Expr
	case *psparse.Pipeline:
		if len(v.Elements) == 1 {
			if es, ok := v.Elements[0].(*psparse.ExprStatement); ok {
				return es.Expr
			}
		}
	}
	return nil
}
