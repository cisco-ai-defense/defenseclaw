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
	sc, err := psparse.Parse(command, psparse.Options{})
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
		for _, ns := range psparse.ExtractNestedScripts(sc) {
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
			for _, fn := range inner.Funcs {
				s.Funcs = append(s.Funcs, fn)
			}
			s.Stmts = append(s.Stmts, inner.Stmts...)
			s.Unknowns = append(s.Unknowns, inner.Unknowns...)
		}
	}
	return s
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
		stage := 0
		for _, el := range seg.Elements {
			switch e := el.(type) {
			case *psparse.Command:
				c := lw.command(e, segCond, stage > 0)
				lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: segCond})
				lastCmd = c
				stage++
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
				out.Words = append(out.Words, lw.exprWord(e.Colon))
			}
		case *psparse.Arg:
			out.Words = append(out.Words, lw.exprWord(e.Value))
		case psparse.Expr:
			out.Words = append(out.Words, lw.exprWord(e))
		}
	}
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
func (lw *psLower) exprCommands(e psparse.Expr, cond bool) {
	psparse.WalkCommands(&psparse.Script{Statements: []psparse.Statement{&psparse.ExprStatement{Expr: e}}}, func(c *psparse.Command) {
		cmd := lw.command(c, true, false)
		lw.out.Stmts = append(lw.out.Stmts, &Stmt{Cmds: []*Cmd{cmd}, Cond: true})
	})
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
