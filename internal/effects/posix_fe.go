// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// parsePOSIX lowers a POSIX/bash command string into the neutral IR using the
// shared bounded parser (mvdan via shellparse). Any construct outside the
// allowlist becomes an UnknownNode with a reason, never a crash and never
// silence. Variable expansion is left to the walker (as word segments) so
// in-call assignments take effect (review PX-2).
func parsePOSIX(command string, o Options) *Script {
	s := &Script{Dialect: DialectPOSIX}
	file, ok := shellparse.Parse(command)
	if !ok || file == nil {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonInvalidSyntax})
		return s
	}
	w := &posixWalker{out: s}
	for _, st := range file.Stmts {
		w.stmt(st, false, false)
	}
	return s
}

type posixWalker struct{ out *Script }

func (w *posixWalker) unknown(reason ReasonCode, node syntax.Node) {
	w.out.Unknowns = append(w.out.Unknowns, UnknownNode{Reason: reason, Span: span(node)})
}

func (w *posixWalker) stmt(st *syntax.Stmt, cond, pipeIn bool) {
	if st == nil {
		return
	}
	cond = cond || st.Negated
	switch cmd := st.Cmd.(type) {
	case nil:
		w.emitCall(st, nil, cond, pipeIn)
	case *syntax.CallExpr:
		w.emitCall(st, cmd, cond, pipeIn)
	case *syntax.BinaryCmd:
		w.binary(st, cmd, cond)
	case *syntax.Block:
		for _, inner := range cmd.Stmts {
			w.stmt(inner, cond, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.Subshell:
		// A subshell runs in a child; cd inside it does not escape. Lower it to
		// one Cmd carrying a nested script so the walker can scope cwd/env.
		sub := &Script{Dialect: DialectPOSIX}
		nw := &posixWalker{out: sub}
		for _, inner := range cmd.Stmts {
			nw.stmt(inner, cond, false)
		}
		c := &Cmd{Sub: sub, Cond: cond, Span: span(st)}
		w.redirs(st, c)
		w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond, Span: span(st)})
	case *syntax.IfClause:
		w.ifClause(cmd, cond)
		w.compoundRedirs(st, cond)
	case *syntax.WhileClause:
		for _, inner := range cmd.Cond {
			w.stmt(inner, cond, false)
		}
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.ForClause:
		if cmd.Loop != nil {
			if wl, ok := cmd.Loop.(*syntax.WordIter); ok {
				for _, word := range wl.Items {
					tmp := &Cmd{}
					w.scanCmdSubsts(word, tmp)
					for _, sub := range tmp.Nested {
						w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{{Sub: sub, Cond: true}}, Cond: true})
					}
				}
			}
		}
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
		w.compoundRedirs(st, cond)
	case *syntax.CaseClause:
		for _, item := range cmd.Items {
			for _, inner := range item.Stmts {
				w.stmt(inner, true, false)
			}
		}
		w.compoundRedirs(st, cond)
	case *syntax.FuncDecl:
		if cmd.Name != nil {
			w.out.Funcs = append(w.out.Funcs, cmd.Name.Value)
		}
		if cmd.Body != nil {
			w.stmt(cmd.Body, true, false)
		}
	case *syntax.DeclClause:
		w.declClause(st, cmd, cond, pipeIn)
	case *syntax.TimeClause:
		if cmd.Stmt != nil {
			w.stmt(cmd.Stmt, cond, pipeIn)
		}
	default:
		w.unknown(ReasonUnparsedConstruct, st.Cmd)
	}
}

// compoundRedirs applies redirections attached to a compound statement
// (block/subshell/loop/if/case) as a redirect-only command (review PX-4).
func (w *posixWalker) compoundRedirs(st *syntax.Stmt, cond bool) {
	if len(st.Redirs) == 0 {
		return
	}
	c := &Cmd{Cond: cond, Span: span(st)}
	w.redirs(st, c)
	if len(c.Redirs) > 0 {
		w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond, Span: span(st)})
	}
}

func (w *posixWalker) binary(st *syntax.Stmt, cmd *syntax.BinaryCmd, cond bool) {
	switch cmd.Op {
	case syntax.AndStmt:
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, true, false)
	case syntax.OrStmt:
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, true, false)
	case syntax.Pipe, syntax.PipeAll:
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, cond, true)
	default:
		w.unknown(ReasonUnparsedConstruct, cmd)
	}
}

func (w *posixWalker) ifClause(cmd *syntax.IfClause, cond bool) {
	for _, inner := range cmd.Cond {
		w.stmt(inner, cond, false)
	}
	for _, inner := range cmd.Then {
		w.stmt(inner, true, false)
	}
	if cmd.Else != nil {
		w.ifClause(cmd.Else, cond)
	}
}

func (w *posixWalker) declClause(st *syntax.Stmt, cmd *syntax.DeclClause, cond, pipeIn bool) {
	c := &Cmd{Cond: cond, PipeIn: pipeIn, Span: span(cmd)}
	exported := cmd.Variant != nil && (cmd.Variant.Value == "export" || cmd.Variant.Value == "declare")
	for _, a := range cmd.Args {
		if a.Name == nil {
			continue
		}
		as := Assign{Name: a.Name.Value, Exported: exported}
		if a.Value != nil {
			as.ValueWord = w.word(a.Value)
			w.scanCmdSubsts(a.Value, c)
		} else {
			as.ValueWord = Word{Static: true}
		}
		c.Assigns = append(c.Assigns, as)
	}
	w.redirs(st, c)
	w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond, Span: span(cmd)})
}

func (w *posixWalker) emitCall(st *syntax.Stmt, call *syntax.CallExpr, cond, pipeIn bool) {
	c := &Cmd{Cond: cond, PipeIn: pipeIn, Span: span(st)}
	if call != nil {
		for _, a := range call.Assigns {
			if a.Name == nil {
				continue
			}
			as := Assign{Name: a.Name.Value}
			if a.Value != nil {
				as.ValueWord = w.word(a.Value)
				w.scanCmdSubsts(a.Value, c)
			} else {
				as.ValueWord = Word{Static: true}
			}
			c.Assigns = append(c.Assigns, as)
		}
		for _, arg := range call.Args {
			c.Words = append(c.Words, w.word(arg))
			w.scanCmdSubsts(arg, c)
		}
	}
	w.redirs(st, c)
	w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond, Background: st.Background, Span: span(st)})
}

// scanCmdSubsts recursively collects every command substitution anywhere in a
// word (including inside double quotes) as a nested script (review PX-3).
func (w *posixWalker) scanCmdSubsts(word *syntax.Word, c *Cmd) {
	if word == nil {
		return
	}
	syntax.Walk(word, func(n syntax.Node) bool {
		if cs, ok := n.(*syntax.CmdSubst); ok {
			sub := &Script{Dialect: DialectPOSIX}
			nw := &posixWalker{out: sub}
			for _, inner := range cs.Stmts {
				nw.stmt(inner, true, false)
			}
			c.Nested = append(c.Nested, sub)
		}
		return true
	})
}

func (w *posixWalker) redirs(st *syntax.Stmt, c *Cmd) {
	for _, r := range st.Redirs {
		if r == nil {
			continue
		}
		red := Redir{FD: -1}
		if r.N != nil {
			if n, ok := atoiSafe(r.N.Value); ok {
				red.FD = n
			}
		}
		switch r.Op {
		case syntax.RdrOut:
			red.Op = RedirWrite
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.AppOut:
			red.Op = RedirAppend
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.RdrIn:
			red.Op = RedirRead
		case syntax.Hdoc, syntax.DashHdoc:
			red.Op = RedirHeredoc
		case syntax.WordHdoc:
			red.Op = RedirHereString
		case syntax.ClbOut:
			red.Op = RedirClobber
			if red.FD < 0 {
				red.FD = 1
			}
		case syntax.DplOut, syntax.DplIn:
			red.Op = RedirDup
		case syntax.RdrAll, syntax.AppAll:
			red.Op = RedirWrite
			red.FD = 1
		default:
			red.Op = RedirWrite
		}
		if r.Word != nil {
			red.Target = w.word(r.Word)
			w.scanCmdSubsts(r.Word, c)
		}
		if r.Hdoc != nil {
			red.Body, red.BodyExpands = heredocBody(r.Hdoc)
		}
		c.Redirs = append(c.Redirs, red)
	}
}

// word builds the neutral Word. A word of only literals and simple $VAR / ${VAR}
// expansions gets Segs for the walker to resolve; anything with a command
// substitution, arithmetic, process substitution or a complex parameter op is
// dynamic (no Segs, a Reason).
func (w *posixWalker) word(word *syntax.Word) Word {
	if word == nil {
		return Word{Reason: ReasonDynamicExpansion}
	}
	out := Word{Span: span(word)}
	var segs []WordSeg
	addLit := func(s string, quoted bool) { segs = append(segs, WordSeg{Lit: s, Quoted: quoted}) }
	dynamic := func(reason ReasonCode) {
		out.Static = false
		out.Segs = nil
		out.Reason = reason
	}
	for _, part := range word.Parts {
		if out.Reason != "" {
			break
		}
		switch p := part.(type) {
		case *syntax.Lit:
			// An escaped metachar (\*) is a literal, not a glob: mark the
			// segment quoted so resolveWord does not treat it as a pattern
			// (review PX-6, Q5).
			addLit(unescapePOSIX(p.Value, false), escapedMetaOnly(p.Value))
		case *syntax.SglQuoted:
			addLit(p.Value, true)
			out.Quoted = true
		case *syntax.DblQuoted:
			out.Quoted = true
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					addLit(unescapePOSIX(ip.Value, true), true)
				case *syntax.ParamExp:
					if name, ok := simpleParam(ip); ok {
						segs = append(segs, WordSeg{Var: name, Quoted: true})
					} else {
						dynamic(ReasonDynamicExpansion)
					}
				default:
					dynamic(ReasonDynamicExpansion)
				}
			}
		case *syntax.ParamExp:
			if name, ok := simpleParam(p); ok {
				segs = append(segs, WordSeg{Var: name})
			} else {
				dynamic(ReasonDynamicExpansion)
			}
		case *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ExtGlob:
			dynamic(ReasonDynamicExpansion)
		case *syntax.ProcSubst:
			dynamic(ReasonUnparsedConstruct)
		default:
			dynamic(ReasonDynamicExpansion)
		}
	}
	if out.Reason != "" {
		return out
	}
	out.Segs = segs
	// A word is fully static (Value set) only when it has no variable segment.
	hasVar := false
	var b strings.Builder
	for _, s := range segs {
		if s.Var != "" {
			hasVar = true
			break
		}
		b.WriteString(s.Lit)
	}
	if !hasVar {
		out.Static = true
		out.Value = b.String()
	}
	return out
}

// simpleParam returns the variable name for a plain $NAME / ${NAME} with no
// modifier, index, slice, replacement or length operator.
func simpleParam(p *syntax.ParamExp) (string, bool) {
	if p == nil || p.Param == nil || p.Excl || p.Length || p.Width ||
		p.Index != nil || p.Slice != nil || p.Repl != nil || p.Exp != nil || p.Names != 0 {
		return "", false
	}
	return p.Param.Value, true
}

func span(n syntax.Node) [2]int {
	if n == nil {
		return [2]int{}
	}
	return [2]int{int(n.Pos().Offset()), int(n.End().Offset())}
}

func heredocBody(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	expands := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		default:
			expands = true
		}
	}
	return b.String(), expands
}

// unescapePOSIX removes shell backslash escapes. Inside double quotes only a
// few characters are escapable, so a backslash before any other byte is literal
// (review PX-8b: `"/tmp/a\b"` keeps the backslash).
func unescapePOSIX(s string, inDoubleQuote bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			nxt := s[i+1]
			if inDoubleQuote && nxt != '"' && nxt != '\\' && nxt != '$' && nxt != '`' {
				b.WriteByte('\\')
				continue
			}
			i++
			b.WriteByte(nxt)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// escapedMetaOnly reports that a raw literal contains a backslash-escaped glob
// metacharacter and no unescaped one, so after unescaping it is a literal name.
func escapedMetaOnly(raw string) bool {
	escaped, unescaped := false, false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			if strings.IndexByte("*?[{", raw[i+1]) >= 0 {
				escaped = true
			}
			i++
			continue
		}
		if strings.IndexByte("*?[", raw[i]) >= 0 {
			unescaped = true
		}
	}
	return escaped && !unescaped
}
