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
// silence.
func parsePOSIX(command string, o Options) *Script {
	s := &Script{Dialect: DialectPOSIX}
	file, ok := shellparse.Parse(command)
	if !ok || file == nil {
		s.Unknowns = append(s.Unknowns, UnknownNode{Reason: ReasonInvalidSyntax})
		return s
	}
	w := &posixWalker{out: s, env: o.Env}
	for _, st := range file.Stmts {
		w.stmt(st, false, false)
	}
	return s
}

type posixWalker struct {
	out *Script
	env map[string]string
}

func (w *posixWalker) unknown(reason ReasonCode, node syntax.Node) {
	var span [2]int
	if node != nil {
		span = [2]int{int(node.Pos().Offset()), int(node.End().Offset())}
	}
	w.out.Unknowns = append(w.out.Unknowns, UnknownNode{Reason: reason, Span: span})
}

// stmt lowers one statement. cond carries conditional context; pipeIn marks a
// pipeline-fed stage.
func (w *posixWalker) stmt(st *syntax.Stmt, cond, pipeIn bool) {
	if st == nil {
		return
	}
	cond = cond || st.Negated
	switch cmd := st.Cmd.(type) {
	case nil:
		// A redirect-only statement (e.g. `> file`): still a write effect.
		w.emitCall(st, nil, cond, pipeIn)
	case *syntax.CallExpr:
		w.emitCall(st, cmd, cond, pipeIn)
	case *syntax.BinaryCmd:
		w.binary(st, cmd, cond)
	case *syntax.Block:
		for _, inner := range cmd.Stmts {
			w.stmt(inner, cond, false)
		}
	case *syntax.Subshell:
		for _, inner := range cmd.Stmts {
			w.stmt(inner, cond, false)
		}
	case *syntax.IfClause:
		w.ifClause(cmd, cond)
	case *syntax.WhileClause:
		for _, inner := range cmd.Cond {
			w.stmt(inner, cond, false)
		}
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
	case *syntax.ForClause:
		for _, inner := range cmd.Do {
			w.stmt(inner, true, false)
		}
	case *syntax.CaseClause:
		for _, item := range cmd.Items {
			for _, inner := range item.Stmts {
				w.stmt(inner, true, false)
			}
		}
	case *syntax.FuncDecl:
		// A function body: its commands run only where the function is called.
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
		// ArithmCmd, LetClause, TestClause, CoprocClause and anything else are
		// outside the modeled set.
		w.unknown(ReasonUnparsedConstruct, st.Cmd)
	}
}

func (w *posixWalker) binary(st *syntax.Stmt, cmd *syntax.BinaryCmd, cond bool) {
	switch cmd.Op {
	case syntax.AndStmt: // &&
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, true, false) // Y runs only if X succeeded
	case syntax.OrStmt: // ||
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, true, false)
	case syntax.Pipe, syntax.PipeAll: // | |&
		w.stmt(cmd.X, cond, false)
		w.stmt(cmd.Y, cond, true) // Y's stdin is X's stdout
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
			v, static, _, _, reason := w.word(a.Value)
			as.Value, as.Static, as.Reason = v, static, reason
		} else {
			as.Static = true
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
				v, static, _, _, reason := w.word(a.Value)
				as.Value, as.Static, as.Reason = v, static, reason
			} else {
				as.Static = true
			}
			c.Assigns = append(c.Assigns, as)
		}
		for _, arg := range call.Args {
			v, static, quoted, glob, reason := w.word(arg)
			word := Word{Value: v, Static: static, Quoted: quoted, Glob: glob, Reason: reason, Span: span(arg)}
			c.Words = append(c.Words, word)
			w.nested(arg, c)
		}
	}
	w.redirs(st, c)
	w.out.Stmts = append(w.out.Stmts, &Stmt{Cmds: []*Cmd{c}, Cond: cond, Background: st.Background, Span: span(st)})
}

// nested walks command substitutions inside a word so their commands are seen.
func (w *posixWalker) nested(arg *syntax.Word, c *Cmd) {
	for _, part := range arg.Parts {
		if cs, ok := part.(*syntax.CmdSubst); ok {
			sub := &Script{Dialect: DialectPOSIX}
			nw := &posixWalker{out: sub, env: w.env}
			for _, inner := range cs.Stmts {
				nw.stmt(inner, true, false)
			}
			c.Nested = append(c.Nested, sub)
		}
	}
}

func (w *posixWalker) redirs(st *syntax.Stmt, c *Cmd) {
	for _, r := range st.Redirs {
		if r == nil {
			continue
		}
		red := Redir{}
		if r.N != nil {
			if n, ok := atoiSafe(r.N.Value); ok {
				red.FD = n
			}
		}
		switch r.Op {
		case syntax.RdrOut:
			red.Op = RedirWrite
		case syntax.AppOut:
			red.Op = RedirAppend
		case syntax.RdrIn:
			red.Op = RedirRead
		case syntax.Hdoc, syntax.DashHdoc:
			red.Op = RedirHeredoc
		case syntax.WordHdoc:
			red.Op = RedirHereString
		case syntax.ClbOut:
			red.Op = RedirClobber
		case syntax.DplOut, syntax.DplIn:
			red.Op = RedirDup
		case syntax.RdrAll, syntax.AppAll:
			red.Op = RedirWrite
		default:
			red.Op = RedirWrite
		}
		if r.Word != nil {
			v, static, quoted, glob, reason := w.word(r.Word)
			red.Target = Word{Value: v, Static: static, Quoted: quoted, Glob: glob, Reason: reason, Span: span(r.Word)}
		}
		if r.Hdoc != nil {
			body, bexp := heredocBody(r.Hdoc)
			red.Body, red.BodyExpands = body, bexp
		}
		c.Redirs = append(c.Redirs, red)
	}
}

// word projects one mvdan word into (value, static, quoted, glob, reason). A
// ParamExp whose name is a known Env value resolves statically.
func (w *posixWalker) word(word *syntax.Word) (string, bool, bool, bool, ReasonCode) {
	// returns value, static(bool), quoted(bool), glob as ReasonCode-sentinel? --
	// simplify: glob encoded as reason too. We return glob via reason==glob.
	if word == nil {
		return "", false, false, false, ReasonDynamicExpansion
	}
	var b strings.Builder
	static := true
	quoted := false
	unquoted := false
	glob := false
	var reason ReasonCode
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			unquoted = true
			b.WriteString(unescapePOSIX(p.Value))
			if looksGlob(p.Value) {
				glob = true
			}
		case *syntax.SglQuoted:
			quoted = true
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			quoted = true
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					b.WriteString(unescapePOSIX(ip.Value))
				case *syntax.ParamExp:
					if v, ok := w.lookupParam(ip); ok {
						b.WriteString(v)
					} else {
						static = false
						reason = ReasonDynamicExpansion
					}
				default:
					static = false
					reason = ReasonDynamicExpansion
				}
			}
		case *syntax.ParamExp:
			if v, ok := w.lookupParam(p); ok {
				b.WriteString(v)
				unquoted = true
			} else {
				static = false
				reason = ReasonDynamicExpansion
			}
		case *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ExtGlob:
			static = false
			reason = ReasonDynamicExpansion
		case *syntax.ProcSubst:
			static = false
			reason = ReasonUnparsedConstruct
		default:
			static = false
			reason = ReasonDynamicExpansion
		}
	}
	_ = unquoted
	if !static {
		return "", false, quoted, false, reason
	}
	// Tilde is only an expansion when unquoted at the start (handled in placePath
	// via Home); a quoted tilde is literal.
	if glob && !quoted {
		return b.String(), true, quoted, true, ""
	}
	return b.String(), true, quoted, false, ""
}

// lookupParam resolves ${VAR} / $VAR against the trusted Env; a plain name with
// no modifier only.
func (w *posixWalker) lookupParam(p *syntax.ParamExp) (string, bool) {
	if p == nil || p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil ||
		p.Slice != nil || p.Repl != nil || p.Exp != nil || p.Names != 0 {
		return "", false
	}
	if w.env == nil {
		return "", false
	}
	v, ok := w.env[p.Param.Value]
	return v, ok
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

func unescapePOSIX(s string) string {
	// mvdan keeps backslash escapes in Lit; a minimal unescape for the common
	// cases so a quoted filename is the real name.
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func atoiSafe(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
