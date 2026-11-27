// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// ArgumentCommandReading puts commands evaluated in argument expressions
// before their containing statement. The argument value becomes an inert
// number: this is an additional reading for positive proofs, never a
// replacement for the original reading. Uninvoked script blocks stay data.
func ArgumentCommandReading(source string) (string, bool, bounded.CapSet) {
	text, changed, _, cut := ArgumentCommandReadingWithGroup(source)
	return text, changed, cut
}

// ArgumentCommandReadingWithGroup also reports an evaluated (group) block.
// Such a group must receive the rule reading of its command, since the outer
// statement's parser does not dispatch the header's inner command.
func ArgumentCommandReadingWithGroup(source string) (string, bool, bool, bounded.CapSet) {
	var trunc bounded.Truncated
	if !trunc.Within(bounded.Bytes, len(source), 64<<10) {
		return "", false, false, trunc.Set()
	}
	r := argumentReader{trunc: &trunc, nodes: bounded.NewCounter(&trunc, bounded.Nodes, 8192)}
	sc, _ := Parse(source, Options{Dialect: DialectUnknown})
	for _, d := range sc.Diagnostics {
		if d.Reason == ReasonDepthLimit {
			trunc.Hit(bounded.Depth)
		}
		if d.Reason == ReasonTruncated {
			trunc.Hit(bounded.Bytes)
		}
	}
	parts := r.statements(sc.Statements, source, 0)
	text := strings.Join(parts, "\n")
	if !trunc.Within(bounded.Bytes, len(text), 128<<10) {
		return "", false, false, trunc.Set()
	}
	return text, r.changed, r.group, trunc.Set()
}

type argumentReader struct {
	trunc   *bounded.Truncated
	nodes   bounded.Counter
	changed bool
	group   bool
}
type argumentEdit struct {
	start, end int
	text       string
}

func (r *argumentReader) enter(depth int) bool {
	return r.trunc.Within(bounded.Depth, depth, 64) && r.nodes.Take()
}
func (r *argumentReader) statements(sts []Statement, src string, depth int) []string {
	var out []string
	for _, s := range sts {
		out = append(out, r.statement(s, src, depth+1)...)
	}
	return out
}
func (r *argumentReader) statement(s Statement, src string, depth int) []string {
	if s == nil || !r.enter(depth) {
		return nil
	}
	start, end := s.Span()
	if start < 0 || end > len(src) || start >= end {
		return nil
	}
	var before []string
	var edits []argumentEdit
	command := func(c *Command) {
		// A block invoked by & or dot runs now; a block passed as data does not.
		if block, ok := c.Name.(*ScriptBlockExpr); ok && c.InvokeOp != "" {
			parts := r.statements(block.Statements, src, depth+1)
			a, b := c.Span()
			_, bodyEnd := c.Name.Span()
			text := strings.Join(parts, "\n")
			if bodyEnd >= a && bodyEnd <= b && b <= len(src) {
				text += src[bodyEnd:b]
			}
			edits = append(edits, argumentEdit{a, b, text})
			return
		}
		for _, el := range c.Elements {
			var expr Expr
			var node Node = el
			switch v := el.(type) {
			case *Arg:
				expr = v.Value
			case *Parameter:
				expr = v.Colon
				node = v.Colon
			case Expr:
				expr = v
			}
			inner := r.expression(expr, src, depth+1)
			if len(inner) == 0 || node == nil {
				continue
			}
			a, b := node.Span()
			if a < start || b > end || a >= b {
				continue
			}
			before = append(before, inner...)
			edits = append(edits, argumentEdit{a, b, "0"})
			r.changed = true
		}
	}
	switch v := s.(type) {
	case *Command:
		command(v)
	case *Pipeline:
		for p := v; p != nil; p = p.ChainRHS {
			for _, el := range p.Elements {
				switch e := el.(type) {
				case *Command:
					command(e)
				case *ExprStatement:
					inner := r.expression(e.Expr, src, depth+1)
					if len(inner) != 0 {
						a, b := e.Span()
						before = append(before, inner...)
						edits = append(edits, argumentEdit{a, b, "0"})
						r.changed = true
					}
				}
			}
		}
	case *Block:
		// A loop runs its header and its body where it stands: the loop is
		// read as those statements written in its place (one pass stands for
		// every pass), so each is judged as the same statement sent alone
		// (rel-1-0-10:GAP-0998); the loop keyword itself left the whole
		// reading unread. Other blocks (function, trap, data, param, switch,
		// try) define code or run it on a condition the walk already reads.
		switch strings.ToLower(v.Keyword) {
		case "foreach", "for", "while", "do":
			loop := r.evaluations(v.Conditions, src, depth+1)
			for _, body := range v.Bodies {
				if body != nil {
					loop = append(loop, r.statements(body.Statements, src, depth+1)...)
				}
			}
			if len(loop) != 0 {
				r.changed = true
				return loop
			}
		}
	case *Assignment:
		// Keep assignment semantics; only its argument evaluations move earlier.
		nested := r.statement(v.RHS, src, depth+1)
		if len(nested) > 0 {
			before = append(before, nested[:len(nested)-1]...)
			a, b := v.RHS.Span()
			edits = append(edits, argumentEdit{a, b, nested[len(nested)-1]})
		}
	}
	slices.SortFunc(edits, func(a, b argumentEdit) int { return b.start - a.start })
	text := src[start:end]
	for _, e := range edits {
		if e.start < start || e.end > end || e.start > e.end {
			continue
		}
		text = text[:e.start-start] + e.text + text[e.end-start:]
	}
	return append(before, text)
}
func (r *argumentReader) expression(e Expr, src string, depth int) []string {
	if e == nil || !r.enter(depth) {
		return nil
	}
	switch v := e.(type) {
	case *scriptExprWrap:
		return r.statement(v.cmd, src, depth+1)
	case *Paren:
		return r.evaluations([]Statement{v.Inner}, src, depth+1)
	case *SubExpr:
		return r.evaluations(v.Statements, src, depth+1)
	case *ArrayExpr:
		return r.evaluations(v.Statements, src, depth+1)
	case *StringLit:
		// Embedded string expressions have spans local to their own source.
		// Reuse the parser's scanner rather than applying them to the outer text.
		if v.Static || (v.Kind != StrDouble && v.Kind != StrHereDouble) {
			return nil
		}
		body := v.Raw
		if v.Kind == StrDouble {
			body = collapseDoubled(trimRuneDelims(body), isDoubleQuote)
		}
		if v.Kind == StrHereDouble {
			body = hereBody(body)
		}
		rs := []rune(body)
		var out []string
		for i := 0; i < len(rs); i++ {
			if rs[i] == '`' {
				i++
				continue
			}
			if rs[i] != '$' || i+1 >= len(rs) || rs[i+1] != '(' {
				continue
			}
			inner, used := scanParenBody(rs[i+2:])
			sc, _ := Parse(inner, Options{Dialect: DialectUnknown})
			out = append(out, r.evaluations(sc.Statements, inner, depth+1)...)
			i += 1 + used
		}
		return out
	case *ArrayLit:
		var out []string
		for _, a := range v.Elements {
			out = append(out, r.expression(a, src, depth+1)...)
		}
		return out
	case *Hashtable:
		var out []string
		for _, a := range v.Keys {
			out = append(out, r.expression(a, src, depth+1)...)
		}
		for _, a := range v.Values {
			out = append(out, r.expression(a, src, depth+1)...)
		}
		return out
	case *Unary:
		return r.expression(v.Operand, src, depth+1)
	case *Convert:
		return r.expression(v.Operand, src, depth+1)
	case *Binary:
		return append(r.expression(v.LHS, src, depth+1), r.expression(v.RHS, src, depth+1)...)
	case *Member:
		return r.expression(v.Target, src, depth+1)
	case *Invoke:
		out := r.expression(v.Target, src, depth+1)
		for _, a := range v.Args {
			out = append(out, r.expression(a, src, depth+1)...)
		}
		return out
	case *Index:
		return append(r.expression(v.Target, src, depth+1), r.expression(v.Index, src, depth+1)...)
	}
	return nil
}

// evaluations excludes values and uninvoked block literals: only statements
// with a command that runs now belong before the containing call.
func (r *argumentReader) evaluations(sts []Statement, src string, depth int) []string {
	var out []string
	for _, s := range sts {
		switch v := s.(type) {
		case *Command:
			out = append(out, r.statement(s, src, depth+1)...)
		case *Pipeline:
			hasCommand := false
			for p := v; p != nil; p = p.ChainRHS {
				for _, el := range p.Elements {
					if _, ok := el.(*Command); ok {
						hasCommand = true
					}
				}
			}
			if hasCommand {
				out = append(out, r.statement(s, src, depth+1)...)
			} else {
				for _, el := range v.Elements {
					if expr, ok := el.(*ExprStatement); ok {
						out = append(out, r.expression(expr.Expr, src, depth+1)...)
					}
				}
			}
		case *ExprStatement:
			out = append(out, r.expression(v.Expr, src, depth+1)...)
		case *Block:
			// Parenthesized header statements can parse as a (group) block
			// when the header has more than one statement (foreach $x in
			// (command)). Those statements run as part of the header; only
			// this evaluated group is descended into, not block literals.
			if v.Keyword == "(group)" {
				for _, body := range v.Bodies {
					if body != nil {
						parts := r.evaluations(body.Statements, src, depth+1)
						r.group = r.group || len(parts) != 0
						out = append(out, parts...)
					}
				}
			}
		case *Assignment:
			out = append(out, r.evaluations([]Statement{v.RHS}, src, depth+1)...)
		}
	}
	return out
}
