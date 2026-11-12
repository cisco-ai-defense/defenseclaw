// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// Invocation is the normalized projection of a single command invocation,
// shaped so it can be compared one-to-one with the projection produced from
// the reference parser (System.Management.Automation.Language). It captures
// the command/argument structure the effects lane relies on and nothing
// cosmetic.
type Invocation struct {
	Op     string   `json:"op"`     // "", "&", "."
	Name   string   `json:"name"`   // resolved literal name (lower-case) when NameKind=="lit"
	NK     string   `json:"nk"`     // name kind: lit|expand|var|expr|dynamic|none
	Params []string `json:"params"` // "-name" or "-name:" (colon form), lower-case
	Args   []string `json:"args"`   // argument kind tags (see argKind)
	Redirs []string `json:"redirs"` // redirection operator texts
	Stop   bool     `json:"stop"`   // a --% stop-parsing token was present
}

// Project walks the AST in source order and returns every command invocation
// as an Invocation, recursing into script blocks, sub-expressions, arrays,
// parentheses, hashtable values, control-flow bodies and expression arguments
// — the same set of CommandAst nodes the reference parser's FindAll exposes.
func Project(sc *Script) []Invocation {
	w := &projector{}
	w.walkStatements(sc.Statements)
	return w.out
}

type projector struct {
	out []Invocation
}

func (w *projector) walkStatements(sts []Statement) {
	for _, s := range sts {
		w.walkStatement(s)
	}
}

func (w *projector) walkStatement(s Statement) {
	switch v := s.(type) {
	case nil:
	case *Pipeline:
		w.walkPipeline(v)
	case *Assignment:
		w.walkExpr(v.LHS)
		w.walkStatement(v.RHS)
	case *Block:
		w.walkStatements(v.Conditions)
		for _, b := range v.Bodies {
			if b != nil {
				w.walkStatements(b.Statements)
			}
		}
	case *Command:
		w.emitCommand(v)
	case *ExprStatement:
		w.walkExpr(v.Expr)
	case *UnknownStatement:
	}
}

func (w *projector) walkPipeline(p *Pipeline) {
	for p != nil {
		for _, el := range p.Elements {
			switch e := el.(type) {
			case *Command:
				w.emitCommand(e)
			case *ExprStatement:
				w.walkExpr(e.Expr)
			case *UnknownStatement:
			}
		}
		p = p.ChainRHS
	}
}

func (w *projector) emitCommand(c *Command) {
	inv := Invocation{Op: c.InvokeOp, Stop: c.StopParsing != ""}
	inv.Name, inv.NK = nameProjection(c.Name)
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *Parameter:
			pm := "-" + strings.ToLower(e.Name)
			if e.HasColon {
				pm += ":"
			}
			inv.Params = append(inv.Params, pm)
			if e.Colon != nil {
				// the -Name:value argument stays attached to the parameter,
				// matching CommandParameterAst.Argument on the reference side.
			}
		case *Arg:
			inv.Args = append(inv.Args, argKind(e.Value))
		case *StringLit:
			inv.Args = append(inv.Args, argKind(e))
		case *Variable:
			inv.Args = append(inv.Args, argKind(e))
		case *ErrorExpr:
			inv.Args = append(inv.Args, "other")
		default:
			inv.Args = append(inv.Args, "other")
		}
	}
	for _, r := range c.Redirs {
		inv.Redirs = append(inv.Redirs, r.Op)
	}
	w.out = append(w.out, inv)
	// recurse into argument expressions and the command name so nested
	// commands (script blocks, $(), @(), casts) are projected too.
	w.walkExpr(c.Name)
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *Parameter:
			w.walkExpr(e.Colon)
		case *Arg:
			w.walkExpr(e.Value)
		case Expr:
			w.walkExpr(e)
		}
	}
	for _, r := range c.Redirs {
		w.walkExpr(r.Target)
	}
}

func nameProjection(e Expr) (string, string) {
	switch v := e.(type) {
	case nil:
		return "", "none"
	case *StringLit:
		if v.Static {
			return strings.ToLower(v.Value), "lit"
		}
		if v.Kind == StrDouble || v.Kind == StrHereDouble {
			return "", "expand"
		}
		return "", "expr"
	case *Variable:
		return "", "var"
	case *ErrorExpr:
		return "", "dynamic"
	}
	return "", "expr"
}

// argKind classifies an expression used as a command argument, matching the
// reference parser's AST node kinds.
func argKind(e Expr) string {
	switch v := e.(type) {
	case nil:
		return "other"
	case *StringLit:
		switch v.Kind {
		case StrSingle, StrHereSingle:
			return "str"
		case StrDouble, StrHereDouble:
			if v.Static {
				return "str"
			}
			return "expand"
		case StrBare:
			// a bareword containing an unescaped $ is an expandable string on
			// the reference side.
			if hasUnescapedDollar(v.Value) {
				return "expand"
			}
			return "str"
		}
		return "str"
	case *Variable:
		if v.Splat {
			return "splat"
		}
		return "var"
	case *Number:
		return "num"
	case *ScriptBlockExpr:
		return "sb"
	case *SubExpr:
		return "sub"
	case *ArrayExpr:
		return "arr"
	case *ArrayLit:
		return "arrlit"
	case *Hashtable:
		return "hash"
	case *Paren:
		return "paren"
	case *Member, *Invoke:
		return "member"
	case *Index:
		return "index"
	case *TypeExpr, *Convert:
		return "type"
	case *Binary, *Unary:
		return "op"
	case *scriptExprWrap:
		return "member"
	}
	return "other"
}

func hasUnescapedDollar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			i++
			continue
		}
		if s[i] == '$' && i+1 < len(s) {
			n := s[i+1]
			if n == '(' || n == '{' || n == '_' || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') {
				return true
			}
		}
	}
	return false
}

// walkExpr recurses into an expression, projecting any commands nested inside
// script blocks, sub-expressions, arrays, parens, casts, member calls, etc.
func (w *projector) walkExpr(e Expr) {
	switch v := e.(type) {
	case nil:
	case *ScriptBlockExpr:
		w.walkStatements(v.Statements)
	case *SubExpr:
		w.walkStatements(v.Statements)
	case *ArrayExpr:
		w.walkStatements(v.Statements)
	case *ArrayLit:
		for _, el := range v.Elements {
			w.walkExpr(el)
		}
	case *Hashtable:
		for _, val := range v.Values {
			w.walkExpr(val)
		}
	case *Paren:
		w.walkStatement(v.Inner)
	case *Member:
		w.walkExpr(v.Target)
	case *Invoke:
		w.walkExpr(v.Target)
		for _, a := range v.Args {
			w.walkExpr(a)
		}
	case *Index:
		w.walkExpr(v.Target)
		w.walkExpr(v.Index)
	case *Binary:
		w.walkExpr(v.LHS)
		w.walkExpr(v.RHS)
	case *Unary:
		w.walkExpr(v.Operand)
	case *Convert:
		w.walkExpr(v.Operand)
	case *StringLit:
		for _, pt := range v.Parts {
			w.walkExpr(pt.Expr)
		}
	case *scriptExprWrap:
		w.emitCommand(v.cmd)
	}
}
