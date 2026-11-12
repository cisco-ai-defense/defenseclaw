// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// This file is the adapter the s7-effects lane consumes. It exposes a stable,
// small surface over the AST: command walking in source order, static literal
// resolution, -EncodedCommand decoding, and extraction of nested script text
// that must be re-parsed. See EFFECTS.md ("PowerShell AST") for the contract.

// WalkCommands calls fn for every command invocation in the script, in source
// order, recursing into script blocks, sub-expressions, arrays, parentheses,
// hashtable values and control-flow bodies. Call operators (& and .) are
// reported with InvokeOp set on the *Command.
func WalkCommands(sc *Script, fn func(*Command)) {
	if sc == nil {
		return
	}
	walkCommandsStmts(sc.Statements, fn)
}

func walkCommandsStmts(sts []Statement, fn func(*Command)) {
	for _, s := range sts {
		walkCommandsStmt(s, fn)
	}
}

func walkCommandsStmt(s Statement, fn func(*Command)) {
	switch v := s.(type) {
	case nil:
	case *Pipeline:
		for p := v; p != nil; p = p.ChainRHS {
			for _, el := range p.Elements {
				switch e := el.(type) {
				case *Command:
					fn(e)
					walkCommandsCmd(e, fn)
				case *ExprStatement:
					walkCommandsExpr(e.Expr, fn)
				}
			}
			for _, r := range p.Redirs {
				walkCommandsExpr(r.Target, fn)
			}
		}
	case *Assignment:
		walkCommandsExpr(v.LHS, fn)
		walkCommandsStmt(v.RHS, fn)
	case *Block:
		walkCommandsStmts(v.Conditions, fn)
		for _, b := range v.Bodies {
			if b != nil {
				walkCommandsStmts(b.Statements, fn)
			}
		}
	case *Command:
		fn(v)
		walkCommandsCmd(v, fn)
	case *ExprStatement:
		walkCommandsExpr(v.Expr, fn)
	}
}

func walkCommandsCmd(c *Command, fn func(*Command)) {
	walkCommandsExpr(c.Name, fn)
	for _, el := range c.Elements {
		switch e := el.(type) {
		case *Parameter:
			walkCommandsExpr(e.Colon, fn)
		case *Arg:
			walkCommandsExpr(e.Value, fn)
		case Expr:
			walkCommandsExpr(e, fn)
		}
	}
	for _, r := range c.Redirs {
		walkCommandsExpr(r.Target, fn)
	}
}

func walkCommandsExpr(e Expr, fn func(*Command)) {
	switch v := e.(type) {
	case nil:
	case *ScriptBlockExpr:
		walkCommandsStmts(v.Statements, fn)
	case *SubExpr:
		walkCommandsStmts(v.Statements, fn)
	case *ArrayExpr:
		walkCommandsStmts(v.Statements, fn)
	case *ArrayLit:
		for _, el := range v.Elements {
			walkCommandsExpr(el, fn)
		}
	case *Hashtable:
		for _, val := range v.Values {
			walkCommandsExpr(val, fn)
		}
	case *Paren:
		walkCommandsStmt(v.Inner, fn)
	case *Member:
		walkCommandsExpr(v.Target, fn)
	case *Invoke:
		walkCommandsExpr(v.Target, fn)
		for _, a := range v.Args {
			walkCommandsExpr(a, fn)
		}
	case *Index:
		walkCommandsExpr(v.Target, fn)
		walkCommandsExpr(v.Index, fn)
	case *Binary:
		walkCommandsExpr(v.LHS, fn)
		walkCommandsExpr(v.RHS, fn)
	case *Unary:
		walkCommandsExpr(v.Operand, fn)
	case *Convert:
		walkCommandsExpr(v.Operand, fn)
	case *StringLit:
		for _, pt := range v.Parts {
			walkCommandsExpr(pt.Expr, fn)
		}
	case *scriptExprWrap:
		fn(v.cmd)
		walkCommandsCmd(v.cmd, fn)
	}
}

// LiteralString resolves an expression to its static string value when it is
// fully known: a single-quoted / here-single string, a double string with no
// expansion, a bareword, a number, or a + concatenation of such. ok is false
// for anything with a variable, sub-expression or other dynamic part.
func LiteralString(e Expr) (string, bool) {
	switch v := e.(type) {
	case *StringLit:
		if v.Static {
			return v.Value, true
		}
		// an expandable string whose parts are all literal is still static
		if len(v.Parts) > 0 {
			var b strings.Builder
			for _, pt := range v.Parts {
				if pt.Expr != nil {
					return "", false
				}
				b.WriteString(pt.Lit)
			}
			return b.String(), true
		}
		return "", false
	case *Number:
		return v.Text, true
	case *Binary:
		if v.Op == "+" {
			l, lok := LiteralString(v.LHS)
			r, rok := LiteralString(v.RHS)
			if lok && rok {
				return l + r, true
			}
		}
	case *Paren:
		switch inner := v.Inner.(type) {
		case *ExprStatement:
			return LiteralString(inner.Expr)
		case *Pipeline:
			if len(inner.Elements) == 1 {
				if es, ok := inner.Elements[0].(*ExprStatement); ok {
					return LiteralString(es.Expr)
				}
			}
		}
	case *ArrayLit:
		// a comma list of literals joins with spaces (ArgumentList style)
		parts := make([]string, 0, len(v.Elements))
		for _, el := range v.Elements {
			s, ok := LiteralString(el)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}

// DecodeEncodedCommand decodes a PowerShell -EncodedCommand value: base64 of
// UTF-16LE text. ok is false if the input is not valid base64/UTF-16LE.
func DecodeEncodedCommand(s string) (string, bool) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw)%2 != 0 {
		return "", false
	}
	u16 := make([]uint16, len(raw)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u16)), true
}
