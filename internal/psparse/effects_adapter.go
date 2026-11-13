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
		for _, k := range v.Keys {
			walkCommandsExpr(k, fn)
		}
		for _, val := range v.Values {
			walkCommandsExpr(val, fn)
		}
	case *TypeExpr:
		for _, a := range v.Args {
			walkCommandsExpr(a, fn)
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
		// A value is a trusted static literal only when it is marked Static AND
		// every rune of its source span (and resolved value) is in the safe
		// allowlist: ASCII letters, digits and \ / : . - _ , = + @ ~ % plus
		// ASCII quotes and spaces. Anything else -- a backtick escape of any
		// kind, smart quotes/dashes, brackets, $, u{, braces, control runes or
		// non-ASCII -- is reported non-static (ps_unsafe_literal), so an
		// obfuscated name/path (i`u{65}x, C:\tmp\`[a]) can never resolve to a
		// trusted literal. (The AST Static flag itself stays set for node-kind
		// matching against the reference parser.)
		if v.Static && safeStaticLiteral(v.Raw) && safeStaticLiteral(v.Value) {
			return v.Value, true
		}
		return "", false
	case *Number:
		// the pwsh-formatted value computed in numberLit (0x10 -> "16",
		// 1.0d -> "1.0", a too-big integer keeps its exact digits).
		if v.OK {
			return v.Display, true
		}
		return "", false
	case *Binary:
		// a binary expression argument is a non-constant node on the reference
		// side (never a static value).
		return "", false
	case *Paren:
		// a parenthesised argument is a ParenExpression (non-constant) on the
		// reference side, so it is never a static literal value.
		return "", false
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

// safeStaticLiteral reports whether every rune of s is in the Static-value
// allowlist (ASCII letters/digits and \ / : . - _ , = + @ ~ % plus ASCII
// quotes and spaces). It is the one gate that decides whether a parsed literal
// is trusted as an exact value; anything outside the class is treated as
// ps_unsafe_literal and resolves non-static.
func safeStaticLiteral(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if strings.ContainsRune(`\/:.-_,=+@~% '"`, r) {
			continue
		}
		return false
	}
	return true
}
