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
		if !v.Static {
			return "", false
		}
		if v.Bare || v.Kind == StrBare {
			// a bareword / command name: the strict class (an operator-class
			// rune here would be a real separator, not literal text).
			if safeStaticLiteral(v.Raw) && safeStaticLiteral(v.Value) {
				return v.Value, true
			}
			return "", false
		}
		// a quoted string literal: its contents are literal (never operators),
		// and when it is a nested script effects re-parses it and re-gates the
		// leaves, so the wider class (printable ASCII, but still no backtick,
		// control rune or non-ASCII) is safe and avoids making ordinary quoted
		// payloads opaque (review 4 R4-7).
		if safeQuotedLiteral(v.Raw) && safeQuotedLiteral(v.Value) {
			return v.Value, true
		}
		return "", false
	case *Number:
		// the pwsh-formatted value computed in numberLit (0x10 -> "16",
		// 1.0d -> "1.0", a too-big integer keeps its exact digits). Gate the
		// display on the strict class too, so a non-ASCII "digit" that slipped
		// through can never resolve static (review 4 invariant fuzzer).
		if v.OK && safeStaticLiteral(v.Display) {
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
		// A comma/array argument is never one static value: effects must read
		// the elements (LiteralList) and treat each as its own word, so a
		// protected element (Remove-Item C:\tmp\a,C:\Windows) is not hidden
		// inside a fabricated joined string (review 4 R4-2).
		return "", false
	}
	return "", false
}

// ListItem is one element of a comma/array argument: its resolved value and
// whether that value is a trusted static literal.
type ListItem struct {
	Text   string
	Static bool
}

// LiteralList returns the elements of a comma/array argument, each with its own
// Static flag, and true if e is such a list. Callers must treat each element as
// a separate word; LiteralString on the same expression is non-static by
// design, so a comma list can never resolve to one joined value.
func LiteralList(e Expr) ([]ListItem, bool) {
	a, ok := e.(*ArrayLit)
	if !ok {
		return nil, false
	}
	items := make([]ListItem, 0, len(a.Elements))
	for _, el := range a.Elements {
		v, st := LiteralString(el)
		items = append(items, ListItem{Text: v, Static: st})
	}
	return items, true
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

// safeQuotedLiteral is the wider class for a quoted string literal (and for a
// nested script's text): every rune must be printable ASCII (0x20..0x7e) and
// not a backtick. It rejects backtick escapes, control runes and non-ASCII
// (the value-changing / homoglyph vectors) but allows the structural
// punctuation that is literal inside quotes (; & | ( ) { } [ ] $ * ? etc.).
func safeQuotedLiteral(s string) bool {
	for _, r := range s {
		if r == '`' || r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}
