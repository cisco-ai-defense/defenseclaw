// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shortCircuitListID is the ShortCircuitListID of a statement whose
// ancestors are stack: the ID of the first command of the outermost && / ||
// list that directly holds it (the next command ID for a new list), or zero.
func (o *parseOutput) shortCircuitListID(stack []syntax.Node) int64 {
	var head *syntax.Stmt
	for index := len(stack) - 1; index >= 0; index-- {
		if binary, ok := stack[index].(*syntax.BinaryCmd); ok {
			if binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt {
				break
			}
			continue
		}
		statement, ok := stack[index].(*syntax.Stmt)
		if !ok {
			break
		}
		binary, ok := statement.Cmd.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.AndStmt && binary.Op != syntax.OrStmt {
			break
		}
		head = statement
	}
	if head == nil {
		return 0
	}
	if o.shortCircuitLists == nil {
		o.shortCircuitLists = make(map[*syntax.Stmt]int64)
	}
	if id, ok := o.shortCircuitLists[head]; ok {
		return id
	}
	o.shortCircuitLists[head] = o.nextID
	return o.nextID
}

// posixHomeSpelling writes a plain $HOME or ${HOME} that starts word (or
// follows the = of a leading --option=) as "~" when every other part of
// word is literal; "" otherwise. A quoted glob character is not a pattern,
// so a word that has one is left unspelled.
func posixHomeSpelling(word *syntax.Word) string {
	var spelling strings.Builder
	home := false
	add := func(part syntax.WordPart, quoted bool) bool {
		switch typed := part.(type) {
		case *syntax.Lit:
			value := unquotePOSIXLiteral(typed.Value, quoted)
			if quoted && strings.ContainsAny(value, "*?[{") {
				return false
			}
			spelling.WriteString(value)
			return true
		case *syntax.SglQuoted:
			if typed.Dollar || strings.ContainsAny(typed.Value, "*?[{") {
				return false
			}
			spelling.WriteString(typed.Value)
			return true
		case *syntax.ParamExp:
			if home || !posixPlainHome(typed) {
				return false
			}
			prefix := spelling.String()
			if prefix != "" && (!strings.HasPrefix(prefix, "--") ||
				strings.IndexByte(prefix, byte(61)) != len(prefix)-1) {
				return false
			}
			spelling.WriteString("~")
			home = true
			return true
		}
		return false
	}
	for _, part := range word.Parts {
		if quoted, ok := part.(*syntax.DblQuoted); ok {
			if quoted.Dollar {
				return ""
			}
			for _, nested := range quoted.Parts {
				if !add(nested, true) {
					return ""
				}
			}
			continue
		}
		if !add(part, false) {
			return ""
		}
	}
	if !home {
		return ""
	}
	return spelling.String()
}

func posixPlainHome(expansion *syntax.ParamExp) bool {
	return expansion.Param != nil && expansion.Param.Value == "HOME" && !expansion.Excl &&
		!expansion.Length && !expansion.Width && expansion.Index == nil && expansion.Slice == nil &&
		expansion.Repl == nil && expansion.Exp == nil && expansion.Names == 0
}

// posixMayRebindHome reports source text that names HOME other than as a
// $HOME or ${HOME} expansion (HOME=..., export HOME, read HOME, for HOME
// in ...): the shell HOME may then differ from the caller home.
func posixMayRebindHome(source string) bool {
	rest := strings.ReplaceAll(source, "${HOME}", "")
	rest = strings.ReplaceAll(rest, "$HOME", "")
	return strings.Contains(rest, "HOME")
}
