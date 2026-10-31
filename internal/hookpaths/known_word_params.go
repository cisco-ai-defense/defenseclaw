// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// knownWordPrograms cannot set a variable of the calling shell: external
// programs and builtins without a binding form. A command that runs any
// other program (read, wait -p, printf -v, eval, source, trap, command,
// builtin, exec, env, cd, a function or a dynamic program word) has no known
// parameter words: a wrapper or a deferred string can rebind the name
// (rel-1-0-2:GAP-0004 review). The list is an allowlist on purpose.
var knownWordPrograms = []string{
	":", "[", "awk", "cat", "chmod", "cmp", "cp", "diff", "echo", "false", "find", "gcp", "git", "go",
	"grep", "head", "ln", "ls", "make", "mkdir", "mv", "rm", "rmdir", "sed", "sort", "tail", "tar",
	"test", "touch", "true", "uniq", "wc",
}

// mayHaveKnownCopyWord is the cheap gate of knownWordParameterUses: the
// command names a copy program and has a parameter expansion.
func mayHaveKnownCopyWord(command string) bool {
	return strings.IndexByte(command, '$') >= 0 && strings.Contains(command, "cp")
}

// literalProgramWord reads a program word spelled as one plain literal
// without the expansion StaticWord does; others take the slow path.
func literalProgramWord(word *syntax.Word, home string) (string, bool) {
	if word != nil && len(word.Parts) == 1 {
		if lit, ok := word.Parts[0].(*syntax.Lit); ok && !strings.ContainsAny(lit.Value, "\\~*?[$") {
			return lit.Value, true
		}
	}
	return StaticWord(word, home)
}

// knownWordParameterUses returns the unquoted copy-operand parameter words of
// file ($f, ${f}) that the shell expands to exactly one fixed word which is
// not an option: f is bound only by plain assignments and for loops whose
// values are fixed plain names (no blank, pattern or quoting character, no
// leading dash), the use sits in the body of such a loop or after a
// top-level assignment that always runs, and every program the command runs
// is in knownWordPrograms. Such a word reads as a quoted single parameter
// ("$f"), so for f in a.txt b.txt; do cp $f build/; done and
// f=a.txt; cp $f out.txt read as their quoted spellings do
// (rel-1-0-2:GAP-0004). Any other binding (an arithmetic, a default
// expansion, a function, an IFS change) or program leaves every word
// unknown. command is the text file was parsed from; most commands leave at
// its cheap gate.
func knownWordParameterUses(command string, file *syntax.File, home string) map[*syntax.Word]bool {
	uses, _ := knownWordParameters(command, file, home)
	return uses
}

// knownWordParameterValues returns, for the uses knownWordParameterUses
// accepts, the one value every binding of the name gives (f=out.txt, or a
// for loop over that single name). A copy operand spelled with such a word
// is that fixed file, so f=out.txt; cp a.txt $f reads as cp a.txt out.txt
// on the hook client and the gateway alike (rel-1-0-6:GAP-0235). A name
// bound to more than one value has none.
func knownWordParameterValues(command string, file *syntax.File, home string) map[*syntax.Word]string {
	_, values := knownWordParameters(command, file, home)
	return values
}

func knownWordParameters(command string, file *syntax.File, home string) (map[*syntax.Word]bool, map[*syntax.Word]string) {
	if file == nil || !mayHaveKnownCopyWord(command) {
		return nil, nil
	}
	safe := func(value string) bool {
		return value != "" && !strings.HasPrefix(value, "-") &&
			!strings.ContainsAny(value, " \t\r\n*?[]{}$`\\\"'()|&;<>!~#=,\x00")
	}
	type loop struct {
		from, to uint
	}
	unsafeNames := map[string]bool{}
	// bound: the distinct values the bindings of each name give.
	bound := map[string]map[string]bool{}
	bind := func(name, value string) {
		if bound[name] == nil {
			bound[name] = map[string]bool{}
		}
		bound[name][value] = true
	}
	loops := map[string][]loop{}
	after := map[string]uint{}
	rejected := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if rejected {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause,
			*syntax.DeclClause, *syntax.CoprocClause, *syntax.ProcSubst:
			rejected = true
		case *syntax.Assign:
			if node.Name == nil {
				rejected = true
				break
			}
			name := node.Name.Value
			if name == "IFS" {
				// Field splitting of every unquoted word changes.
				rejected = true
				break
			}
			value, fixed := "", false
			if node.Value != nil {
				value, fixed = StaticWord(node.Value, home)
			}
			if node.Append || node.Naked || node.Array != nil || node.Index != nil || !fixed || !safe(value) {
				unsafeNames[name] = true
			}
			bind(name, value)
		case *syntax.ForClause:
			iter, ok := node.Loop.(*syntax.WordIter)
			if !ok || iter.Name == nil || node.Select {
				rejected = true
				break
			}
			name := iter.Name.Value
			if name == "IFS" {
				rejected = true
				break
			}
			if !iter.InPos.IsValid() || len(iter.Items) == 0 {
				unsafeNames[name] = true
				break
			}
			for _, item := range iter.Items {
				value, fixed := StaticWord(item, home)
				if !fixed || !safe(value) {
					unsafeNames[name] = true
				}
				bind(name, value)
			}
			loops[name] = append(loops[name], loop{node.DoPos.Offset(), node.DonePos.Offset()})
		case *syntax.ParamExp:
			if node.Param != nil && node.Exp != nil {
				unsafeNames[node.Param.Value] = true
			}
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				break
			}
			program, static := literalProgramWord(node.Args[0], home)
			if !static || !slices.Contains(knownWordPrograms, programBase(program)) {
				rejected = true
			}
		}
		return !rejected
	})
	if rejected {
		return nil, nil
	}
	// A top-level assignment statement, or the first statement of a
	// top-level AND list, always runs before what follows it.
	var first func(*syntax.Stmt) *syntax.Stmt
	first = func(stmt *syntax.Stmt) *syntax.Stmt {
		if stmt == nil || stmt.Background || stmt.Negated || stmt.Coprocess {
			return nil
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
			return first(pair.X)
		}
		return stmt
	}
	for _, top := range file.Stmts {
		stmt := first(top)
		if stmt == nil || len(stmt.Redirs) != 0 {
			continue
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 {
			continue
		}
		for _, assign := range call.Assigns {
			if assign.Name != nil {
				if _, seen := after[assign.Name.Value]; !seen {
					after[assign.Name.Value] = stmt.End().Offset()
				}
			}
		}
	}
	uses := map[*syntax.Word]bool{}
	values := map[*syntax.Word]string{}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		for _, word := range call.Args[1:] {
			if len(word.Parts) != 1 {
				continue
			}
			param, ok := word.Parts[0].(*syntax.ParamExp)
			quoted := false
			if double, isQuoted := word.Parts[0].(*syntax.DblQuoted); isQuoted && len(double.Parts) == 1 {
				// "$f" with a known plain value is the same one word; it
				// only gets a value, the source rule already reads it.
				param, ok = double.Parts[0].(*syntax.ParamExp)
				quoted = true
			}
			if !ok || !simpleScalarParameter(param) || unsafeNames[param.Param.Value] {
				continue
			}
			name, at := param.Param.Value, word.Pos().Offset()
			known := false
			if end, bound := after[name]; bound && at > end {
				known = true
			}
			for _, body := range loops[name] {
				known = known || at > body.from && at < body.to
			}
			if known {
				if !quoted {
					uses[word] = true
				}
				if len(bound[name]) == 1 {
					for value := range bound[name] {
						values[word] = value
					}
				}
			}
		}
		return true
	})
	return uses, values
}

// simpleScalarParameter accepts $name or ${name} of a plain variable name.
func simpleScalarParameter(param *syntax.ParamExp) bool {
	if param == nil || param.Param == nil || param.Excl || param.Length || param.Width || param.IsSet ||
		param.Index != nil || param.Slice != nil || param.Repl != nil || param.Names != 0 ||
		param.Exp != nil || param.Flags != nil || param.NestedParam != nil || len(param.Modifiers) != 0 {
		return false
	}
	name := param.Param.Value
	if name == "" || name == "IFS" {
		return false
	}
	for i, ch := range name {
		if ch != '_' && (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') &&
			(i == 0 || ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}
