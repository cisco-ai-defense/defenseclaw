// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The broad command reading can match an earlier assignment or a read
// operand. It is not positive write evidence when every variable target has
// a known ordinary value at its write. Keep unknown or control-dependent
// targets for the managed gateway to judge conservatively.
func actionClientProvedSafeVariableTargets(command, cwd, home string) bool {
	return actionClientProvedSafeVariableTargetsWithBindings(command, cwd, home, false)
}

func actionClientProvedSafeVariableTargetsWithBindings(command, cwd, home string, trackBindings bool) bool {
	if actionClientLoopCopySourceStartupUnknown() {
		return false
	}
	file, ok := parseShell(command)
	if !ok || !filepath.IsAbs(cwd) {
		return false
	}
	// These forms can change a later binding without a plain assignment.
	// A prefix assignment with a program is temporary, not a shell binding.
	directDynamicPrintf := make(map[*syntax.CallExpr]bool)
	for _, stmt := range file.Stmts {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) >= 2 {
			if _, simple := actionSimpleProgramParameter(call.Args[1]); simple {
				directDynamicPrintf[call] = true
			}
		}
	}
	unsafe := false
	functions := make(map[string]bool)
	topLevelFunctions := make(map[*syntax.FuncDecl]bool)
	for _, stmt := range file.Stmts {
		if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			topLevelFunctions[function] = true
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if unsafe {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if !topLevelFunctions[node] || node.Name == nil || actionFunctionValue(node, home) == actionFunctionUnknownValue {
				unsafe = true
			} else {
				functions[node.Name.Value] = true
			}
			return false
		case *syntax.Block, *syntax.TimeClause:
			unsafe = true
		case *syntax.Redirect:
			switch node.Op {
			case syntax.RdrIn, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			default:
				unsafe = !actionOutputRedirect(node.Op)
			}
		case *syntax.DeclClause:
			unsafe = !actionClientReadonlyDecl(node, home)
		case *syntax.Assign:
			// A later ~ is resolved from the shell's current HOME, not
			// necessarily from the hook's active home.
			if node.Name != nil && node.Name.Value == "HOME" {
				unsafe = true
			}
		case *syntax.Word:
			// The kept evaluator knows ~ and ~/ but does not expand
			// directory-stack or named-user tildes.
			if len(node.Parts) != 0 {
				if lit, ok := node.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(lit.Value, "~") &&
					lit.Value != "~" && !strings.HasPrefix(lit.Value, "~/") {
					unsafe = true
				}
			}
		case *syntax.ForClause:
			// Only a no-op loop may precede an unconditional overwrite.
			// A writer inside the loop needs its own target proof.
			for _, stmt := range node.Do {
				call, ok := stmt.Cmd.(*syntax.CallExpr)
				if !ok || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) != 1 || call.Args[0].Lit() != ":" {
					unsafe = true
					return false
				}
			}
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			if len(node.Assigns) != 0 {
				unsafe = true
				return false
			}
			program, fixed := staticProgramWord(node.Args[0], home)
			if !fixed {
				unsafe = true
				return false
			}
			if functions[program] {
				return true
			}
			switch programBase(program) {
			case "trap", "eval", "source", ".", "builtin", "command", "declare", "local", "typeset", "read", "mapfile", "readarray", "wait", "set", "export":
				unsafe = true
			case "unset":
				unsafe = !actionClientFunctionUnset(node, home)
			case "readonly":
				unsafe = !actionClientReadonlyName(node, home)
			case "cd":
				if len(node.Args) != 2 {
					unsafe = true
					break
				}
				value, fixed := StaticWord(node.Args[1], home)
				if !fixed || !samePathName(OperandPath(value, cwd), cwd) {
					unsafe = true
				}
			case "printf":
				// An option assembled from expansions is not proof that printf
				// leaves later shell bindings alone. A simple parameter option
				// can only change a binding after this statement's redirects
				// have expanded. Bash also accepts -vNAME.
				if len(node.Args) < 2 {
					unsafe = true
					break
				}
				// The kept tracker follows literal binding options. A later
				// target stays unproved if its value cannot be recovered.
				option, fixed := StaticWord(node.Args[1], home)
				if !fixed {
					unsafe = !directDynamicPrintf[node]
				} else if !trackBindings && strings.HasPrefix(option, "-v") {
					unsafe = true
				}
			case "install":
				// Only the simple source/destination form and -m MODE
				// have the final word as their sole write path.
				if len(node.Args) != 3 && (len(node.Args) != 5 || node.Args[1].Lit() != "-m" ||
					node.Args[2].Lit() == "" || strings.Trim(node.Args[2].Lit(), "01234567") != "") {
					unsafe = true
				} else {
					source := node.Args[len(node.Args)-2]
					value, fixed := StaticWord(source, home)
					unsafe = !fixed || strings.HasPrefix(value, "-") || !actionClientQuotedVariableTarget(node.Args[len(node.Args)-1])
				}
			case "rsync":
				if len(node.Args) != 3 {
					unsafe = true
				} else {
					value, fixed := StaticWord(node.Args[1], home)
					unsafe = !fixed || strings.HasPrefix(value, "-") || !actionClientQuotedVariableTarget(node.Args[2])
				}
			case "tee":
				unsafe = len(node.Args) != 2 || !actionClientQuotedVariableTarget(node.Args[1])
			case "echo", "cat", "true", "false", ":", "[", "test":
			default:
				unsafe = true
			}
		}
		return !unsafe
	})
	if unsafe {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	kept := []actionValues{{"HOME": home, "PWD": cwd}}
	steps := 0
	seen := false
	possibleLaterBinding := false
	for _, stmt := range file.Stmts {
		var writeValues []actionValues
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 && len(stmt.Redirs) > 0 {
			if name, fixed := staticProgramWord(call.Args[0], home); fixed &&
				(functions[name] || programBase(name) == "printf") {
				// The redirect opens before the function changes any binding.
				// Keep the values from before this statement for its target.
				writeValues = kept
			}
		}
		// A dynamic printf option may change a later binding. Its own
		// redirect expands before printf runs, while a later target cannot
		// use the ordinary-target proof below.
		dynamicPrintf := false
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) >= 2 {
			if program, fixed := staticProgramWord(call.Args[0], home); fixed && programBase(program) == "printf" {
				_, dynamicPrintf = actionSimpleProgramParameter(call.Args[1])
				if trackBindings {
					resolved := true
					for _, values := range kept {
						if _, shadowed := values[actionFunctionValuePrefix+program]; shadowed || program != "printf" {
							if dynamicPrintf {
								resolved = false
							}
							continue
						}
						option, known := actionWordValue(call.Args[1], values, cwd, home)
						if !known {
							resolved = false
							break
						}
						if strings.HasPrefix(option, "-v") {
							if _, _, bound := actionPrintfBoundName(call, values, cwd, home); !bound {
								resolved = false
								break
							}
						}
					}
					dynamicPrintf = !resolved
				}
			}
		}
		kept = actionUpdateValuesKept(stmt, kept, cwd, home, &steps)
		if writeValues == nil {
			writeValues = kept
		}
		if actionKeptSaturated(kept) || len(kept) == 0 {
			return false
		}
		// The kept tracker does not bind a for iterator to its word list.
		// Forget its prior value until a later plain assignment replaces it.
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if loop, ok := node.(*syntax.ForClause); ok {
				if iter, ok := loop.Loop.(*syntax.WordIter); ok && iter.Name != nil {
					for _, values := range kept {
						delete(values, iter.Name.Value)
					}
				}
			}
			return true
		})
		var targets []*syntax.Word
		var nestedUnsafe bool
		syntax.Walk(stmt, func(node syntax.Node) bool {
			switch node := node.(type) {
			case *syntax.Subshell, *syntax.ForClause, *syntax.WhileClause, *syntax.CaseClause:
				nestedUnsafe = true
			case *syntax.Redirect:
				if node.Word != nil && actionOutputRedirect(node.Op) {
					targets = append(targets, node.Word)
				}
			case *syntax.CallExpr:
				if len(node.Args) >= 2 {
					program, fixed := staticProgramWord(node.Args[0], home)
					if fixed && (programBase(program) == "install" || programBase(program) == "rsync" || programBase(program) == "tee") {
						targets = append(targets, node.Args[len(node.Args)-1])
					}
				}
			}
			return true
		})
		if len(targets) == 0 {
			possibleLaterBinding = possibleLaterBinding || dynamicPrintf
			continue
		}
		if nestedUnsafe || possibleLaterBinding {
			return false
		}
		// A statement that assigns and writes may write before its final
		// binding. The post-statement candidates cannot prove that target.
		assigned := false
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if _, ok := node.(*syntax.Assign); ok {
				assigned = true
			}
			return !assigned
		})
		if assigned {
			return false
		}
		for _, target := range targets {
			seen = seen || wordExpandsParameter(target)
			for _, values := range writeValues {
				value, known := actionWordValue(target, values, cwd, home)
				if !known || value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") ||
					actionClientProtectedPath(value, cwd, protected, ssh) {
					return false
				}
			}
		}
		possibleLaterBinding = possibleLaterBinding || dynamicPrintf
	}
	return seen
}

// ProvedOrdinaryVariableTargets applies the client proof to a call that uses
// a declared shell function. The local gateway can then resolve user paths.
func ProvedOrdinaryVariableTargets(command, cwd, home string) bool {
	if !actionClientBindingSyntax(command) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	functions := make(map[string]bool)
	called := false
	binding := false
	for _, stmt := range file.Stmts {
		if function, ok := stmt.Cmd.(*syntax.FuncDecl); ok {
			if function.Name != nil {
				functions[function.Name.Value] = true
			}
			continue
		}
		syntax.Walk(stmt, func(node syntax.Node) bool {
			switch node := node.(type) {
			case *syntax.FuncDecl:
				return false
			case *syntax.DeclClause:
				binding = binding || actionClientReadonlyDecl(node, home)
			case *syntax.CallExpr:
				if len(node.Args) > 0 {
					name, fixed := staticProgramWord(node.Args[0], home)
					called = called || fixed && functions[name]
					if fixed && name == "printf" && len(node.Args) > 1 {
						option, known := StaticWord(node.Args[1], home)
						binding = binding || known && strings.HasPrefix(option, "-v")
					}
					binding = binding || fixed && name == "readonly" && actionClientReadonlyName(node, home)
				}
			}
			return !called && !binding
		})
		if called || binding {
			return actionClientProvedSafeVariableTargetsWithBindings(command, cwd, home, true)
		}
	}
	return false
}

func actionClientBindingSyntax(command string) bool {
	return strings.Contains(command, "(") || strings.Contains(command, "function ") ||
		strings.Contains(command, "-v") || strings.Contains(command, "readonly")
}

func actionClientProvedSafeVariableTargetsForHook(command, cwd, home string) bool {
	if actionClientBindingSyntax(command) {
		return actionClientProvedSafeVariableTargetsWithBindings(command, cwd, home, true)
	}
	return actionClientProvedSafeVariableTargets(command, cwd, home)
}

func actionClientFunctionUnset(call *syntax.CallExpr, home string) bool {
	if len(call.Args) < 3 {
		return false
	}
	option, ok := StaticWord(call.Args[1], home)
	if !ok || option != "-f" {
		return false
	}
	for _, arg := range call.Args[2:] {
		name, fixed := StaticWord(arg, home)
		if !fixed || !actionEvalAssignmentName(name) {
			return false
		}
	}
	return true
}

func actionClientReadonlyName(call *syntax.CallExpr, home string) bool {
	if len(call.Args) != 2 {
		return false
	}
	word, fixed := StaticWord(call.Args[1], home)
	if !fixed {
		return false
	}
	name, _, _ := strings.Cut(word, "=")
	return actionEvalAssignmentName(name)
}

func actionClientReadonlyDecl(declaration *syntax.DeclClause, home string) bool {
	if declaration.Variant == nil || declaration.Variant.Value != "readonly" || len(declaration.Args) != 1 {
		return false
	}
	assign := declaration.Args[0]
	if assign.Name == nil || !actionEvalAssignmentName(assign.Name.Value) || assign.Append ||
		assign.Array != nil || assign.Index != nil {
		return false
	}
	if assign.Value != nil {
		_, fixed := StaticWord(assign.Value, home)
		return fixed
	}
	return true
}

func actionClientQuotedVariableTarget(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	_, quoted := word.Parts[0].(*syntax.DblQuoted)
	return quoted
}

// A shell startup file can install a DEBUG trap between a conditional and
// a later alias assignment. The assigned value is then not a stable proof
// of the redirect target, even when every written value in the command is
// ordinary on its own.
func actionStartupConditionalAliasRedirect(command string) bool {
	if !strings.Contains(command, "if ") || !strings.Contains(command, ">") ||
		!strings.Contains(command, "$") || !actionClientLoopCopySourceStartupUnknown() {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	conditional := false
	aliases := map[string]bool{}
	for _, stmt := range file.Stmts {
		if _, ok := stmt.Cmd.(*syntax.IfClause); ok {
			conditional = true
		}
		if !conditional {
			continue
		}
		for _, redir := range stmt.Redirs {
			if actionOutputRedirect(redir.Op) && redir.Word != nil && aliases[actionSoleParameter(redir.Word)] {
				return true
			}
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
			continue
		}
		assign := call.Assigns[0]
		if assign.Name != nil && assign.Value != nil &&
			!assign.Append && assign.Array == nil && assign.Index == nil &&
			actionSoleParameter(assign.Value) != "" {
			aliases[assign.Name.Value] = true
		}
	}
	return false
}

// The broad target scan can see an assignment to a protected link even when
// a later unconditional assignment replaces it before the sole write. Keep
// that narrow proof out of the client's positive-only decision; the managed
// gateway cannot otherwise distinguish the transient value from a write.
func actionClientProvedOverwrittenRedirect(command, cwd, home string) bool {
	if actionClientLoopCopySourceStartupUnknown() {
		return false
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 3 || !filepath.IsAbs(cwd) {
		return false
	}
	assignment := func(stmt *syntax.Stmt) (string, string, bool) {
		if stmt == nil || len(stmt.Redirs) != 0 || stmt.Background || stmt.Negated {
			return "", "", false
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
			return "", "", false
		}
		assign := call.Assigns[0]
		if assign.Name == nil || assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil {
			return "", "", false
		}
		value, fixed := StaticWord(assign.Value, home)
		return assign.Name.Value, value, fixed && value != "" && !strings.ContainsAny(value, "*?[]\x00\x1f")
	}
	name, before, ok := assignment(file.Stmts[0])
	if !ok || !actionClientProtectedPath(before, cwd, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
		return false
	}
	second := file.Stmts[1]
	if branch, yes := second.Cmd.(*syntax.IfClause); yes {
		if len(second.Redirs) != 0 || second.Background || second.Negated || branch.Else != nil ||
			len(branch.Cond) != 1 || len(branch.Then) != 1 {
			return false
		}
		condition := branch.Cond[0]
		call, yes := condition.Cmd.(*syntax.CallExpr)
		if !yes || condition.Negated || condition.Background || len(condition.Redirs) != 0 ||
			len(call.Assigns) != 0 || len(call.Args) != 1 || call.Args[0].Lit() != "true" {
			return false
		}
		second = branch.Then[0]
	}
	otherName, after, ok := assignment(second)
	if !ok || otherName != name || actionClientProtectedPath(after, cwd, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
		return false
	}
	last := file.Stmts[2]
	call, ok := last.Cmd.(*syntax.CallExpr)
	if !ok || last.Background || last.Negated || len(call.Assigns) != 0 || len(call.Args) == 0 ||
		len(last.Redirs) != 1 || last.Redirs[0].Word == nil || !actionOutputRedirect(last.Redirs[0].Op) ||
		actionSoleParameter(last.Redirs[0].Word) != name {
		return false
	}
	for i, word := range call.Args {
		value, fixed := StaticWord(word, home)
		if !fixed || i == 0 && programBase(value) != "echo" {
			return false
		}
	}
	return true
}
