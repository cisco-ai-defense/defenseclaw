// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// KnownEnvironmentWriteTargets reads write operands with values supplied by
// a tool's execution environment. It uses the same shell parser, value
// tracker, and ActionFacts write roles as the hook client and gateway. A
// shell assignment replaces an inherited value before its write is read.
// Only proven targets are returned; callers can apply their own protected
// roots to those paths. The result is bounded by the hook target budget.
func KnownEnvironmentWriteTargets(command, cwd, home string, environment map[string]string) (targets []string, ok bool) {
	if runtime.GOOS == "windows" || !filepath.IsAbs(cwd) || !filepath.IsAbs(home) {
		return nil, false
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	for name, value := range environment {
		if knownShellVariableName(name) {
			values[name] = value
		}
	}
	// The tool's cwd is fixed by the caller; HOME may be set by the tool's
	// execution environment and is kept for shell expansion. The account
	// home remains the separate protected-path root.
	values["PWD"] = cwd
	return knownEnvironmentWriteTargets(command, cwd, home, values, 0)
}

func knownEnvironmentWriteTargets(command, cwd, home string, values actionValues, depth int) (targets []string, ok bool) {
	targets, _, ok = knownEnvironmentWriteFlow(command, cwd, home, values, depth)
	return targets, ok
}

func knownEnvironmentWriteFlow(command, cwd, home string, values actionValues, depth int) (targets []string, states []actionValues, ok bool) {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return nil, nil, false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return nil, nil, false
	}
	seen := make(map[string]bool)
	overflow := false
	add := func(path string) {
		if path == "" {
			return
		}
		path = OperandPath(path, cwd)
		if seen[path] {
			return
		}
		if len(targets) >= MaxWriteTargets {
			overflow = true
			return
		}
		seen[path] = true
		targets = append(targets, path)
	}
	functions := make(map[string]*syntax.Stmt)
	syntax.Walk(file, func(node syntax.Node) bool {
		if function, isFunction := node.(*syntax.FuncDecl); isFunction && function.Name != nil {
			functions[function.Name.Value] = function.Body
		}
		return true
	})
	var visit func(*syntax.Stmt, actionValues, int) ([]actionValues, bool)
	var visitList func([]*syntax.Stmt, []actionValues, int) ([]actionValues, bool)
	var visitIf func(*syntax.IfClause, actionValues, int) ([]actionValues, bool)
	visitList = func(statements []*syntax.Stmt, candidates []actionValues, nesting int) ([]actionValues, bool) {
		for _, stmt := range statements {
			var next []actionValues
			for _, current := range candidates {
				outcomes, valid := visit(stmt, current, nesting)
				if !valid {
					return nil, false
				}
				next = actionAppendValueCandidates(next, outcomes)
				if actionKeptSaturated(next) {
					return nil, false
				}
			}
			candidates = next
		}
		return candidates, true
	}
	visitIf = func(clause *syntax.IfClause, current actionValues, nesting int) ([]actionValues, bool) {
		if len(clause.Cond) == 0 {
			return visitList(clause.Then, []actionValues{current}, nesting+1)
		}
		prior := maps.Clone(current)
		condition, valid := visitList(clause.Cond, []actionValues{current}, nesting+1)
		if !valid {
			return nil, false
		}
		truth := knownEnvironmentCondition(clause.Cond[len(clause.Cond)-1], prior, home)
		var outcomes []actionValues
		for _, state := range condition {
			if truth >= 0 {
				branch, valid := visitList(clause.Then, []actionValues{maps.Clone(state)}, nesting+1)
				if !valid {
					return nil, false
				}
				outcomes = actionAppendValueCandidates(outcomes, branch)
			}
			if truth <= 0 {
				if clause.Else == nil {
					outcomes = actionAppendValueCandidates(outcomes, []actionValues{state})
				} else {
					branch, valid := visitIf(clause.Else, maps.Clone(state), nesting+1)
					if !valid {
						return nil, false
					}
					outcomes = actionAppendValueCandidates(outcomes, branch)
				}
			}
			if actionKeptSaturated(outcomes) {
				return nil, false
			}
		}
		return outcomes, true
	}
	visit = func(stmt *syntax.Stmt, current actionValues, nesting int) ([]actionValues, bool) {
		if stmt == nil || nesting >= 32 {
			return nil, false
		}
		if stmt.Background {
			foreground := *stmt
			foreground.Background = false
			_, valid := visit(&foreground, maps.Clone(current), nesting+1)
			return []actionValues{current}, valid
		}
		prior := maps.Clone(current)
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		if isCall || stmt.Cmd != nil && isKnownEnvDeclaration(stmt.Cmd) {
			actionUpdateValues(stmt, current, cwd, home)
		}
		// The calling shell expands redirections before an invocation-local
		// assignment reaches the child process.
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil || !actionOutputRedirect(redirect.Op) {
				continue
			}
			if target, known := actionWordValue(redirect.Word, prior, cwd, home); known {
				add(target)
			}
		}
		if isCall && len(call.Args) > 0 {
			// ActionFacts supplies the same destination roles for cp, mv,
			// tee, dd and other simple writers that the gateway uses. An
			// unknown word keeps its argv position without naming a target.
			words := make([]string, len(call.Args))
			knownWords := make([]bool, len(call.Args))
			for i, word := range call.Args {
				value, known := actionWordValue(word, prior, cwd, home)
				knownWords[i] = known
				if !known {
					value = "defenseclaw-unknown-operand"
				}
				words[i] = value
			}
			program, programKnown := words[0], knownWords[0]
			outcomes := []actionValues{current}
			if programKnown {
				var rendered strings.Builder
				for i, word := range words {
					if i > 0 {
						rendered.WriteByte(' ')
					}
					rendered.WriteByte('\'')
					rendered.WriteString(strings.ReplaceAll(word, "'", "'\\''"))
					rendered.WriteByte('\'')
				}
				facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: rendered.String(), CWD: cwd, ActiveHome: home})
				for _, path := range facts.Paths {
					switch path.Access {
					case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
						if path.Resolved != "" {
							add(path.Resolved)
						} else {
							add(path.Value)
						}
					}
				}
				if body := functions[program]; body != nil {
					var valid bool
					outcomes, valid = visit(body, current, nesting+1)
					if !valid {
						return nil, false
					}
				}
				if program == "eval" && len(words) > 1 {
					bodyKnown := true
					for _, known := range knownWords[1:] {
						bodyKnown = bodyKnown && known
					}
					if bodyKnown {
						// eval joins its expanded arguments and runs them in this shell.
						// The shared value tracker applies invocation assignments
						// before the nested body, then the body's values persist.
						evalValues := maps.Clone(prior)
						actionUpdateValuesAs(stmt, evalValues, cwd, home, false)
						child, childStates, childOK := knownEnvironmentWriteFlow(strings.Join(words[1:], " "), cwd, home, evalValues, depth+1)
						if !childOK {
							return nil, false
						}
						for _, target := range child {
							add(target)
						}
						outcomes = childStates
					}
				}
				if programBase(program) == "env" || actionInterpreterWrappers[programBase(program)] ||
					posixShellProgram(programBase(program)) {
					for i, shell := range words {
						if !knownWords[i] || !posixShellProgram(programBase(shell)) {
							continue
						}
						childValues := maps.Clone(current)
						envIndex := -1
						for j := 0; j < i; j++ {
							if knownWords[j] && programBase(words[j]) == "env" {
								envIndex = j
								break
							}
						}
						if envIndex >= 0 {
							for j := envIndex + 1; j < i; j++ {
								prefix := words[j]
								switch prefix {
								case "-i", "--ignore-environment":
									clear(childValues)
									continue
								case "-u", "--unset":
									if j+1 < i {
										j++
										delete(childValues, words[j])
									}
									continue
								}
								if name, found := strings.CutPrefix(prefix, "--unset="); found {
									delete(childValues, name)
									continue
								}
								if name, value, assigned := strings.Cut(prefix, "="); assigned && knownShellVariableName(name) {
									childValues[name] = value
								}
							}
						}
						for j := i + 1; j+1 < len(call.Args); j++ {
							option := words[j]
							if !knownWords[j] || !strings.HasPrefix(option, "-") {
								break
							}
							if option == "-c" || len(option) > 2 && strings.Contains(option[1:], "c") && !strings.HasPrefix(option, "--") {
								if knownWords[j+1] {
									// The first word after the body is $0; later words are
									// positional parameters in the child shell.
									for name := range childValues {
										if _, err := strconv.Atoi(name); err == nil {
											delete(childValues, name)
										}
									}
									for position, value := range words[j+2:] {
										name := strconv.Itoa(position)
										if knownWords[j+2+position] {
											childValues[name] = value
										}
									}
									child, childOK := knownEnvironmentWriteTargets(words[j+1], cwd, home, childValues, depth+1)
									if !childOK {
										return nil, false
									}
									for _, target := range child {
										add(target)
									}
								}
								break
							}
						}
						break
					}
				}
			}
			// Invocation assignments do not persist in the calling shell.
			if len(call.Assigns) > 0 && (!programKnown || !knownEnvSpecialBuiltin(program)) {
				for _, outcome := range outcomes {
					for _, assignment := range call.Assigns {
						if assignment.Name == nil {
							continue
						}
						name := assignment.Name.Value
						if value, present := prior[name]; present {
							outcome[name] = value
						} else {
							delete(outcome, name)
						}
					}
				}
			}
			return outcomes, true
		}
		switch compound := stmt.Cmd.(type) {
		case *syntax.Block:
			return visitList(compound.Stmts, []actionValues{current}, nesting+1)
		case *syntax.Subshell:
			_, valid := visitList(compound.Stmts, []actionValues{maps.Clone(current)}, nesting+1)
			return []actionValues{current}, valid
		case *syntax.BinaryCmd:
			if compound.Op == syntax.Pipe || compound.Op == syntax.PipeAll {
				if _, valid := visit(compound.X, maps.Clone(current), nesting+1); !valid {
					return nil, false
				}
				_, valid := visit(compound.Y, maps.Clone(current), nesting+1)
				return []actionValues{current}, valid
			}
			leftPrior := maps.Clone(current)
			left, valid := visit(compound.X, current, nesting+1)
			if !valid {
				return nil, false
			}
			truth := knownEnvironmentCondition(compound.X, leftPrior, home)
			var outcomes []actionValues
			for _, state := range left {
				if truth == 0 || compound.Op == syntax.AndStmt && truth < 0 || compound.Op == syntax.OrStmt && truth > 0 {
					outcomes = actionAppendValueCandidates(outcomes, []actionValues{state})
				}
				if truth == 0 || compound.Op == syntax.AndStmt && truth > 0 || compound.Op == syntax.OrStmt && truth < 0 {
					right, valid := visit(compound.Y, maps.Clone(state), nesting+1)
					if !valid {
						return nil, false
					}
					outcomes = actionAppendValueCandidates(outcomes, right)
				}
				if actionKeptSaturated(outcomes) {
					return nil, false
				}
			}
			return outcomes, true
		case *syntax.IfClause:
			return visitIf(compound, current, nesting+1)
		case *syntax.WhileClause:
			prior := maps.Clone(current)
			condition, valid := visitList(compound.Cond, []actionValues{current}, nesting+1)
			if !valid {
				return nil, false
			}
			truth := 0
			if len(compound.Cond) > 0 {
				truth = knownEnvironmentCondition(compound.Cond[len(compound.Cond)-1], prior, home)
			}
			if compound.Until {
				truth = -truth
			}
			var outcomes []actionValues
			for _, state := range condition {
				if truth <= 0 {
					outcomes = actionAppendValueCandidates(outcomes, []actionValues{state})
				}
				if truth >= 0 {
					body, valid := visitList(compound.Do, []actionValues{maps.Clone(state)}, nesting+1)
					if !valid {
						return nil, false
					}
					outcomes = actionAppendValueCandidates(outcomes, body)
				}
				if actionKeptSaturated(outcomes) {
					return nil, false
				}
			}
			return outcomes, true
		case *syntax.ForClause:
			if iteration, ok := compound.Loop.(*syntax.WordIter); ok && !compound.Select && iteration.InPos.IsValid() {
				items := make([]string, 0, len(iteration.Items))
				fixed := true
				for _, word := range iteration.Items {
					item, known := knownEnvironmentForItem(word, current, cwd, home)
					if !known {
						fixed = false
						break
					}
					items = append(items, item)
				}
				if fixed {
					states := []actionValues{current}
					for _, item := range items {
						var next []actionValues
						for _, state := range states {
							state = maps.Clone(state)
							state[iteration.Name.Value] = item
							body, valid := visitList(compound.Do, []actionValues{state}, nesting+1)
							if !valid {
								return nil, false
							}
							next = actionAppendValueCandidates(next, body)
						}
						if actionKeptSaturated(next) {
							return nil, false
						}
						states = next
					}
					return states, true
				}
			}
			branch := maps.Clone(current)
			if iteration, ok := compound.Loop.(*syntax.WordIter); ok && iteration.Name != nil {
				delete(branch, iteration.Name.Value)
			}
			body, valid := visitList(compound.Do, []actionValues{branch}, nesting+1)
			if !valid {
				return nil, false
			}
			outcomes := actionAppendValueCandidates([]actionValues{current}, body)
			return outcomes, !actionKeptSaturated(outcomes)
		case *syntax.CaseClause:
			selector, selectorKnown := actionWordValueWithGlob(compound.Word, current, cwd, home, true)
			plainBranches := true
			catchAll := false
			for _, item := range compound.Items {
				if item.Op != 0 && item.Op != syntax.Break {
					plainBranches = false
				}
				for _, pattern := range item.Patterns {
					if pattern.Lit() == "*" {
						catchAll = true
					}
				}
			}
			if selectorKnown && plainBranches {
				definite := true
				for _, item := range compound.Items {
					match := false
					for _, pattern := range item.Patterns {
						if pattern.Lit() == "*" {
							match = true
							break
						}
						value, known := actionWordValueWithGlob(pattern, current, cwd, home, true)
						if !known || knownEnvironmentPatternGlobs(pattern) {
							definite = false
							break
						}
						if value == selector {
							match = true
							break
						}
					}
					if !definite {
						break
					}
					if match {
						return visitList(item.Stmts, []actionValues{current}, nesting+1)
					}
				}
				if definite {
					return []actionValues{current}, true
				}
			}
			var outcomes []actionValues
			if !catchAll || !plainBranches {
				outcomes = []actionValues{current}
			}
			for _, item := range compound.Items {
				branch, valid := visitList(item.Stmts, []actionValues{maps.Clone(current)}, nesting+1)
				if !valid {
					return nil, false
				}
				outcomes = actionAppendValueCandidates(outcomes, branch)
				if actionKeptSaturated(outcomes) {
					return nil, false
				}
			}
			return outcomes, true
		}
		return []actionValues{current}, true
	}
	states, valid := visitList(file.Stmts, []actionValues{values}, 0)
	return targets, states, valid && !overflow
}

func isKnownEnvDeclaration(command syntax.Command) bool {
	_, ok := command.(*syntax.DeclClause)
	return ok
}

// An assignment-only command succeeds when it has no command substitution or
// known readonly destination. Its value persists even when a following branch
// is skipped. Other conditions keep both possible paths.
func knownEnvironmentCondition(stmt *syntax.Stmt, values actionValues, home string) int {
	if truth := actionStaticCondition(stmt, home); truth != 0 {
		return truth
	}
	if stmt == nil || stmt.Background || len(stmt.Redirs) != 0 {
		return 0
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) == 0 {
		return 0
	}
	for _, assignment := range call.Assigns {
		if assignment.Name == nil || values[actionReadonlyValuePrefix+assignment.Name.Value] != "" {
			return 0
		}
		if assignment.Value != nil {
			commandSubstitution := false
			syntax.Walk(assignment.Value, func(node syntax.Node) bool {
				if _, found := node.(*syntax.CmdSubst); found {
					commandSubstitution = true
					return false
				}
				return true
			})
			if commandSubstitution {
				return 0
			}
		}
	}
	if stmt.Negated {
		return -1
	}
	return 1
}

// A for-list item is one iteration only when its known expansion cannot be
// split or globbed. Quoted values use the active shell bindings, including a
// tool-supplied HOME, rather than the account home used for protection.
func knownEnvironmentForItem(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	if word == nil {
		return "", false
	}
	unquotedExpansion := false
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return "", false
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			unquotedExpansion = true
		}
	}
	value, known := actionWordValueWithGlob(word, values, cwd, home, true)
	if !known {
		return "", false
	}
	if unquotedExpansion {
		ifs, set := values["IFS"]
		if !set {
			ifs = " \t\n"
		}
		if value == "" || strings.ContainsAny(value, ifs+"*?[") {
			return "", false
		}
	}
	return value, true
}

func knownEnvironmentPatternGlobs(word *syntax.Word) bool {
	for _, part := range word.Parts {
		if literal, ok := part.(*syntax.Lit); ok && strings.ContainsAny(literal.Value, "*?[") {
			return true
		}
	}
	return false
}

func knownEnvSpecialBuiltin(program string) bool {
	switch programBase(program) {
	case ":", ".", "eval", "export", "readonly", "set", "shift", "trap", "unset":
		return true
	}
	return false
}

func knownShellVariableName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
