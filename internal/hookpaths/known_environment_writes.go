// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path/filepath"
	"runtime"
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
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return nil, false
	}
	file, parsed := parseShell(command)
	if !parsed {
		return nil, false
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
	var visit func(*syntax.Stmt, actionValues, int) bool
	var visitList func([]*syntax.Stmt, actionValues, int) bool
	visitList = func(statements []*syntax.Stmt, current actionValues, nesting int) bool {
		for _, stmt := range statements {
			if !visit(stmt, current, nesting) {
				return false
			}
		}
		return true
	}
	visit = func(stmt *syntax.Stmt, current actionValues, nesting int) bool {
		if stmt == nil || nesting >= 32 {
			return false
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
			for i, word := range call.Args {
				value, known := actionWordValue(word, prior, cwd, home)
				if !known {
					value = "defenseclaw-unknown-operand"
				}
				words[i] = value
			}
			program, programKnown := StaticWord(call.Args[0], home)
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
					if !visit(body, current, nesting+1) {
						return false
					}
				}
				if programBase(program) == "env" || actionInterpreterWrappers[programBase(program)] ||
					posixShellProgram(programBase(program)) {
					for i, word := range call.Args {
						shell, known := StaticWord(word, home)
						if !known || !posixShellProgram(programBase(shell)) {
							continue
						}
						childValues := maps.Clone(current)
						envIndex := -1
						for j := 0; j < i; j++ {
							if wrapped, fixed := StaticWord(call.Args[j], home); fixed && programBase(wrapped) == "env" {
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
							option, known := StaticWord(call.Args[j], home)
							if !known || !strings.HasPrefix(option, "-") {
								break
							}
							if option == "-c" || len(option) > 2 && strings.Contains(option[1:], "c") && !strings.HasPrefix(option, "--") {
								body, bodyKnown := StaticWord(call.Args[j+1], home)
								if bodyKnown {
									child, childOK := knownEnvironmentWriteTargets(body, cwd, home, childValues, depth+1)
									if !childOK {
										return false
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
				for _, assignment := range call.Assigns {
					if assignment.Name == nil {
						continue
					}
					name := assignment.Name.Value
					if value, present := prior[name]; present {
						current[name] = value
					} else {
						delete(current, name)
					}
				}
			}
			return true
		}
		switch compound := stmt.Cmd.(type) {
		case *syntax.Block:
			return visitList(compound.Stmts, current, nesting+1)
		case *syntax.Subshell:
			return visitList(compound.Stmts, maps.Clone(current), nesting+1)
		case *syntax.BinaryCmd:
			branch := maps.Clone(current)
			return visit(compound.X, branch, nesting+1) && visit(compound.Y, branch, nesting+1)
		case *syntax.IfClause:
			branch := maps.Clone(current)
			if !visitList(compound.Cond, branch, nesting+1) || !visitList(compound.Then, branch, nesting+1) {
				return false
			}
			for alternative := compound.Else; alternative != nil; alternative = alternative.Else {
				if !visitList(alternative.Cond, maps.Clone(current), nesting+1) ||
					!visitList(alternative.Then, maps.Clone(current), nesting+1) {
					return false
				}
			}
		case *syntax.WhileClause:
			branch := maps.Clone(current)
			return visitList(compound.Cond, branch, nesting+1) && visitList(compound.Do, branch, nesting+1)
		case *syntax.ForClause:
			return visitList(compound.Do, maps.Clone(current), nesting+1)
		case *syntax.CaseClause:
			for _, item := range compound.Items {
				if !visitList(item.Stmts, maps.Clone(current), nesting+1) {
					return false
				}
			}
		}
		return true
	}
	return targets, visitList(file.Stmts, values, 0) && !overflow
}

func isKnownEnvDeclaration(command syntax.Command) bool {
	_, ok := command.(*syntax.DeclClause)
	return ok
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
