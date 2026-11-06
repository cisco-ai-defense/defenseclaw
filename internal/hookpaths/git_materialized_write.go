// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// GitMaterializedWrite grades a write made after a Git operation could
// install a new link at that name. The name is only Possible until the Git
// operation runs. The caller combines this grade with any named target it
// already proved; a named target always takes precedence.
func GitMaterializedWrite(input actionfacts.Input, facts actionfacts.Facts) Grade {
	if input.Command == "" || len(input.Command) > MaxPayloadBytes || !filepath.IsAbs(input.CWD) {
		return GradeNone
	}
	commands := actionfacts.SimpleCommands(input, facts)
	if len(commands) == 1 && commands[0].EvaluationFailure == "parse" {
		// The ordered top-level reader can still place a static wrapper
		// such as env -C even when the shell-state reader has no reduction.
		if placed, ok := TopLevelStatements(input.Command, input.CWD, input.ActiveHome); ok {
			commands = make([]actionfacts.SimpleCommand, 0, len(placed))
			for _, statement := range placed {
				commands = append(commands, actionfacts.SimpleCommand{Text: statement.Command, CWD: statement.Dir})
			}
		}
	}
	if len(commands) < 2 {
		return GradeNone
	}
	redirectedTree := false
	if strings.Contains(input.Command, "GIT_WORK_TREE") || strings.Contains(input.Command, "GIT_DIR") {
		redirectedTree = gitRedirectedMaterialization(input.Command, input.CWD, input.ActiveHome)
	}
	var scopes []string
	for _, simple := range commands {
		if simple.EvaluationFailure != "" {
			return GradeNone
		}
		cwd := simple.CWD
		if !filepath.IsAbs(cwd) {
			cwd = input.CWD
		}
		if len(scopes) > 0 && gitMaterializedWriteInScopes(simple.Text, cwd, input.ActiveHome, scopes) {
			return GradePossible
		}
		if scope, materializes := gitSimpleMaterializationScope(simple.Text, cwd, input.ActiveHome); materializes {
			if redirectedTree {
				scope = ""
			}
			scopes = append(scopes, scope)
		}
	}
	return GradeNone
}

// SimpleCommands drops command-local environment assignments after it has
// resolved their values. Retain a redirected Git worktree's unknown scope
// from the complete syntax tree before reading those simple commands.
func gitRedirectedMaterialization(command, cwd, home string) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		if !gitCallRedirectedWorktree(call, home) {
			return true
		}
		words, static := gitCallWords(call, home)
		if run, wrapped := actionfacts.StaticPrefixWrapperChild(words, static); wrapped &&
			run.Index < len(words) && !run.ChangesResolution {
			words, static = words[run.Index:], static[run.Index:]
		}
		if len(words) == 0 || !static[0] || programBase(words[0]) != "git" {
			return true
		}
		_, found = gitMaterializationScope(words[1:], static[1:], cwd)
		return !found
	})
	return found
}

func gitCallRedirectedWorktree(call *syntax.CallExpr, home string) bool {
	for _, assignment := range call.Assigns {
		if assignment.Name != nil && (assignment.Name.Value == "GIT_WORK_TREE" || assignment.Name.Value == "GIT_DIR") {
			return true
		}
	}
	words := make([]string, len(call.Args))
	static := make([]bool, len(call.Args))
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	for i, word := range call.Args {
		words[i], static[i] = staticShellWord(word, env, home != "")
	}
	if run, wrapped := actionfacts.StaticPrefixWrapperChild(words, static); wrapped {
		for _, word := range words[:run.Index] {
			if strings.HasPrefix(word, "GIT_WORK_TREE=") || strings.HasPrefix(word, "GIT_DIR=") {
				return true
			}
		}
	}
	return false
}

func gitCallWords(call *syntax.CallExpr, home string) ([]string, []bool) {
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	words := make([]string, len(call.Args))
	static := make([]bool, len(call.Args))
	for i, word := range call.Args {
		words[i], static[i] = staticShellWord(word, env, home != "")
	}
	if index, wrapped := plainWrappedChild(words, static); wrapped {
		words, static = words[index:], static[index:]
	}
	return words, static
}

func gitSimpleMaterializationScope(command, cwd, home string) (string, bool) {
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 {
		return "", false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	words, static := gitCallWords(call, home)
	if run, wrapped := actionfacts.StaticPrefixWrapperChild(words, static); wrapped &&
		run.Dir != "" && !run.DirUnknown && !run.ChangesResolution &&
		run.Index < len(words) {
		cwd = OperandPath(run.Dir, cwd)
		words, static = words[run.Index:], static[run.Index:]
	}
	if len(words) == 0 || !static[0] || programBase(words[0]) != "git" {
		return "", false
	}
	scope, materializes := gitMaterializationScope(words[1:], static[1:], cwd)
	if !materializes {
		return "", false
	}
	if gitCallRedirectedWorktree(call, home) {
		return "", true
	}
	return scope, true
}

func gitMaterializedWriteInScopes(command, cwd, home string, scopes []string) bool {
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	facts := actionfacts.Analyze(input)
	var writes []string
	for _, path := range facts.Paths {
		if path.Access != actionfacts.PathAccessWrite && path.Access != actionfacts.PathAccessAppend &&
			path.Access != actionfacts.PathAccessDelete {
			continue
		}
		if path.Value != "" {
			writes = append(writes, OperandPath(path.Value, cwd))
		}
	}
	redirects, _, _ := ShellWriteOperands(command, cwd, home)
	writes = append(writes, redirects...)
	writes = append(writes, LiteralWriteOperands(command, cwd, home)...)
	for _, write := range writes {
		for _, scope := range scopes {
			if scope == "" || pathAtOrUnder(write, scope) {
				return true
			}
			if resolved, ok := ResolveWriteTarget(write); ok && pathAtOrUnder(resolved, scope) {
				return true
			}
		}
	}
	return false
}
