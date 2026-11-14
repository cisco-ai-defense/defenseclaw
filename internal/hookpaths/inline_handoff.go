// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// inlineInterpreterNames are the substrings a command holds when it can run
// an inline-code interpreter (actionfacts.InlineCodeHandedFrom).
var inlineInterpreterNames = []string{"python", "pypy", "node", "bun", "ruby", "php"}

// inlineHandedWords returns the words of a call that follow the code of an
// inline-code interpreter child (python -c CODE ARG...): the words it is
// handed, fixed or not, and whether a runner (xargs, parallel) feeds it more
// at run time (actionfacts.InlineCodeHandedFrom is the one rule). handsIn is
// false for a call that is no such child.
func inlineHandedWords(words []*syntax.Word, home string) (handed []*syntax.Word, fed, handsIn bool) {
	static := make([]string, len(words))
	for i, word := range words {
		value, fixed := StaticWord(word, home)
		if !fixed {
			value = "$"
		}
		static[i] = value
	}
	from, fed := actionfacts.InlineCodeHandedFrom(static)
	if from < 0 {
		return nil, false, false
	}
	return words[from:], fed, true
}

// InlineHandedPaths returns the absolute paths a command hands to an inline-code
// interpreter child as arguments (python -c CODE PATH): each is a path the
// code may write, since no reader proves the code read-only
// (rel-1-0-10:GAP-0365). The words are read with the values the command
// binds before the call (a variable-bound target), through shell -c bodies,
// and dynamic reports a hand-off of a word with no fixed value ("$f" of a
// while read or xargs loop), whose value only the runner knows.
func InlineHandedPaths(command, cwd, home string) (paths []string, dynamic bool) {
	if !filepath.IsAbs(cwd) || !containsAny(command, inlineInterpreterNames) {
		return nil, false
	}
	file, ok := parseShell(command)
	if !ok {
		return nil, false
	}
	paths, dynamic = inlineHandedPathsIn(file, cwd, home, 0)
	// A relative word is read in the folder a cd of the list leads to.
	if strings.Contains(command, "cd") || strings.Contains(command, "pushd") {
		if statements, placed := TopLevelStatements(command, cwd, home); placed && len(statements) > 1 {
			for _, statement := range statements {
				more, unknown := InlineHandedPaths(statement.Command, statement.Dir, home)
				paths, dynamic = append(paths, more...), dynamic || unknown
			}
		}
	}
	return paths, dynamic
}

// inlineShells are the shells whose -c body is read as a command of its own.
var inlineShells = []string{"sh", "bash", "dash", "ash", "zsh", "ksh"}

// CommandMentionsPath reports a command that spells the path as a whole path
// (with ~ and $HOME read as home), for a hand-off whose word only a runner
// knows.
func CommandMentionsPath(command, home, name string) bool {
	return registrationMentions(registrationHomeText(command, home), name, false)
}

// inlineWordValue is the text of a word: its static spelling, else the value
// the command binds, else "$" (a word only the runner knows).
func inlineWordValue(word *syntax.Word, values actionValues, cwd, home string) string {
	if value, fixed := StaticWord(word, home); fixed {
		return value
	}
	if value, fixed := actionWordValue(word, values, cwd, home); fixed {
		return value
	}
	return "$"
}

func containsAny(text string, names []string) bool {
	for _, name := range names {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

func inlineHandedPathsIn(file *syntax.File, cwd, home string, depth int) (paths []string, dynamic bool) {
	values := actionValues{"HOME": home, "PWD": cwd}
	for _, top := range file.Stmts {
		syntax.Walk(top, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			words := make([]string, len(call.Args))
			for i, arg := range call.Args {
				words[i] = inlineWordValue(arg, values, cwd, home)
			}
			if child, _ := actionfacts.InlineChild(words); len(child) > 1 && depth < 4 && slices.Contains(inlineShells, programBase(child[0])) {
				if body, shell := shellCommandBodyIndex(child); shell {
					if inner, ok := parseShell(child[body]); ok {
						more, unknown := inlineHandedPathsIn(inner, cwd, home, depth+1)
						paths, dynamic = append(paths, more...), dynamic || unknown
					}
					return true
				}
			}
			from, fed := actionfacts.InlineCodeHandedFrom(words)
			if from < 0 {
				return true
			}
			dynamic = dynamic || fed
			for _, word := range words[from:] {
				switch {
				case word == "$" || strings.Contains(word, "{}"):
					dynamic = true
				case actionfacts.InlineHandedWordIsPath(word):
					paths = append(paths, OperandPath(word, cwd))
				}
			}
			return true
		})
		actionUpdateValues(top, values, cwd, home)
	}
	return paths, dynamic
}
