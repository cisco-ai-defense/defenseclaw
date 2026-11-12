// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// referenceProvesLiteralPath and referencePosixExpandsTilde are the scans of
// every argument and redirect the per-command index replaced (GAP-0483).
func referenceProvesLiteralPath(command CommandFact, fact PathFact) bool {
	matched := false
	static := true
	for _, argument := range command.Arguments {
		if argument.Value != fact.Value {
			continue
		}
		matched = true
		static = static && !argument.Expands
	}
	for _, redirect := range command.Redirects {
		if redirect.Target != fact.Value || redirect.Access != fact.Access {
			continue
		}
		matched = true
		static = static && !redirect.Expands
	}
	return matched && static
}

func referencePosixExpandsTilde(command CommandFact, fact PathFact) bool {
	matched := false
	expands := true
	for _, argument := range command.Arguments {
		if argument.Value == "" && argument.Expands &&
			argument.Quote == QuoteNone && argument.StaticGlob == fact.Value &&
			strings.HasPrefix(fact.Value, "~/") &&
			!strings.ContainsAny(fact.Value, "*?[") {
			matched = true
			continue
		}
		if argument.Value != fact.Value {
			continue
		}
		matched = true
		expands = expands &&
			!argument.Expands &&
			argument.Quote == QuoteNone &&
			!argument.literalTilde
	}
	for _, redirect := range command.Redirects {
		if redirect.Target != fact.Value || redirect.Access != fact.Access {
			continue
		}
		matched = true
		expands = false
	}
	return matched && expands
}

func TestCommandPathIndexAnswersLikeAScanOfTheCommand(t *testing.T) {
	t.Parallel()
	commands := []string{
		"touch a b a",
		"touch ~/a ~/b",
		"touch \x27~/a\x27 ~/a",
		"touch \\~/a",
		"sudo touch \x27~/a\x27",
		"cat < ~/x > ~/x",
		"echo hi > ~/x; echo hi >> out.txt",
		"cp a b > b",
		"ls $HOME/x ~/* \"$X\" a$Y",
		"env X=~/a touch ~/a",
		"touch ~/a ~/a*",
	}
	for _, command := range commands {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/work", ActiveHome: "/home/u"})
		byID := map[int64]CommandFact{}
		for _, c := range facts.Commands {
			byID[c.ID] = c
		}
		for _, fact := range facts.Paths {
			c, ok := byID[fact.CommandID]
			if !ok {
				continue
			}
			index := newCommandPathIndex(&c)
			if got, want := index.provesLiteralPath(fact), referenceProvesLiteralPath(c, fact); got != want {
				t.Errorf("%q %q: literal path got %v want %v", command, fact.Value, got, want)
			}
			if got, want := index.posixExpandsTilde(fact), referencePosixExpandsTilde(c, fact); got != want {
				t.Errorf("%q %q: tilde got %v want %v", command, fact.Value, got, want)
			}
		}
	}
}
