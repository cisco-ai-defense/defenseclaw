// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// findGlobStateMutation judges a find whose words include an unquoted
// static glob (GAP-2498: `find ~/.defenseclaw/hooks -name t9d* -delete`).
// ActionFacts keeps such a command partial, with no path fact even for its
// start, so it ran in every mode while the quoted spelling was denied. find
// receives its pattern, action and option words as argv, and an unmatched
// glob stays literal, so the command is judged as the same argv with every
// word after the start points quoted: the quoted spelling's facts. A start
// point that is itself a pattern, a word with no static spelling and a
// wrapped find are left to the other checks.
func findGlobStateMutation(facts actionfacts.Facts, command actionfacts.CommandFact, cwd string) bool {
	if !strings.EqualFold(command.Program, "find") || command.ArgvComplete || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || len(command.Arguments) < 2 || len(command.Arguments) != len(command.Argv) {
		return false
	}
	text, ok := findQuotedPatternText(command.Arguments)
	if !ok {
		return false
	}
	requoted := actionfacts.Analyze(actionfacts.Input{
		Tool: "Bash", Command: text, CWD: cwd, ActiveHome: facts.ActiveHome,
		ActiveAgentFiles: facts.ActiveAgentFiles,
	})
	if requoted.Parse.Status != actionfacts.StatusComplete || len(requoted.Commands) != 1 {
		return false
	}
	return activeStatePathsMutate(requoted)
}

// findQuotedPatternText is the find command text with the start points as
// written (a tilde still expands) and every later word single-quoted.
func findQuotedPatternText(arguments []actionfacts.ArgumentFact) (string, bool) {
	parts := []string{"find"}
	globbed := false
	starts := true
	for _, argument := range arguments[1:] {
		word := argument.Value
		if word == "" {
			if argument.StaticGlob == "" {
				return "", false
			}
			word = argument.StaticGlob
		}
		if starts && (strings.HasPrefix(word, "-") || word == "(" || word == "!") &&
			word != "-H" && word != "-L" && word != "-P" {
			starts = false
		}
		if starts {
			if argument.Value == "" {
				if strings.ContainsAny(word, "*?[") {
					return "", false
				}
				parts = append(parts, word)
				continue
			}
			parts = append(parts, findShellQuote(word))
			continue
		}
		if argument.Value == "" {
			globbed = true
		}
		parts = append(parts, findShellQuote(word))
	}
	return strings.Join(parts, " "), globbed
}

func findShellQuote(word string) string {
	return "'" + strings.ReplaceAll(word, "'", "'\\''") + "'"
}
