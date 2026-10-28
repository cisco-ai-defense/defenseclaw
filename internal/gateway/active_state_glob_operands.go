// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// activeStateTreeNames are the protected trees directly under the state
// root; every entry in one is protected state (matchesActiveDefenseClawState).
var activeStateTreeNames = []string{
	"cache", "hooks", "installer", "policies", "previous", "quarantine", "receipts", "registries",
}

// activeStateFileNames are the protected files directly under the state root.
var activeStateFileNames = []string{
	".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
	"device.key", "picked_connector", "custom-providers.json", "audit.db",
	"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal", "judge.db-shm",
	"judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm",
}

// maxStateBraceExpansions bounds the brace alternatives one operand expands to.
const maxStateBraceExpansions = 64

// globbedStateMutation proves a removal, move or overwrite of the active
// state through an operand the shell expands before the program runs: a
// pathname pattern (`rm -rf ~/.defenseclaw/*`, `~/.defenseclaw/instal*`,
// `~/.defenseclaw/hooks/*`), a brace list (`~/.defenseclaw/{installer,hooks}`),
// a pattern copied into the state root (`cp /tmp/x/* ~/.defenseclaw/`), an
// rsync into it, and a git clean of it (GAP-2047). ActionFacts keeps such a
// word only as its static spelling, so these calls had no path fact and ran
// in every mode. A pattern counts when it could match a protected name (the
// shell's own matching, a leading dot only by an explicit dot); log and
// temp cleanup such as `rm ~/.defenseclaw/*.log` or
// `rm ~/.defenseclaw/logs/*` matches none and stays allowed.
func globbedStateMutation(facts actionfacts.Facts) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return false
	}
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectPreview || command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		words, ok := stateOperandWords(command)
		if !ok {
			continue
		}
		if globbedStateCommandMutates(command, words, home, facts.CWD) {
			return true
		}
	}
	return false
}

// stateOperandWords returns the static spelling of each argument after the
// program word ("" for a word with no static spelling).
func stateOperandWords(command actionfacts.CommandFact) ([]string, bool) {
	if len(command.Arguments) == 0 || len(command.Arguments) != len(command.Argv) {
		return nil, false
	}
	words := make([]string, 0, len(command.Arguments)-1)
	for _, argument := range command.Arguments[1:] {
		value := argument.Value
		if value == "" {
			value = argument.StaticGlob
		}
		words = append(words, value)
	}
	return words, true
}

func globbedStateCommandMutates(command actionfacts.CommandFact, words []string, home, cwd string) bool {
	operands, options := splitStateOperands(words)
	expanded := func(word string) bool { return stateWordExpands(word) }
	switch strings.ToLower(command.Program) {
	case "rm", "unlink", "rmdir", "shred":
		for _, operand := range operands {
			if expanded(operand) && statePatternReaches(operand, home, cwd) {
				return true
			}
		}
	case "mv", "cp":
		destination, sources := copyMoveStateOperands(operands, options)
		if command.Program == "mv" {
			for _, source := range sources {
				if expanded(source) && statePatternReaches(source, home, cwd) {
					return true
				}
			}
		}
		if destination == "" {
			return false
		}
		for _, source := range sources {
			if expanded(source) && stateLandingReached(destination, path.Base(source), home, cwd) {
				return true
			}
		}
		if expanded(destination) {
			for _, source := range sources {
				if stateLandingReached(destination, path.Base(strings.TrimRight(source, "/")), home, cwd) {
					return true
				}
			}
		}
	case "rsync":
		if len(operands) < 2 {
			return false
		}
		destination := operands[len(operands)-1]
		if strings.Contains(destination, ":") {
			return false
		}
		deletes := false
		for _, option := range options {
			if strings.HasPrefix(option, "--del") || strings.HasPrefix(option, "--remove-source-files") {
				deletes = true
			}
		}
		tree, root := stateDirectoryOf(destination, home, cwd)
		return tree || root && deletes
	case "git":
		index := slices.Index(operands, "clean")
		if index < 0 || !slices.ContainsFunc(options, gitCleanForces) ||
			slices.ContainsFunc(options, gitCleanDryRun) {
			return false
		}
		for _, operand := range operands[index+1:] {
			if tree, root := stateDirectoryOf(operand, home, cwd); tree || root ||
				statePatternReaches(operand, home, cwd) {
				return true
			}
		}
	}
	return false
}

func gitCleanForces(option string) bool {
	return option == "--force" || len(option) > 1 && option[0] == '-' && option[1] != '-' && strings.ContainsRune(option, 'f')
}

func gitCleanDryRun(option string) bool {
	return option == "--dry-run" || len(option) > 1 && option[0] == '-' && option[1] != '-' && strings.ContainsRune(option, 'n')
}

// splitStateOperands separates option words from operands; "--" ends the
// options. An option's value is not told apart from an operand, which only
// widens the words a pattern check reads.
func splitStateOperands(words []string) (operands, options []string) {
	optionsDone := false
	for _, word := range words {
		switch {
		case optionsDone:
			operands = append(operands, word)
		case word == "--":
			optionsDone = true
		case strings.HasPrefix(word, "-") && word != "-":
			options = append(options, word)
		default:
			operands = append(operands, word)
		}
	}
	return operands, options
}

// copyMoveStateOperands returns the destination and the sources of a cp or
// mv: the -t/--target-directory value, else the last operand.
func copyMoveStateOperands(operands, options []string) (string, []string) {
	for _, option := range options {
		if value, ok := strings.CutPrefix(option, "--target-directory="); ok {
			return value, operands
		}
		if value, ok := strings.CutPrefix(option, "-t"); ok && value != "" {
			return value, operands
		}
	}
	if len(operands) < 2 {
		return "", nil
	}
	return operands[len(operands)-1], operands[:len(operands)-1]
}

// stateWordExpands reports a word with a pathname pattern or a brace list.
func stateWordExpands(word string) bool {
	return strings.ContainsAny(word, "*?[") || len(expandStateBraces(word)) > 1
}

// stateHomePath places a word: a leading ~ is the active home, a relative
// word is under cwd. ok is false for a word with no static spelling.
func stateHomePath(word, home, cwd string) (string, bool) {
	switch {
	case word == "":
		return "", false
	case word == "~":
		return home, true
	case strings.HasPrefix(word, "~/"):
		return home + word[1:], true
	case strings.HasPrefix(word, "~"):
		return "", false
	case strings.HasPrefix(word, "/"):
		return word, true
	case strings.HasPrefix(cwd, "/"):
		return strings.TrimRight(cwd, "/") + "/" + word, true
	}
	return "", false
}

// stateRelativeComponents returns the path components of word under the
// state root (".defenseclaw" first), one entry per expanded brace form.
func stateRelativeComponents(word, home, cwd string) [][]string {
	var out [][]string
	for _, form := range expandStateBraces(word) {
		full, ok := stateHomePath(form, home, cwd)
		if !ok {
			continue
		}
		full = path.Clean(full)
		relative, within := strings.CutPrefix(full, home+"/")
		if !within || relative == "" {
			continue
		}
		out = append(out, strings.Split(relative, "/"))
	}
	return out
}

// statePatternReaches reports a (possibly globbed) operand that can name
// the state root, a protected tree or anything in one, or a protected file.
func statePatternReaches(word, home, cwd string) bool {
	for _, components := range stateRelativeComponents(word, home, cwd) {
		if !shellComponentMatches(components[0], ".defenseclaw") {
			continue
		}
		if len(components) == 1 {
			return true
		}
		for _, name := range activeStateTreeNames {
			if shellComponentMatches(components[1], name) {
				return true
			}
		}
		if len(components) == 2 {
			for _, name := range activeStateFileNames {
				if shellComponentMatches(components[1], name) {
					return true
				}
			}
		}
	}
	return false
}

// stateDirectoryOf reports whether a directory operand is (in) a protected
// tree, or is the state root itself.
func stateDirectoryOf(word, home, cwd string) (tree, root bool) {
	for _, components := range stateRelativeComponents(word, home, cwd) {
		if !shellComponentMatches(components[0], ".defenseclaw") {
			continue
		}
		if len(components) == 1 {
			root = true
			continue
		}
		for _, name := range activeStateTreeNames {
			if shellComponentMatches(components[1], name) {
				tree = true
			}
		}
	}
	return tree, root
}

// stateLandingReached reports a copy or move of a source named like base
// into destination that lands on protected state: anything into a
// protected tree, or a name into the root that can be a protected one.
func stateLandingReached(destination, base, home, cwd string) bool {
	tree, root := stateDirectoryOf(destination, home, cwd)
	if tree {
		return true
	}
	if !root {
		return false
	}
	for _, form := range expandStateBraces(base) {
		for _, name := range append(slices.Clone(activeStateTreeNames), activeStateFileNames...) {
			if shellComponentMatches(form, name) {
				return true
			}
		}
	}
	return false
}

// shellComponentMatches matches one path component as the shell expands a
// pattern: a leading dot of a name matches only an explicit dot. A
// malformed pattern counts as a match.
func shellComponentMatches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") {
		return false
	}
	matched, err := path.Match(pattern, name)
	return matched || err != nil
}

// expandStateBraces expands bash brace lists ({a,b}, nested) of a word; a
// word with none, or more than maxStateBraceExpansions forms, is returned
// unchanged.
func expandStateBraces(word string) []string {
	forms := []string{word}
	for range maxStateBraceExpansions {
		changed := false
		var next []string
		for _, form := range forms {
			prefix, alternatives, suffix, ok := firstBraceList(form)
			if !ok {
				next = append(next, form)
				continue
			}
			changed = true
			for _, alternative := range alternatives {
				next = append(next, prefix+alternative+suffix)
			}
		}
		if !changed {
			return forms
		}
		if len(next) > maxStateBraceExpansions {
			return []string{word}
		}
		forms = next
	}
	return forms
}

// firstBraceList finds the first {x,y,...} group with a top-level comma.
func firstBraceList(word string) (prefix string, alternatives []string, suffix string, ok bool) {
	for start := 0; start < len(word); start++ {
		if word[start] != '{' {
			continue
		}
		depth, last := 0, start+1
		var parts []string
		for end := start; end < len(word); end++ {
			switch word[end] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if len(parts) == 0 {
						end = len(word)
						break
					}
					parts = append(parts, word[last:end])
					return word[:start], parts, word[end+1:], true
				}
			case ',':
				if depth == 1 {
					parts = append(parts, word[last:end])
					last = end + 1
				}
			}
		}
	}
	return "", nil, "", false
}
