// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// uncertainWriteVerbs are the programs whose operands UncertainWriteReason
// reads: the write and metadata verbs of the GAP-0293 corpus.
var uncertainWriteVerbs = map[string]bool{
	"touch": true, "gtouch": true, "chmod": true, "chown": true, "chgrp": true, "cp": true, "mv": true,
	"ln": true, "tee": true, "truncate": true, "install": true, "sed": true, "gsed": true, "dd": true, "rsync": true,
}

// UncertainWriteReason reports an operand of a write or metadata call that
// the one shell word resolver cannot settle (an unknown variable, a command
// substitution, a glob form it does not model exactly, a glob option the
// call may have changed, a directory it cannot read, a result past its
// bound). It returns "" when every operand is proven, else the
// UnprovenReasonKey class of the first uncertain one (unprovenReasonTitles).
//
// This is the explicit UNCERTAIN result of the resolver (rel-1-0-10
// GAP-0293 round 3): such an operand is not proven to leave the protected
// files alone, so the pack tier decides it (GAP-0350), never a plain allow.
// startup is the agent's shell startup (nil: this process's own).
func UncertainWriteReason(command, cwd, home string, startup *ShellStartup) string {
	return uncertainWriteReason(command, cwd, home, startup, false)
}

// UncertainGlobWriteReason is UncertainWriteReason for the operands whose
// pieces are all known and whose glob reading is what the resolver cannot
// settle: a glob form it does not model, a glob option the call may have
// changed, a directory it cannot read, a result past its bound. An operand
// that holds an unknown variable or a command substitution is left to the
// dynamic-operand proofs of the gateway, which judge it with the whole
// command in view (rel-1-0-10:GAP-0350, GAP-0378, GAP-0379, GAP-0380).
func UncertainGlobWriteReason(command, cwd, home string, startup *ShellStartup) string {
	return uncertainWriteReason(command, cwd, home, startup, true)
}

func uncertainWriteReason(command, cwd, home string, startup *ShellStartup, globOnly bool) string {
	if home == "" || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return ""
	}
	file, parsed := parseShell(command)
	if !parsed {
		return ""
	}
	current := CurrentShellStartup()
	if startup != nil {
		current = *startup
	}
	options := shellGlobOptionsForCall(command, current)
	values := actionValues{"HOME": home, "PWD": cwd}
	reason := ""
	check := func(word *syntax.Word) {
		if reason != "" || word == nil {
			return
		}
		if !globOnly {
			reason = resolveWriteWord(word, values, cwd, options).uncertain
			return
		}
		// Bash expands a brace list into its words first; each is then a plain
		// word or a glob. A list of known alternatives is read word by word, as the
		// shell passes them; a list that is too long is not read.
		split := *word
		split.Parts = append([]syntax.WordPart(nil), word.Parts...)
		syntax.SplitBraces(&split)
		alternatives := expand.Braces(&split)
		if len(alternatives) > 64 {
			return // too long to read: the older tiers judge it
		}
		for _, alternative := range alternatives {
			if !resolverWordKnown(alternative, values) {
				continue
			}
			// Only a word that holds a glob is read here: a known parameter that
			// field-splits into several words, or an option the resolver does not
			// place, is not a glob form and keeps the older tiers' reading.
			if pattern, ok := resolverPattern(alternative, resolverConfig(values, cwd), values["HOME"]); !ok || !resolverPatternActive(pattern) {
				continue
			}
			if reason = resolveWriteWord(alternative, values, cwd, options).uncertain; reason != "" {
				return
			}
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if reason != "" {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		values["PWD"] = cwd
		actionUpdateValues(stmt, values, cwd, home)
		for _, redirect := range stmt.Redirs {
			if actionOutputRedirect(redirect.Op) {
				check(redirect.Word)
			}
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed || !uncertainWriteVerbs[programBase(program)] {
			return true
		}
		if globOnly && (programBase(program) == "sed" || programBase(program) == "gsed") && !sedEditsInPlace(call, home) {
			return true // a sed that does not edit in place writes none of its operands
		}
		for _, word := range call.Args[1:] {
			if text, fixed := StaticWord(word, home); fixed && len(text) > 0 && text[0] == '-' {
				continue // an option
			}
			check(word)
		}
		return true
	})
	return reason
}

// sedEditsInPlace reports a sed call with -i, --in-place or a short option
// cluster that holds i (-ni, -Ei): the only calls that write the files they name.
func sedEditsInPlace(call *syntax.CallExpr, home string) bool {
	for _, arg := range call.Args[1:] {
		text, fixed := StaticWord(arg, home)
		if !fixed {
			// A word with a glob or an expansion is an operand or the script;
			// an option the shell has to expand first could hide an -i, so a
			// word that starts with a dash and is not fixed counts as in place.
			if literal := arg.Lit(); strings.HasPrefix(literal, "-") || len(arg.Parts) > 0 && !isLitPart(arg.Parts[0]) {
				return true
			}
			continue
		}
		if text == "--" {
			return false
		}
		if strings.HasPrefix(text, "--in-place") {
			return true
		}
		if len(text) > 1 && text[0] == '-' && text[1] != '-' && strings.ContainsRune(text[1:], 'i') {
			return true
		}
	}
	return false
}

func isLitPart(part syntax.WordPart) bool {
	_, ok := part.(*syntax.Lit)
	return ok
}
