// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// ActionMentionsNoWriteRole reports a command the target scan holds as a
// protected-target only because of words in statements that read a protected
// file (sha256sum KEYS, ls -l KEYS, test -e KEYS) while other statements of
// the same command do other work. The decision itself stays protected-target:
// a compound that reads the keys file beside other work is not the plain read
// the whole-command rule allows. The caller decides what that is worth; an
// action that only reads the file is no write of it (rel-1-0-10:GAP-0018).
//
// A command that names $_ is never such a reading: $_ is the last word of the
// statement before, so it carries the name a reader statement read into the
// role of another statement (ls KEYS; echo x >> $_ appends to KEYS), which
// the per-statement excuse cannot see (rel-1-0-10:GAP-0860). Shell text the
// parser cannot read is not proven free of one. ($_ of PowerShell is the
// pipeline item, not a word of another statement.)
func ActionMentionsNoWriteRole(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	if dialect != actionfacts.DialectPowerShell && actionNamesLastArgument(command) {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites = true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}

// actionNamesLastArgument reports shell text that expands $_ (also ${_} and
// inside quotes, here-documents or substitutions), or that does not parse.
func actionNamesLastArgument(command string) bool {
	file, ok := parseShell(command)
	if !ok {
		return true
	}
	names := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if expansion, isParam := node.(*syntax.ParamExp); isParam && expansion.Param != nil && expansion.Param.Value == "_" {
			names = true
		}
		return !names
	})
	return names
}
