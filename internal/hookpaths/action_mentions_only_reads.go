// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

// ActionMentionsNoWriteRole reports a command the target scan holds as a
// protected-target only because of words in statements that read a protected
// file (sha256sum KEYS, ls -l KEYS, test -e KEYS) while other statements of
// the same command do other work. The decision itself stays protected-target:
// a compound that reads the keys file beside other work is not the plain read
// the whole-command rule allows. The caller decides what that is worth; an
// action that only reads the file is no write of it (rel-1-0-10:GAP-0018).
//
// A POSIX call whose reader statements are no plain reads under the
// GAP-0570 rules is never such a reading (actionCallKeepsMentions): $_ is the
// last word of the statement before, so it carries the name a reader read
// into another statement (ls KEYS; echo x >> $_ appends to KEYS,
// rel-1-0-10:GAP-0860, GAP-0643); an assignment, a function or a program word
// that is not static can change what a reader runs. Shell text the parser
// cannot read is not proven free of one. ($_ of PowerShell is the pipeline
// item, not a word of another statement.)
func ActionMentionsNoWriteRole(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	if dialect != actionfacts.DialectPowerShell && actionPosixCallKeepsMentions(command, home) {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites = true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}

// actionPosixCallKeepsMentions reports POSIX shell text whose reader
// statements are no plain reads (actionCallKeepsMentions: $_, an assignment, a
// function, an echo of an expansion, a program word that is not static, a
// rebound reader name), or text that does not parse.
func actionPosixCallKeepsMentions(command, home string) bool {
	file, ok := parseShell(command)
	return !ok || actionCallKeepsMentions(file, home)
}
