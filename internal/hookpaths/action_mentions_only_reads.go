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
// The excused scan reads a statement as a reader only under the call-level
// GAP-0570 rules (actionCallKeepsMentions: $_ carries the name a reader read
// into another statement, ls KEYS; echo x >> $_, rel-1-0-10:GAP-0860,
// GAP-0643) and when the reading call runs a system program (GAP-0715).
func ActionMentionsNoWriteRole(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites = true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}

// ActionMentionsNoKnownWrite is ActionMentionsNoWriteRole for the unknown
// tier (S7 lead ruling 2026-11-15, rel-1-0-10:GAP-0843): a command that names
// a protected file only in statements that read it, where another statement
// runs a program the scan has no model of (wc -l KEYS && $TOOL > /tmp/r), a
// reader stage hands its output on (cat KEYS | python3 -c "$CODE"), or a
// reader writes its output to a file the call names (cat KEYS > /tmp/k.bak).
// No word of it is a write target that reaches the file; a program the scan
// cannot read could write it as well without the mention, so the mention is
// no proof. $_ and a rebound reader name still hand the name on and keep the
// block (actionCallKeepsMentions).
func ActionMentionsNoKnownWrite(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites, memo.excuseUnknownRoles = true, true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}
