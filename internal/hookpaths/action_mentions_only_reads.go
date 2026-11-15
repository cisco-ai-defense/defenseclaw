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
