// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"
)

// TestBoundRuleSedBackupBraceProgram: a program word that is a brace list
// past the brace caps is a word the reader cannot expand; the call is at
// least the unknown tier, as the same call with a small list blocks
// (rel-1-0-10:GAP-0739). A run-time program from a plain variable keeps its
// verdict (other layers judge it).
func TestBoundRuleSedBackupBraceProgram(t *testing.T) {
	env, keys := sedBackupBoundEnv(t)
	const unresolved, block, allow = "unresolved", "block", "allow"
	cases := []struct{ id, command, want string }{
		{"BND-b7-cmd-brace-small", "{sed,-i{keys}/*,s/x/y/,authorized_keys}", block},
		{"BND-b7-cmd-brace-oversize", "{sed,-i{keys}/*,s/x/y/,authorized_keys,{1..300}}", unresolved},
		{"BND-b7-cmd-brace-oversize-benign", "{sed,-i.bak,s/x/y/,f,{1..300}}", unresolved},
		{"BND-b7-cmd-brace-small-benign", "{sed,-i.bak,s/x/y/,f}", allow},
		{"BND-b7-cmd-var-program", `"$ED" -i.bak s/x/y/ f`, allow},
	}
	runSedBackupTierRows(t, env, keys, cases)
}
