// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"
)

// TestSedStateSpellingsBlockInEveryTier: the in-place readers of active
// DefenseClaw state take the program from the word the parser makes, so a
// split, quoted, escaped, GNU-prefixed or versioned spelling of sed and perl
// blocks as the plain one does (rel-1-0-10:GAP-0737).
func TestSedStateSpellingsBlockInEveryTier(t *testing.T) {
	env, keys := sedBackupBoundEnv(t)
	const block, allow = "block", "allow"
	sed := []struct{ id, word string }{
		{"plain", "sed"}, {"split", "s''ed"}, {"dq", `"s"ed`}, {"bs", `s\ed`},
		{"gsed", "gsed"}, {"gsed-split", "gs''ed"}, {"abs-split", "/usr/bin/s''ed"},
	}
	perl := []struct{ id, word string }{
		{"plain", "perl"}, {"split", "p''erl"}, {"dq", `"perl"`}, {"v5", "perl5.38.2"}, {"split-v", "p''erl5.38.2"},
	}
	var cases []struct{ id, command, want string }
	add := func(id, command, want string) {
		cases = append(cases, struct{ id, command, want string }{id, command, want})
	}
	for _, v := range sed {
		add("STATE-link-sed-"+v.id, "ln -s ~/.defenseclaw hc; "+v.word+" -i s/a/b/ hc/config.yaml", block)
		add("STATE-cd-link-sed-"+v.id, "cd ~ && ln -s .defenseclaw hc && "+v.word+" -i s/a/b/ hc/config.yaml", block)
		add("STATE-direct-follow-"+v.id, v.word+" -i --follow-symlinks s/a/b/ ~/.defenseclaw/config.yaml", block)
		add("STATE-direct-plain-"+v.id, v.word+" -i s/a/b/ ~/.defenseclaw/config.yaml", block)
		add("STATE-benign-link-"+v.id, "ln -s src s; "+v.word+" -i s/a/b/ s/b.txt", allow)
	}
	for _, v := range perl {
		add("STATE-link-perl-"+v.id, "ln -s ~/.defenseclaw hc; "+v.word+" -pi -e s/a/b/ hc/config.yaml", block)
		add("STATE-benign-perl-"+v.id, v.word+" -pi -e s/a/b/ notes.txt", allow)
	}
	runSedBackupTierRows(t, env, keys, cases)
}
