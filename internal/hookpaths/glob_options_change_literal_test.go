// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"strings"
	"testing"
)

// The literal pre-check of globOptionsChangeText never answers no for a
// command the expression matches (rel-1-0-10:GAP-1613): it only leaves out
// the scan of a call that holds none of its literals.
func TestGAP1613GlobOptionsLiteralCheckKeepsEveryMatch(t *testing.T) {
	cases := []string{
		"shopt -s dotglob; touch *", "GLOBIGNORE=x touch *", "BASHOPTS=dotglob bash -c x",
		"SHELLOPTS=noglob x", "set -f; touch *", "a;set +o noglob", "(eval x)", "x|source y",
		". ./env; touch *", "a&.\tb", "x\n.\ny", "bash -O dotglob -c x", "bash  -c 'x' -o noglob",
		"touch f0 f1 hlk-home", "touch -h a b", "cp a.b c", "settle a", "sh -c x",
	}
	pieces := []string{"shopt", "GLOB", "IGNORE", "BASH", "OPTS", "SHELL", "set", "eval", "source", "bash",
		".", " ", "\t", "\n", "\f", "\r", ";", "&", "|", "(", "-", "+", "O", "o", "x", "f1", "touch", "-h"}
	rng := rand.New(rand.NewSource(1613))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(8); n >= 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		cases = append(cases, b.String())
	}
	matched := 0
	for _, command := range cases {
		if globOptionsChangeText.MatchString(command) {
			matched++
			if !globOptionsChangeTextMayMatch(command) {
				t.Fatalf("pre-check says no for a matching command %q", command)
			}
		}
	}
	if matched < 100 {
		t.Fatalf("only %d generated commands match: the check proves little", matched)
	}
	if globOptionsChangeTextMayMatch("touch -h f0 f1 f2 hlk-home") {
		t.Fatal("a touch -h call with no literal of the expression is scanned")
	}
}
