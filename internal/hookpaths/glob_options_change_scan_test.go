// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// globOptionsChangeExpression is the expression the gate of
// globOptionsInCall ran until rel-1-0-10:GAP-0299; globOptionsChangeScan
// answers as it does.
var globOptionsChangeExpression = regexp.MustCompile(`shopt|GLOBIGNORE|BASHOPTS|SHELLOPTS|(^|[;&|(\s])(set\s+[-+]|eval\b|source\b|\.\s)|\bbash\s+[^|;&]*-[Oo]`)

// TestGAP0299GlobOptionsScanMatchesTheExpression: the linear scan of the
// glob-options gate answers exactly as the expression it replaced, on the
// GAP-1613 cases, word-boundary and separator edges, and 200,000 generated
// texts (rel-1-0-10:GAP-0299). A touch -h call with none of its words is
// still not a match (GAP-1613).
func TestGAP0299GlobOptionsScanMatchesTheExpression(t *testing.T) {
	cases := []string{
		"", ".", ". ", "x. ", "x .", "x . y", "shopt -s dotglob; touch *", "GLOBIGNORE=x touch *",
		"BASHOPTS=dotglob bash -c x", "SHELLOPTS=noglob x", "set -f; touch *", "a;set +o noglob", "(eval x)",
		"x|source y", ". ./env; touch *", "a&.\tb", "x\n.\ny", "bash -O dotglob -c x", "bash  -c 'x' -o noglob",
		"touch f0 f1 hlk-home", "touch -h a b", "touch -h f0 f1 f2 hlk-home", "cp a.b c", "settle a", "sh -c x",
		"set", "set ", "set -", "set\t\n+", "xset -f", "_set -f", "(set -f", "eval", "evalx", "eval_", "eval1", "eval-x",
		"eval\xff", "evalé", "éeval", "source", "sources", " source.", "bash -o", "bash", "bash ", "xbash -o", "_bash -o",
		"ébash -o", "\xffbash -o", "bash\t-O", "bash x | -o", "bash x ; y -o", "bash x & -O", "bash bash -o",
		"bash x; bash -o", "bash x bash y -o", "bash x|bash -o", "bashbash -o", "bash-o", "bash\v-o", "a\vset -f",
		"meeting notes: the team agreed on the next steps.\nrow 2\n", "Meeting.\x00next", "x(.\r", "x|eval;",
	}
	pieces := []string{"shopt", "GLOB", "IGNORE", "BASH", "OPTS", "SHELL", "set", "eval", "source", "bash",
		".", " ", "\t", "\n", "\f", "\r", "\v", ";", "&", "|", "(", ")", "-", "+", "O", "o", "x", "_", "1", "é",
		"\xff", "f1", "touch", "-h", "steps.", "-O", "-o"}
	rng := rand.New(rand.NewSource(299))
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for n := rng.Intn(12); n >= 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		cases = append(cases, b.String())
	}
	matched := 0
	for _, text := range cases {
		want := globOptionsChangeExpression.MatchString(text)
		if want {
			matched++
		}
		if got := globOptionsChangeScan(text); got != want {
			t.Fatalf("globOptionsChangeScan(%q) = %t, the expression says %t", text, got, want)
		}
	}
	if matched < 1000 || matched > len(cases)-1000 {
		t.Fatalf("%d of %d texts match: the cases prove little", matched, len(cases))
	}
	if globOptionsChangeScan("touch -h f0 f1 f2 hlk-home") {
		t.Fatal("a touch -h call with no word of the gate is a match")
	}
}
