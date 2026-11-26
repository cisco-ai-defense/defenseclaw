// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
)

func perlSpecInvariant(t *testing.T, code string) {
	t.Helper()
	base := literalInterpreterWritesBase(code, "perl", "/tmp", "/tmp")
	head := literalInterpreterWrites(code, "perl", "/tmp", "/tmp")
	for _, path := range base {
		if !slices.Contains(head, path) {
			t.Fatalf("rel operand %q missing from head %v", path, head)
		}
	}
	tokens, complete := perlLex(code)
	if complete {
		_, complete = perlBlockContexts(tokens)
	}
	if !complete && !slices.Equal(base, head) {
		t.Fatalf("incomplete program changed rel operands: rel=%v head=%v", base, head)
	}
}

func FuzzPerlSpecNeverBelowRel(f *testing.F) {
	for _, seed := range []string{
		`unlink(".claude/settings.json");`,
		`open(F,">.claude/settings.json");`,
		`sysopen(F,".claude/settings.json",1);`,
		`__END__
unlink(".claude/settings.json");`,
		`sub helper { $flags=1 }; sysopen(F,".claude/settings.json",$flags);`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, code string) {
		if len(code) > 16<<10 {
			return
		}
		perlSpecInvariant(t, code)
	})
}

func TestPerlSpecNeverBelowRelRandom300K(t *testing.T) {
	rng := rand.New(rand.NewSource(592))
	fragments := []string{
		`unlink(".claude/settings.json");`, `open(F,">.claude/settings.json");`,
		`sysopen(F,".claude/settings.json",1);`, `open(F,"<",".claude/settings.json");`,
		`sub helper { $flags=1 };`, `my $mode=">";`, `eval "x";`,
		`# comment
`, `print "data";`, `BEGIN { 1 };`, `{ `, ` }`, `;`,
	}
	for i := 0; i < 300000; i++ {
		var b strings.Builder
		n := 1 + rng.Intn(5)
		for j := 0; j < n; j++ {
			b.WriteString(fragments[rng.Intn(len(fragments))])
		}
		if i%4 == 0 {
			for j := 0; j < rng.Intn(15); j++ {
				b.WriteByte(byte(32 + rng.Intn(95)))
			}
		}
		perlSpecInvariant(t, b.String())
	}
}
