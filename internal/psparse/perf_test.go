package psparse

import (
	"strings"
	"testing"
	"time"
)

// TestNoSuperlinearBlowup guards against pathological parse times on adversarial
// deeply-nested or long inputs (a hook-path DoS risk). Each must finish well
// under the hook answer window.
func TestNoSuperlinearBlowup(t *testing.T) {
	n := 4000
	cases := map[string]string{
		"subexpr": strings.Repeat("$(", n),
		"hash":    strings.Repeat("@{", n),
		"paren":   strings.Repeat("(", n),
		"brace":   strings.Repeat("{", n),
		"bracket": strings.Repeat("[", n),
		"array":   strings.Repeat("@(", n),
		"amp":     strings.Repeat("& ", n) + "x",
		"pipe":    strings.Repeat("a|", n) + "b",
		"comma":   "x " + strings.Repeat("a,", n) + "b",
		"dollar":  strings.Repeat("${`", n),
	}
	for name, src := range cases {
		start := time.Now()
		_ = Project(mustParse(src, DialectPwsh7))
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%s: %v (too slow, len=%d)", name, d, len(src))
		}
	}
}
