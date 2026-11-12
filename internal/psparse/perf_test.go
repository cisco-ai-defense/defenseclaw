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

// TestNestedStringScaling guards F12: nested "$( ... )" inside expandable
// strings must stay near-linear. A ~100 KB deeply nested string must parse
// well under the hook window.
func TestNestedStringScaling(t *testing.T) {
	// depth chosen so the source is ~100 KB (each level adds about 5 bytes).
	depth := 20000
	var b strings.Builder
	b.WriteString("Write-Output ")
	for i := 0; i < depth; i++ {
		b.WriteString(`"$(`)
	}
	b.WriteString("x")
	for i := 0; i < depth; i++ {
		b.WriteString(`)"`)
	}
	src := b.String()
	start := time.Now()
	sc, _ := Parse(src, Options{})
	_ = Project(sc)
	_ = ExtractNestedScripts(sc)
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("nested string len=%d parsed in %v (> 50ms)", len(src), d)
	}
}
