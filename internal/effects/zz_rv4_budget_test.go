package effects

import (
	"strings"
	"testing"
	"time"
)

func TestRv4Budget(t *testing.T) {
	for _, n := range []int{1000, 5000, 10000, 20000, 40000} {
		c := strings.Repeat("cd a;", n) + "touch f"
		st := time.Now()
		r := Extract(sh(c), envOpts)
		t.Logf("cd chain %6d len=%7d dur=%v fullyKnown=%v unknowns=%v", n, len(c), time.Since(st).Round(time.Millisecond), r.FullyKnown(), r.Unknowns)
	}
	for _, n := range []int{10000, 25000, 50000} {
		c := strings.Repeat("true;", n) + "touch f"
		st := time.Now()
		r := Extract(sh(c), envOpts)
		t.Logf("true chain %6d dur=%v fullyKnown=%v unknowns=%v", n, time.Since(st).Round(time.Millisecond), r.FullyKnown(), r.Unknowns)
	}
}
