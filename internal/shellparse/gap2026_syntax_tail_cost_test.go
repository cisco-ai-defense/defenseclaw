// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10:GAP-2026: the longer reading of GAP-0745 parsed the text from
// every start piece to its end and charged the budget only up to the error,
// which for an opener the text never closes is the opener: a close paren, K
// lines of an open brace and an echo of N bytes cost K times N (50 KB, K =
// 400: 2.4 s against 0.06 s in T21f). Its cost is linear: the reading of
// K = 400 with N = 50 KB is within a small factor of the sum of the reading
// of K = 400 with a short echo and of K = 4 with N = 50 KB (the window
// reading alone costs K pieces, and the echo costs N; a run under -race
// slows all three alike).
func TestSyntaxTailLongReadingCostIsLinear(t *testing.T) {
	cost := func(k, n int) time.Duration {
		best := time.Duration(1 << 62)
		for range 3 {
			command := ")\n" + strings.Repeat("{\n", k) + " echo " + strings.Repeat("a", n) + "\n"
			began := time.Now()
			// readSyntaxTail: the memo of ReadSyntaxTail would answer the
			// second try.
			if _, ok := readSyntaxTail(command); !ok {
				t.Fatalf("K=%d N=%d: not read", k, n)
			}
			best = min(best, time.Since(began))
		}
		return best
	}
	pieces, length, both := cost(400, 8), cost(4, 50<<10), cost(400, 50<<10)
	if both > 3*(pieces+length)+50*time.Millisecond {
		t.Errorf("K=400 N=50K took %v against %v (K=400 N=8) and %v (K=4 N=50K): the longer reading is not linear in the text",
			both, pieces, length)
	}
}

// rel-1-0-10:GAP-2027: the statements of the longer reading took slots of
// the statement cap of the 1.0.10 window reading. A syntax error, 20 long
// while loops (each also read piece by piece by the window) and a trailing
// command hit the cap, so the text was TRUNCATED and the trailing command
// went unread, where T21f read it untruncated. The longer reading counts its
// statements on a bound of its own.
func TestSyntaxTailExtendedReadingsKeepTheWindowCap(t *testing.T) {
	loop := "while :; do true; true; true; true; true; true; true; done\n)\n"
	command := ")\n" + strings.Repeat(loop, 20) + "touch notes.txt"
	tail, ok := readSyntaxTail(command)
	if !ok || tail.Truncated.Any() || !slices.Contains(tail.Statements, "touch notes.txt") || len(tail.Extended) == 0 {
		t.Errorf("ok %v truncated %q statements %d extended %d, want the loops read whole, the trailing command read and no cap",
			ok, tail.Truncated.Reason(), len(tail.Statements), len(tail.Extended))
	}
}
