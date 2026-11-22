// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package textlower

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/workcount"
)

// TestLowerIsToLower is the oracle of Lower: small and large texts, ASCII
// and the Unicode letters whose lower case changes length or lands in ASCII
// (Kelvin sign, dotted capital I), cold and kept, give strings.ToLower.
func TestLowerIsToLower(t *testing.T) {
	letters := []string{"A", "b", "Z", "K", "İ", "É", "Σ", " ", "\n", "_", "\xff", "MKLINK"}
	rng := rand.New(rand.NewPCG(2, 299))
	for _, size := range []int{0, 10, memoMin - 1, memoMin, memoMin + 7, 1 << 20, memoMax + 1} {
		var text strings.Builder
		for text.Len() < size {
			text.WriteString(letters[rng.IntN(len(letters))])
		}
		value := text.String()
		want := strings.ToLower(value)
		for round := 0; round < 3; round++ {
			if got := Lower(value); got != want {
				t.Fatalf("size %d round %d: Lower differs from strings.ToLower", size, round)
			}
		}
	}
}

// TestLowerCopiesALargeTextOnce is the counted-work bound of Lower
// (rel-1-0-10:GAP-0299): ten readers of one large text make one lower-cased
// copy, a different text makes its own.
func TestLowerCopiesALargeTextOnce(t *testing.T) {
	one, two := strings.Repeat("Echo HI\n", memoMin/8+1), strings.Repeat("Echo HO\n", memoMin/8+1)
	before := workcount.Take()
	for range 10 {
		Lower(one)
		Lower(strings.Clone(one))
	}
	Lower(two)
	if got := before.Since(workcount.TextLower); got != 2 {
		t.Fatalf("lower-cased copies = %d, want 2 (one per distinct text)", got)
	}
}
