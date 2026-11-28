// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// gap1028SequenceSource is a call of the guest timing shapes: a loop of
// declarations, calls and a USER loop, over sequenceMemoMinSource bytes.
func gap1028SequenceSource() string {
	var b strings.Builder
	b.WriteString("for USER in a b; do ")
	for k := 0; b.Len() < 6<<10; k++ {
		n := strconv.Itoa(k)
		b.WriteString("f" + n + "(){ :; }; f" + n + "; touch out" + n + "; ")
	}
	b.WriteString("done; read -r u <<< x; cat ~/.ssh/id_rsa")
	return b.String()
}

// TestGAP1028SequenceSplitIsKeptForLargeSources: one hook splits the same
// large call into its statements many times (the semantic splitter, the
// statement budget, the guest plan); the split of a large source is kept, a
// repeat costs a copy of the statements, not another walk, and every caller
// gets a copy of its own (substrate-1 GAP-1028).
func TestGAP1028SequenceSplitIsKeptForLargeSources(t *testing.T) {
	source := gap1028SequenceSource()
	for _, flags := range [][4]bool{{true, true, false, true}, {true, true, true, false}, {false, false, false, false}} {
		first, reduced, ok := sequenceStatementDetails(source, flags[0], flags[1], flags[2], flags[3])
		again, reducedAgain, okAgain := sequenceStatementDetails(source, flags[0], flags[1], flags[2], flags[3])
		if !reflect.DeepEqual(first, again) || reduced != reducedAgain || ok != okAgain {
			t.Fatalf("flags %v: a repeated split differs", flags)
		}
		if len(first) == 0 {
			continue
		}
		first[0].text = "changed"
		if len(first[0].callStarts) != 0 {
			first[0].callStarts[0] = -1
		}
		third, _, _ := sequenceStatementDetails(source, flags[0], flags[1], flags[2], flags[3])
		if third[0].text == "changed" || len(third[0].callStarts) != 0 && third[0].callStarts[0] == -1 {
			t.Fatalf("flags %v: a caller's change reached another caller's split", flags)
		}
		bound := float64(8*len(again) + 64)
		if allocs := testing.AllocsPerRun(5, func() { sequenceStatementDetails(source, flags[0], flags[1], flags[2], flags[3]) }); allocs > bound {
			t.Fatalf("flags %v: a repeated split of %d statements allocates %.0f times, want at most %.0f (walked again)", flags, len(again), allocs, bound)
		}
	}
}
