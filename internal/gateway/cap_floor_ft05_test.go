// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-10:GAP-1025. The reading taken at a quote that STARTS a word ends in
// the previous word, so it cannot stand for the word that grows from there:
// bash --rcfile=/x '-'c'true' reads -c as an option word in a fresh reading
// of the prefix, while the reused reading (last argument --rcfile=/x) ruled a
// shell -c out. Only a reading that ends inside the growing word is reused.
func TestGAP1025CapFloorWordStartReadingIsNotReused(t *testing.T) {
	for _, command := range []string{
		"bash --rcfile=/x '-'c'true'",
		"echo a;bash --rcfile=/x '-'c'true'",
		"x=1 bash --rcfile=/x '-'c'true'",
	} {
		reader := &capFloorConsumerReader{budget: capFloorConsumerBytes}
		pieces := capFloorCut(command, reader, 0, len(command))
		found := false
		for _, piece := range pieces {
			if piece.body == "true" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no script piece for the quote after a joined -c", command)
		}
		if reader.unread {
			t.Errorf("%q: unexpected budget refusal", command)
		}
	}
}

// rel-1-0-10:GAP-0897. A word whose first path segment is not a plain name
// (@/x, +/x, ,/x) may name something outside the project; a plain name and a
// dot path do not.
func TestGAP0897CapFloorMayLeaveNonNamePrefix(t *testing.T) {
	env := boundedLaneEnv(t)
	region := &capFloorRegion{walk: true, cwd: env.cwd, home: env.home, paths: map[string]capFloorPathKind{}}
	for text, want := range map[string]bool{
		"cat src/a":  false,
		"cat ./a/b":  false,
		"cat _x/y":   false,
		"cat @/x":    true,
		"cat +/x":    true,
		"cat ,/x":    true,
		"cat =/x":    true,
		"cat /x/y":   true,
		"cat -f/x/y": true,
	} {
		if got := region.mayLeave(text); got != want {
			t.Errorf("mayLeave(%q) = %v, want %v", text, got, want)
		}
	}
}
