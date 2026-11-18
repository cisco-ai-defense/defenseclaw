// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// Attribution of a refusal (GAP-0257, GAP-0300).
func TestGAP0257RefusedSegmentsUnit(t *testing.T) {
	insp := &covInspector{}
	p := &GuardrailProxy{inspector: insp}
	block := &ScanVerdict{Action: "block"}
	bad := "say " + covMarker
	equal := func(a, b []string) bool { return fmt.Sprint(a) == fmt.Sprint(b) }
	for _, tc := range []struct {
		name          string
		v             *ScanVerdict
		current, turn []string
		fresh         []string
		want          []string
		probes        int
	}{
		{"not a guardrail block (audit closed)", &ScanVerdict{Action: "allow"}, []string{bad}, []string{bad}, nil, nil, 0},
		{"no current turn", block, []string{"sys " + covMarker}, nil, nil, []string{"sys " + covMarker}, 0},
		{"one current turn, no probe (one AI Defense call)", block, []string{"sys", bad}, []string{bad}, nil, []string{bad}, 0},
		{"blamed among co-turns", block, []string{"sys", "ok", bad, "fine"}, []string{"ok", bad, "fine"}, nil, []string{bad}, 3},
		{"no co-turn blamed alone", block, []string{"sys " + covMarker, "ok", "fine"}, []string{"ok", "fine"}, nil, []string{"sys " + covMarker, "ok", "fine"}, 2},
		// GAP-0300: a text first seen as history is a candidate; the benign
		// current turn is not blamed. Every blame is inspected (substrate-1
		// GAP-0308): current turns 1, fresh history with them 1, one
		// binary-search step 1.
		{"fresh history blamed, not the current turn", block, []string{"Say OK."}, []string{"Say OK."}, []string{"the notes say " + covMarker, "Summarize the notes."},
			[]string{"the notes say " + covMarker}, 3},
		{"newest history blamed, the oldest inspected too", block, []string{"Say OK."}, []string{"Say OK."}, []string{"Summarize the notes.", "the notes say " + covMarker},
			[]string{"the notes say " + covMarker}, 3},
		{"the current turns block alone: history not blamed", block, []string{bad}, []string{bad}, []string{"older"}, []string{bad}, 1},
		{"one fresh history segment that blocks with the current turn", block, []string{"Say OK."}, []string{"Say OK."}, []string{"older " + covMarker}, []string{"older " + covMarker}, 2},
		// Nothing fresh blocks (the refusal came from text inspected on every
		// request or seen before): the fail safe, current scope and fresh
		// history; no blame by elimination (GAP-0308).
		{"one fresh history segment that does not block: fail safe", block, []string{"sys", "Say OK."}, []string{"Say OK."}, []string{"older"}, []string{"sys", "Say OK.", "older"}, 2},
		{"too many current turns", block, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, nil,
			[]string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, 0},
		// 15 fresh segments, one group each (up to 64 with a current turn):
		// current 1, all fresh 1, binary search 4: 6 calls, never over 8, and
		// only the segment that holds the refused text is blamed.
		{"fifteen fresh history segments: binary search", block, []string{"now"}, []string{"now"},
			[]string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", bad, "h15"},
			[]string{bad}, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insp.mu.Lock()
			insp.prompts = nil
			insp.mu.Unlock()
			got := p.refusedSegments(t.Context(), tc.v, tc.current, tc.turn, tc.fresh, "m", "action")
			if !equal(got, tc.want) {
				t.Errorf("refusedSegments = %q, want %q", got, tc.want)
			}
			insp.mu.Lock()
			n := len(insp.prompts)
			insp.mu.Unlock()
			if n != tc.probes {
				t.Errorf("%d attribution inspections, want %d", n, tc.probes)
			}
		})
	}
}
