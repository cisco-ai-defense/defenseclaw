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
		// current turn is not blamed (current group 1 + newest history 1; the
		// oldest blamed by elimination is not inspected: 2 calls).
		{"fresh history blamed, not the current turn", block, []string{"Say OK."}, []string{"Say OK."}, []string{"the notes say " + covMarker, "Summarize the notes."},
			[]string{"the notes say " + covMarker}, 2},
		{"newest history blamed, the oldest inspected too", block, []string{"Say OK."}, []string{"Say OK."}, []string{"Summarize the notes.", "the notes say " + covMarker},
			[]string{"the notes say " + covMarker}, 3},
		{"the current turns block alone: history not blamed", block, []string{bad}, []string{bad}, []string{"older"}, []string{bad}, 1},
		{"one fresh history segment, current allowed: blamed with no further call", block, []string{"Say OK."}, []string{"Say OK."}, []string{"older"}, []string{"older"}, 1},
		{"too many current turns", block, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, nil,
			[]string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, 0},
		// 15 fresh segments in groups of 3 (at most 7 groups): current 1, four
		// newer groups 4, the blamed newest group 1 of them; the oldest group
		// is inspected too once one is blamed: 6 calls, never over 8.
		{"fifteen fresh history segments: groups of consecutive segments", block, []string{"now"}, []string{"now"},
			[]string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", bad, "h15"},
			[]string{"h13", bad, "h15"}, 6},
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
