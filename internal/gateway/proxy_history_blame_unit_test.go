// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

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
		want          []string
		probes        int
	}{
		{"not a guardrail block (audit closed)", &ScanVerdict{Action: "allow"}, []string{bad}, []string{bad}, nil, 0},
		{"no current turn", block, []string{"sys " + covMarker}, nil, []string{"sys " + covMarker}, 0},
		{"one current turn, no probe (one AI Defense call)", block, []string{"sys", bad}, []string{bad}, []string{bad}, 0},
		{"blamed among co-turns", block, []string{"sys", "ok", bad, "fine"}, []string{"ok", bad, "fine"}, []string{bad}, 3},
		{"no co-turn blamed alone", block, []string{"sys " + covMarker, "ok", "fine"}, []string{"ok", "fine"}, []string{"sys " + covMarker, "ok", "fine"}, 2},
		{"too many candidates", block, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"},
			[]string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insp.mu.Lock()
			insp.prompts = nil
			insp.mu.Unlock()
			got := p.refusedSegments(t.Context(), tc.v, tc.current, tc.turn, "m", "action")
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
