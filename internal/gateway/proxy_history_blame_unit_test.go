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
		name                 string
		v                    *ScanVerdict
		current, turn, fresh []string
		want                 []string
		probes               int
	}{
		{"not a guardrail block (audit closed)", &ScanVerdict{Action: "allow"}, []string{bad}, []string{bad}, nil, nil, 0},
		{"one inspected segment", block, []string{"sys"}, nil, nil, []string{"sys"}, 0},
		{"blamed among co-turns", block, []string{"sys", "ok", bad, "fine"}, []string{"ok", bad, "fine"}, nil, []string{bad}, 3},
		{"no turn blamed alone", block, []string{"sys " + covMarker, "ok"}, []string{"ok"}, nil, []string{"sys " + covMarker, "ok"}, 1},
		{"fresh history is a second inspected segment", block, []string{"ok"}, []string{"ok"}, []string{"hist " + covMarker}, []string{"ok"}, 1},
		{"too many candidates", block, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, []string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, nil,
			[]string{bad, "1", "2", "3", "4", "5", "6", "7", "8"}, 0},
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
