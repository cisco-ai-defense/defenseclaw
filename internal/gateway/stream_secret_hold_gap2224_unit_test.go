// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP2224ParkedOnlyOpenSecret: openSecret.parkedOnly, what the held
// bound reads to decide a parked run by its own bytes (rel-1-0-10:GAP-2224).
// An open run that is not parked, in any lane, clears it; a run parked at a
// block end or by the switch to the answer sets it.
func TestGAP2224ParkedOnlyOpenSecret(t *testing.T) {
	var r responseText
	r.Add(reasoningPiece(0, "Let me count the rows: step 3"))
	if o := r.OpenSecret(); !o.open || o.parkedOnly {
		t.Fatalf("an open, unparked thinking run: %+v, want open and not parkedOnly", o)
	}
	r.Add(responsePiece{lane: responseLane{choice: 0}, end: laneEndBlock})
	if o := r.OpenSecret(); !o.open || !o.parkedOnly {
		t.Errorf("a run parked at its block end: %+v, want parkedOnly", o)
	}
	r.Add(answerPiece(0, "The table has rows 4111"))
	if o := r.OpenSecret(); !o.open || o.parkedOnly {
		t.Errorf("a parked thinking run and an open answer run: %+v, want not parkedOnly", o)
	}
	var a responseText
	a.Add(answerPiece(0, "Done."))
	if o := a.OpenSecret(); o.open || o.parkedOnly {
		t.Errorf("no open run: %+v, want neither open nor parkedOnly", o)
	}
}
