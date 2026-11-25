// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP2224UntextedEventsSpendTheParkOnly: the shared park clock of every
// stream route (responseText.AddEvent: passthrough events, Bedrock frames,
// raw-forward payloads). Events that add no model text spend a block-end or
// tool-switch park (streamRunParkMax) by their size, so the run ends past
// the budget; the same bytes below the budget keep it parked; an answer
// park (limit 0, GAP-2170) never expires on them; an event with text adds
// nothing beyond its text; an event with only the walker's strings (a
// server tool result's URL) spends its wire size.
func TestGAP2224UntextedEventsSpendTheParkOnly(t *testing.T) {
	parkedAtBlockEnd := func() *responseText {
		var r responseText
		r.Add(reasoningPiece(0, "Let me count the rows: step 3"))
		r.Add(responsePiece{lane: responseLane{choice: 0}, end: laneEndBlock})
		if !r.OpenSecret().reasoningOnly {
			t.Fatal("setup: the thinking run is not parked")
		}
		return &r
	}
	r := parkedAtBlockEnd()
	r.AddEvent(nil, streamRunParkMax-64)
	if !r.OpenSecret().open {
		t.Error("untexted bytes under the park budget ended the run")
	}
	r.AddEvent(nil, 128)
	if r.OpenSecret().open {
		t.Error("untexted bytes past the park budget left the run parked (GAP-2224)")
	}
	r = parkedAtBlockEnd()
	r.AddEvent([]responsePiece{toolInputPiece(0, 1, `{"q":"x"}`)}, streamRunParkMax*4)
	if !r.OpenSecret().open {
		t.Error("an event with text spent the park by its wire size")
	}
	// A server tool result start: no typed text, only the walker's strings
	// (the URL); its document bytes spend the park.
	r = parkedAtBlockEnd()
	r.AddEvent([]responsePiece{{lane: responseLane{field: responseFieldOther}, text: "https://example.com/report.pdf"}}, streamRunParkMax+64)
	if r.OpenSecret().open {
		t.Error("a server tool result event with only the walker's strings left the run parked (GAP-2224)")
	}
	var a responseText
	a.Add(reasoningPiece(0, "Let me count the rows: step 3"))
	a.Add(answerPiece(0, "Answer: "))
	a.AddEvent(nil, streamSecretMaxHeld)
	if o := a.OpenSecret(); !o.reasoningOnly || !o.answerParkedOnly {
		t.Errorf("the reasoning-to-answer park expired on untexted bytes: %+v", o)
	}
}
