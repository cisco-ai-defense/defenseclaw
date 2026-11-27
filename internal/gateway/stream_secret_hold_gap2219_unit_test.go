// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP2219OpenRunFromBoundaryRun: an open run of the reasoning-to-answer
// boundary line (GAP-2166) that starts before the oldest open lane run is
// the start the held-bound cut keeps (rel-1-0-10:GAP-2219). The answer lane
// resumes after earlier answer text, so its own run starts only at the
// second digit group, while the boundary line has a word boundary before the
// first one: the piece with the first group must stay held.
func TestGAP2219OpenRunFromBoundaryRun(t *testing.T) {
	var r responseText
	r.Add(answerPiece(0, "Total x"))
	r.Add(reasoningPiece(0, "ok "))
	r.Add(answerPiece(0, "4111"))
	r.Add(answerPiece(0, " 1111"))
	if !r.OpenSecret().open {
		t.Fatal("no open secret")
	}
	first := len("Total x") + len("ok ")
	if got := r.OpenRunFrom(); got != first {
		t.Fatalf("OpenRunFrom = %d, want %d (the boundary run's first byte)", got, first)
	}
	marks := []int{len("Total x"), first, first + len("4111"), r.Len()}
	if got := heldBeforeRun(marks, r.OpenRunFrom()); got != 2 {
		t.Fatalf("heldBeforeRun = %d, want 2: the piece with the boundary run's first byte is held", got)
	}

	// The run ends: nothing open.
	r.Add(answerPiece(0, " is it.\n"))
	r.OpenSecret()
	if got := r.OpenRunFrom(); got != -1 {
		t.Fatalf("OpenRunFrom after the run ended = %d, want -1", got)
	}
}
