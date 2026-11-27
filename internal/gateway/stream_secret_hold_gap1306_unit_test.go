// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP1306OpenRunFrom: the reply text offset of an open run is found in
// the lane it runs in, across pieces and lanes, and the held pieces before it
// are the ones that end at or before it.
func TestGAP1306OpenRunFrom(t *testing.T) {
	var r responseText
	r.Add(answerPiece(0, "The total is 12 apples and "))
	r.Add(toolInputPiece(0, 0, `{"path":"a.txt"}`))
	r.Add(answerPiece(0, "the code is 4111 1111"))
	r.Add(toolInputPiece(0, 0, `x`))
	lead := len("The total is 12 apples and ") + len(`{"path":"a.txt"}`) + len("the code is ")
	if got := r.OpenRunFrom(); got != lead {
		t.Fatalf("OpenRunFrom = %d, want %d", got, lead)
	}
	marks := []int{27, 27 + 16, r.Len() - 1, r.Len()}
	if got := heldBeforeRun(marks, lead); got != 2 {
		t.Fatalf("heldBeforeRun = %d, want 2", got)
	}
	r.Add(answerPiece(0, " 1111 1111 is it.\n"))
	if got := r.OpenRunFrom(); got != -1 {
		t.Fatalf("OpenRunFrom after the run ended = %d, want -1", got)
	}
}
