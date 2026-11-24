// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP2154LaneEnds: the readers report the providers' lane ends, a later
// lane of the same choice ends the one it follows, and an end ends only its
// own choice; a run that starts after an end is held as before.
func TestGAP2154LaneEnds(t *testing.T) {
	hasEnd := func(ps []responsePiece, choice int) bool {
		for _, p := range ps {
			if p.end && p.lane.choice == choice {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		name   string
		pieces []responsePiece
		choice int
	}{
		{"anthropic content_block_stop", anthropicStreamPieces([]byte(`{"type":"content_block_stop","index":0}`)), 0},
		{"anthropic message_stop", anthropicStreamPieces([]byte(`{"type":"message_stop"}`)), 0},
		{"chat finish_reason", streamEventPieces(`{"choices":[{"index":1,"delta":{},"finish_reason":"stop"}]}`, "openai"), 1},
		{"responses output_item.done", streamEventPieces(`{"type":"response.output_item.done","output_index":0,"item":{}}`, "openai"), 0},
		{"responses reasoning done", streamEventPieces(`{"type":"response.reasoning_summary_text.done","text":"x"}`, "openai"), 0},
		{"gemini finishReason", streamEventPieces(`{"candidates":[{"index":0,"finishReason":"STOP","content":{"parts":[{"text":"a"}]}}]}`, "gemini"), 0},
		{"bedrock contentBlockStop", streamEventPieces(`{"contentBlockStop":{"contentBlockIndex":0}}`, "bedrock"), 0},
	} {
		if !hasEnd(c.pieces, c.choice) {
			t.Errorf("%s: no lane end for choice %d in %+v", c.name, c.choice, c.pieces)
		}
	}
	if hasEnd(streamEventPieces(`{"choices":[{"index":0,"delta":{"content":"a"},"finish_reason":null}]}`, "openai"), 0) {
		t.Errorf("a chat delta with no finish_reason ended its choice")
	}
	if ps := withWalkerPieces([]responsePiece{laneEndPiece(0)}, []string{"walker 7"}); len(ps) != 2 || !ps[1].end {
		t.Errorf("the lane end must follow the walker's strings of its event: %+v", ps)
	}

	var r responseText
	r.Add(reasoningPiece(0, "Let me count: step 3"))
	r.Add(answerPiece(1, "choice one ends in 12"))
	if !r.OpenSecret().open {
		t.Fatal("open runs not held")
	}
	r.Add(answerPiece(0, "The answer."))
	r.Add(laneEndPiece(1))
	if o := r.OpenSecret(); o.open {
		t.Fatalf("the reasoning (answer of the same choice started) and choice 1 (ended) still hold: %+v", o)
	}
	r.Add(answerPiece(1, " and 4111"))
	if !r.OpenSecret().open {
		t.Fatal("a run that starts after the end is not held")
	}
	r.Add(answerPiece(0, " Then 55"))
	r.Add(laneEndPiece(0))
	if !r.OpenSecret().open {
		t.Fatal("ending choice 0 ended choice 1's run")
	}
	var tools responseText
	tools.Add(toolInputPiece(0, 0, `{"n":4`))
	tools.Add(toolInputPiece(0, 1, `{"path":"a"}`))
	if tools.OpenSecret().open {
		t.Fatal("a tool call's run is held after a later tool call started")
	}
}
