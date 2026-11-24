// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// GAP-1768 (RV-ROUTE2b follow-ups on GAP-1206): the block mark of an Anthropic
// content_block_start survives a content_block that is not an object, and the
// call types other than tool_use mark a call.
func TestAnthropicStreamMarkReadsTheBlockTypeAndSurvivesAnOddBlock(t *testing.T) {
	cases := []struct {
		name, data string
		start      int
		call       bool
	}{
		{"text", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`, 0, false},
		{"tool_use", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"x","input":{}}}`, 1, true},
		{"server_tool_use", `{"type":"content_block_start","index":2,"content_block":{"type":"server_tool_use","id":"st_1","name":"web_search","input":{}}}`, 2, true},
		{"mcp_tool_use", `{"type":"content_block_start","index":3,"content_block":{"type":"mcp_tool_use","id":"mt_1","name":"x","server_name":"s","input":{}}}`, 3, true},
		{"null block", `{"type":"content_block_start","index":4,"content_block":null}`, 4, false},
		{"string block", `{"type":"content_block_start","index":5,"content_block":"tool_use"}`, 5, false},
		{"array block", `{"type":"content_block_start","index":6,"content_block":[]}`, 6, false},
		{"no block", `{"type":"content_block_start","index":7}`, 7, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := anthropicStreamMark(c.data)
			if m.start != c.start || m.call != c.call {
				t.Fatalf("anthropicStreamMark = start %d call %v, want start %d call %v", m.start, m.call, c.start, c.call)
			}
		})
	}
}

// An allowed text block 0 then a refused call block 1: the agent got block 0
// closed and block 1 opened, so the tail closes block 1 and writes its text at
// index 2.
func TestStreamSentFollowsAnAllowedBlockAndARefusedCallBlock(t *testing.T) {
	sent := newStreamSent()
	for _, data := range []string{
		`{"type":"message_start","message":{"id":"m"}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_stop","index":0}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"server_tool_use","id":"st_1","name":"web_search","input":{}}}`,
	} {
		sent.add(anthropicStreamMark(data))
	}
	if !sent.msgStart || sent.open != 1 || !sent.openCall || sent.next != 2 {
		t.Fatalf("sent = %+v, want msgStart, open 1 (a call), next 2", sent)
	}
	sent.add(anthropicStreamMark(`{"type":"content_block_stop","index":1}`))
	if sent.open != -1 || sent.openCall || sent.next != 2 {
		t.Fatalf("after the stop: %+v, want no open block, next 2", sent)
	}
}
