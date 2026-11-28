// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// The reply text the passthrough checks read is rel's typed fields
// (response_text_fields.go: answer, reasoning, refusal, streamed tool input,
// every choice, each in its own lane, GAP-0370) and every other string the
// reply walker finds (scanReplyJSON: inspect by default, substrate-1
// GAP-0189, GAP-0239). The walker's strings that a typed field already
// holds are not read twice; the others go into one more lane, in stream
// order, as the walker read them before the lanes.

// responseFieldOther is the lane of the strings no typed reader names.
const responseFieldOther responseField = 200

// withWalkerPieces adds to typed the walker's strings of the same event or
// body that no typed piece holds.
func withWalkerPieces(typed []responsePiece, segs []string) []responsePiece {
	// A lane end (GAP-2154) goes after the walker's strings of the same
	// event, so it ends them too.
	var ends []responsePiece
	out := typed[:0:0]
	for _, p := range typed {
		if p.end != laneEndNone {
			ends = append(ends, p)
		} else {
			out = append(out, p)
		}
	}
	for _, seg := range segs {
		if seg == "" {
			continue
		}
		covered := false
		for _, p := range typed {
			if p.text != "" && strings.Contains(p.text, seg) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, responsePiece{lane: responseLane{field: responseFieldOther}, text: seg})
		}
	}
	return append(out, ends...)
}

// passthroughReplyText is the model text of a buffered reply: the typed
// lanes, then every other string of the reply on its own line.
func passthroughReplyText(body []byte, provider string, segs []string) string {
	return passthroughReplyTextMode(body, provider, segs, false)
}

func passthroughReplyCheckText(body []byte, provider string, segs []string) string {
	return passthroughReplyTextMode(body, provider, segs, true)
}

func passthroughReplyTextMode(body []byte, provider string, segs []string, check bool) string {
	var typed string
	if check {
		typed = extractPassthroughResponseCheckContent(body, provider)
	} else {
		typed = extractPassthroughResponseContent(body, provider)
	}
	lines := make([]string, 0, len(segs)+1)
	if typed != "" {
		lines = append(lines, typed)
	}
	for _, seg := range segs {
		if strings.TrimSpace(seg) == "" || strings.Contains(typed, seg) {
			continue
		}
		lines = append(lines, seg)
	}
	return strings.Join(lines, "\n")
}

// passthroughReplyToolCalls is the tool calls of a buffered reply: the
// walker's (every call object of the reply) and the typed reader's
// (extractPassthroughToolCalls: a legacy function_call, Cohere and Ollama
// shapes, GAP-0519/0521), each call once, in the inspectToolCalls shape.
func passthroughReplyToolCalls(walker []sseToolCall, body []byte, provider string) json.RawMessage {
	type call struct {
		ID       string `json:"id,omitempty"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	var all []call
	seen := map[[2]string]bool{}
	add := func(c call) {
		key := [2]string{c.Function.Name, c.Function.Arguments}
		if c.Function.Name == "" && c.Function.Arguments == "" || seen[key] {
			return
		}
		seen[key] = true
		if c.Type == "" {
			c.Type = "function"
		}
		all = append(all, c)
	}
	for _, w := range walker {
		var c call
		c.ID, c.Type, c.Function.Name, c.Function.Arguments = w.ID, w.Type, w.Function.Name, w.Function.Arguments
		add(c)
	}
	if raw := extractPassthroughToolCalls(body, provider); raw != nil {
		var typed []call
		if json.Unmarshal(raw, &typed) == nil {
			for _, c := range typed {
				add(c)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	b, err := json.Marshal(all)
	if err != nil {
		return nil
	}
	return b
}
