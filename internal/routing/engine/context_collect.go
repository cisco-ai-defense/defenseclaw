// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// ContextCollector gathers the human-typed user turns and the tool names of
// one request, in conversation order and in bounded memory: the first turn,
// the newest RecentTurns+1 turns (the last is the newest turn, which
// Request.Text already carries) and at most ContextMaxToolNames+1 distinct
// names. A kept turn is cut a few bytes past PerTurnBytes, so assembly
// still sees that it was longer. The caller feeds it only text the user
// typed: never tool results, assistant text or system prompts. Turns older
// than the window are a configured choice, not a truncation.
type ContextCollector struct {
	opts  ContextOptions
	turns int
	first string
	ring  []string
	next  int
	tools []string
	loop  bool
}

// ContextCollector returns a collector for one request, or nil when
// routing.context is off (the caller then reads nothing more).
func (e *Engine) ContextCollector() *ContextCollector {
	if e == nil || !e.context.Active() {
		return nil
	}
	return &ContextCollector{opts: e.context}
}

// Reset drops what was collected (a repeated conversation key).
func (c *ContextCollector) Reset() {
	if c != nil {
		*c = ContextCollector{opts: c.opts}
	}
}

// Turn records one user turn the user typed; empty text is ignored.
func (c *ContextCollector) Turn(text string) {
	if c == nil || text == "" || (c.opts.RecentTurns == 0 && !c.opts.FirstTurn) {
		return
	}
	kept := strings.Clone(cutUTF8(text, c.opts.PerTurnBytes+utf8.UTFMax))
	c.turns++
	if c.turns == 1 {
		c.first = kept
	}
	if size := c.opts.RecentTurns + 1; len(c.ring) < size {
		c.ring = append(c.ring, kept)
	} else {
		c.ring[c.next] = kept
		c.next = (c.next + 1) % size
	}
}

// WantsTools reports whether Tool records anything (include_tool_names).
func (c *ContextCollector) WantsTools() bool { return c != nil && c.opts.ToolNames }

// Tool records one tool call, or a tool result (name ""), of the loop.
// Only the name is kept, never arguments or results.
func (c *ContextCollector) Tool(name string) {
	if c == nil || !c.opts.ToolNames {
		return
	}
	c.loop = true
	name = strings.TrimSpace(name)
	if name == "" || len(c.tools) > ContextMaxToolNames {
		return
	}
	name = cutUTF8(name, ContextToolNameBytes+utf8.UTFMax)
	if !slices.Contains(c.tools, name) {
		c.tools = append(c.tools, strings.Clone(name))
	}
}

// Fill sets the context fields of req: the older turns newest first, the
// first turn when the window does not hold it, the tool names and ToolLoop.
func (c *ContextCollector) Fill(req *Request) {
	if c == nil || req == nil {
		return
	}
	if n := len(c.ring); n > 1 {
		older := make([]string, 0, n-1)
		for i := n - 2; i >= 0; i-- {
			older = append(older, c.ring[(c.next+i)%n])
		}
		req.ContextTurns = older
	}
	if c.opts.FirstTurn && c.turns > len(c.ring) {
		req.FirstTurn = c.first
	}
	req.ToolNames, req.ToolLoop = c.tools, c.loop
}
