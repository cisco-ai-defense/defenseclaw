// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func init() { bounded.PanicOnMisuse(true) }

func ctxOpts(maxBytes, per int) ContextOptions {
	return ContextOptions{RecentTurns: 2, FirstTurn: true, MaxBytes: maxBytes, PerTurnBytes: per, ToolNames: true}
}

func TestAssembleContext(t *testing.T) {
	x16, y16 := strings.Repeat("x", 16), strings.Repeat("y", 16)
	many := make([]string, ContextMaxToolNames+1)
	for i := range many {
		many[i] = fmt.Sprintf("t%d", i)
	}
	for _, tc := range []struct {
		name          string
		newest, first string
		older, tools  []string
		o             ContextOptions
		text, signal  string
		caps          bounded.CapSet
	}{
		{name: "newest first, older newest first, then the first turn", newest: "new", older: []string{"b", "a"}, first: "f", o: ctxOpts(64, 16),
			text: "new\n\nb\n\na\n\nf"},
		{name: "newest alone over the per-turn cap is cut, never dropped", newest: x16 + "zz", o: ctxOpts(64, 16),
			text: x16, caps: bounded.Of(bounded.Bytes)},
		{name: "cut on a UTF-8 boundary", newest: strings.Repeat("a", 15) + "é", o: ctxOpts(64, 16),
			text: strings.Repeat("a", 15), caps: bounded.Of(bounded.Bytes)},
		{name: "max_bytes leaves older turns out", newest: x16, older: []string{y16, "zzzz"}, o: ctxOpts(34, 16),
			text: x16 + "\n\n" + y16, caps: bounded.Of(bounded.Bytes)},
		{name: "older turn cut to what is left", newest: x16, older: []string{y16}, o: ctxOpts(26, 16),
			text: x16 + "\n\n" + "yyyyyyyy", caps: bounded.Of(bounded.Bytes)},
		{name: "tool names are signal-only", newest: "new", tools: []string{"Bash", "Read"}, o: ctxOpts(64, 16),
			text: "new", signal: "new\n\ntools: Bash,Read"},
		{name: "too many tool names", newest: "n", tools: many, o: ctxOpts(64, 16),
			text: "n", signal: "n\n\ntools: " + strings.Join(many[:ContextMaxToolNames], ","), caps: bounded.Of(bounded.Items)},
		{name: "long tool name is cut", newest: "n", tools: []string{strings.Repeat("k", ContextToolNameBytes+1)}, o: ctxOpts(64, 16),
			text: "n", signal: "n\n\ntools: " + strings.Repeat("k", ContextToolNameBytes), caps: bounded.Of(bounded.Bytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, signal, caps := assembleContext(tc.newest, tc.older, tc.first, tc.tools, tc.o)
			want := tc.signal
			if want == "" {
				want = tc.text
			}
			if text != tc.text || signal != want || caps != tc.caps {
				t.Fatalf("got text=%q signal=%q caps=%v, want %q %q %v", text, signal, caps.Reason(), tc.text, want, tc.caps.Reason())
			}
			if len(text) > tc.o.MaxBytes {
				t.Fatalf("text %d bytes over max_bytes %d", len(text), tc.o.MaxBytes)
			}
		})
	}
}

func TestAssembleContextSeparatorMakesNoWord(t *testing.T) {
	m := &signalMatcher{signals: []compiledSignal{{name: "joined", keywords: []string{"foobar"}}}}
	_, signal, _ := assembleContext("foo", []string{"bar"}, "", nil, ctxOpts(64, 16))
	if m.Match(signal)["joined"] {
		t.Fatalf("%q joined two turns into one word", signal)
	}
}

func TestContextWarningNamesTheCaps(t *testing.T) {
	if got := contextWarning(bounded.Of(bounded.Items, bounded.Bytes)); got != "context_truncated:items,bytes" {
		t.Fatalf("warning = %q", got)
	}
}

func TestContextCollectorWindow(t *testing.T) {
	c := &ContextCollector{opts: ctxOpts(64, 16)}
	for i := 1; i <= 5; i++ {
		c.Turn(fmt.Sprintf("t%d", i))
	}
	c.Turn("")
	var req Request
	c.Fill(&req)
	if !slices.Equal(req.ContextTurns, []string{"t4", "t3"}) || req.FirstTurn != "t1" {
		t.Fatalf("window = %q first %q", req.ContextTurns, req.FirstTurn)
	}
	c.Reset()
	c.Turn("t1")
	c.Turn("t2")
	req = Request{}
	c.Fill(&req)
	if !slices.Equal(req.ContextTurns, []string{"t1"}) || req.FirstTurn != "" {
		t.Fatalf("short conversation = %q first %q (the first turn is in the window)", req.ContextTurns, req.FirstTurn)
	}
	c.Reset()
	c.Turn(strings.Repeat("w", 10_000))
	if got := len(c.ring[0]); got > 16+4 || got <= 16 {
		t.Fatalf("kept %d bytes of a long turn, want a little past per_turn_bytes", got)
	}
}

func TestContextCollectorToolNames(t *testing.T) {
	c := &ContextCollector{opts: ctxOpts(64, 16)}
	c.Tool(" Bash ")
	c.Tool("Bash")
	c.Tool("Read")
	var req Request
	c.Fill(&req)
	if !slices.Equal(req.ToolNames, []string{"Bash", "Read"}) || !req.ToolLoop {
		t.Fatalf("tools = %q loop %v", req.ToolNames, req.ToolLoop)
	}
	c.Reset()
	c.Tool("")
	req = Request{}
	c.Fill(&req)
	if req.ToolNames != nil || !req.ToolLoop {
		t.Fatalf("a tool result alone: tools %q loop %v", req.ToolNames, req.ToolLoop)
	}
	for i := 0; i < 100; i++ {
		c.Tool(fmt.Sprintf("n%d", i))
	}
	if len(c.tools) != ContextMaxToolNames+1 {
		t.Fatalf("kept %d names, want %d (cap + 1 marks the overflow)", len(c.tools), ContextMaxToolNames+1)
	}
	off := &ContextCollector{opts: ContextOptions{RecentTurns: 1, MaxBytes: 64, PerTurnBytes: 16}}
	off.Tool("Bash")
	off.Fill(&req)
	if req.ToolNames != nil || req.ToolLoop || off.WantsTools() {
		t.Fatalf("include_tool_names off still records tools: %q %v", req.ToolNames, req.ToolLoop)
	}
}

func TestContextCollectorNilIsSafe(t *testing.T) {
	var c *ContextCollector
	c.Turn("x")
	c.Tool("x")
	c.Reset()
	req := Request{Text: "x"}
	c.Fill(&req)
	if c.WantsTools() || req.ContextTurns != nil || req.ToolLoop {
		t.Fatal("a nil collector changed the request")
	}
}
