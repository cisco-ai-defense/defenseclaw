// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// routeContext fills the routing.context facts of req (older human-typed
// user turns, the first turn, tool names) when the generation has
// routing.context on; off, it reads nothing (rel-1-0-10:GAP-0002).
func routeContext(eng *engine.Engine, in *ModelRouterInput, req *engine.Request) {
	col := eng.ContextCollector()
	if col == nil || in == nil {
		return
	}
	if len(in.Body) > 0 {
		routeContextFromBody(col, req.APIFamily, in.Body)
	} else {
		routeContextFromMessages(col, in.Messages)
	}
	col.Fill(req)
}

// routerUserText is user-role text as the router may read it: system
// reminders stripped, bounded, and "" when the agent wrote it
// (engine.InjectedUserText: instruction files, command output, compaction
// summaries, IDE and environment context).
// The OpenClaw "Sender (untrusted metadata):" envelope is removed, and a
// heartbeat or session-startup probe turn gives "" (routerProbeTurnText).
func routerUserText(s string) string {
	t := capText(strings.TrimSpace(stripOpenClawUntrustedEnvelope(stripReminders(s))))
	if engine.InjectedUserText(t) {
		return ""
	}
	if rest, ok := stripCanonicalProbes(t); ok {
		t = routerProbeTurnText(rest)
		if engine.InjectedUserText(t) {
			return ""
		}
	}
	return t
}

// routerProbeNoiseRe is one line a messaging bridge or OpenClaw puts around a
// probe: a "System:" transport banner or the "Current time:" footer.
var routerProbeNoiseRe = lazyregexp.New(`^(?:System:\s.{0,240}|Current time:\s.{0,240})$`)

// routerProbeTurnText is the router text of a user turn that held an OpenClaw
// probe, the canonical sentences already left out (stripCanonicalProbes):
// "" when only banners, time footers or whitespace remain, so system noise
// never picks a model, else the remaining typed text without that noise.
// Only the router reads a probe turn this way; the guardrail inspects every
// part of it but the canonical sentences (GAP-0248).
func routerProbeTurnText(rest string) string {
	var kept []string
	for _, line := range strings.Split(rest, "\n") {
		if l := strings.TrimSpace(line); l != "" && !routerProbeNoiseRe.MatchString(l) {
			kept = append(kept, line)
		}
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// injectedBlock reports whether one content block was written by the agent.
// System reminders are stripped first (they are removed from the message
// text anyway), so a reminder followed by typed text keeps the typed text.
func injectedBlock(text string) bool {
	return engine.InjectedUserText(text) && engine.InjectedUserText(stripReminders(text))
}

// userBlockFilter filters the text blocks of one user message, in order.
// A Claude Code slash command block (command-name or command-message) gives
// what the user typed after the command (its command-args), and the next
// typed-looking block of the message is the expanded command file, which is
// skipped, unless local command output follows first (a built-in command
// such as /model, which has no expanded file).
type userBlockFilter struct{ commandBody bool }

// keep returns the router text of one block and whether to add it; an
// empty block is kept as is (the joined text keeps its line breaks).
func (f *userBlockFilter) keep(text string) (string, bool) {
	t := strings.TrimSpace(text)
	switch {
	case t == "" || (engine.StartsWithTag(t, "system-reminder") && stripReminders(t) == ""):
		// Empty, or reminders only (the message text drops them): kept as
		// is, and it does not count as the expanded command file.
		return text, true
	case engine.StartsWithTag(t, "command-name") || engine.StartsWithTag(t, "command-message"):
		f.commandBody = true
		args := commandArgs(t)
		return args, args != ""
	case engine.StartsWithTag(t, "local-command-stdout") || engine.StartsWithTag(t, "local-command-stderr"):
		f.commandBody = false
		return "", false
	case injectedBlock(text):
		return "", false
	case f.commandBody:
		f.commandBody = false
		return "", false
	}
	return text, true
}

// commandArgs is the text of the command-args element of a slash command
// block ("" when there is none).
func commandArgs(t string) string {
	const open, closeTag = "<command-args>", "</command-args>"
	i := strings.Index(t, open)
	if i < 0 {
		return ""
	}
	rest := t[i+len(open):]
	if j := strings.Index(rest, closeTag); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// passthroughRouterText is the router text of a passthrough body: the newest
// user message with typed text, block by block (the scan of the route-only
// listener), never the joined guardrail text. fallback (the guardrail text)
// is used only when the body does not scan.
func passthroughRouterText(family string, body []byte, fallback string) string {
	s := humanTextScan{responses: family == config.RoutingAPIResponses}
	s.dec = json.NewDecoder(bytes.NewReader(body))
	s.dec.UseNumber()
	if !s.document() {
		return routerUserText(fallback)
	}
	return s.text
}

// routerMessageText is the router text of one parsed user message: its
// text blocks the agent did not inject, joined, then routerUserText.
func routerMessageText(m *ChatMessage) string {
	raw := bytes.TrimSpace(m.RawContent)
	if len(raw) == 0 || raw[0] != 0x5b { // [
		return routerUserText(m.Content)
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return routerUserText(m.Content)
	}
	var b strings.Builder
	var f userBlockFilter
	for _, bl := range blocks {
		switch bl.Type {
		case "text", "input_text", "":
			t, ok := f.keep(bl.Text)
			if !ok {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte(0x0a)
			}
			b.WriteString(t)
		}
	}
	return routerUserText(b.String())
}

// routeContextFromBody feeds col from a Messages, Chat Completions, Bedrock
// or Responses body with the scan of routeOnlyHumanText: user text only,
// system reminders stripped, tool names from tool_use blocks, tool_calls,
// Bedrock toolUse blocks and Responses *_call items. A body the scan
// refuses gives nothing.
func routeContextFromBody(col *engine.ContextCollector, family string, body []byte) {
	s := humanTextScan{responses: family == config.RoutingAPIResponses, ctx: col}
	s.dec = json.NewDecoder(bytes.NewReader(body))
	s.dec.UseNumber()
	if !s.document() {
		col.Reset()
	}
}

// routeContextFromMessages feeds col from the parsed messages of the chat
// route: user text (tool results are role tool there), assistant tool_calls
// names, and role tool as a tool result.
func routeContextFromMessages(col *engine.ContextCollector, msgs []ChatMessage) {
	for i := range msgs {
		m := &msgs[i]
		switch m.Role {
		case "user":
			col.Turn(routerMessageText(m))
		case "assistant":
			if len(m.ToolCalls) > 0 && col.WantsTools() {
				var calls []struct {
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				}
				_ = json.Unmarshal(m.ToolCalls, &calls)
				for _, c := range calls {
					col.Tool(c.Function.Name)
				}
			}
		case "tool":
			col.Tool("")
		}
	}
}
