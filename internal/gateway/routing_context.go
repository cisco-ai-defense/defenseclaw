// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
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
func routerUserText(s string) string {
	t := capText(stripReminders(s))
	if engine.InjectedUserText(t) {
		return ""
	}
	return t
}

// injectedBlock reports whether one content block was written by the agent.
// System reminders are stripped first (they are removed from the message
// text anyway), so a reminder followed by typed text keeps the typed text.
func injectedBlock(text string) bool {
	return engine.InjectedUserText(text) && engine.InjectedUserText(stripReminders(text))
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
	for _, bl := range blocks {
		switch bl.Type {
		case "text", "input_text", "":
			if injectedBlock(bl.Text) {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte(0x0a)
			}
			b.WriteString(bl.Text)
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
