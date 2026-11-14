// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"

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
			if t := capText(stripReminders(m.Content)); t != "" {
				col.Turn(t)
			}
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
