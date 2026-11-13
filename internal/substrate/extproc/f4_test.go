// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"strings"
	"testing"
)

// GAP-0146: a managed callout that fails closed with body_inspection auto
// refuses an MCP request to a listed MCP host while no body has reached it
// (a stock egress filter would send the body on unread), and asks for the
// body once one has.
func TestManagedClosedAutoRefusesUnconfirmedMCPBodies(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) { c.Managed = true })
	if h.eng.Degraded() != "mcp_refused_until_body_support" {
		t.Fatalf("degraded = %q", h.eng.Degraded())
	}
	c := dial(t, h)
	s, cancel := open(t, c)
	r := exchange(t, s, mcpHeaders(mcpCall("x")))
	cancel()
	im := r.GetImmediateResponse()
	if im == nil || r.GetModeOverride() != nil {
		t.Fatalf("want a refusal at the headers, got %v", r)
	}
	if !strings.Contains(string(im.GetBody()), "body_inspection") {
		t.Fatalf("refusal does not say what to set: %q", im.GetBody())
	}
	ev := waitEvents(t, h.events, 1)[0]
	if ev.Decision == "allow" || ev.Category != CategoryBodyUninspected || ev.Rule != whyUnavailable {
		t.Fatalf("event %+v", ev)
	}
	// A body reached the callout (a listed body host, or an admin who set
	// on): the filter sends bodies, so MCP bodies are asked for and read.
	h.eng.body.arrived()
	s2, cancel2 := open(t, c)
	defer cancel2()
	if r := exchange(t, s2, mcpHeaders(mcpCall("x"))); r.GetModeOverride() == nil {
		t.Fatalf("body not asked for once support is known: %v", r)
	}
	if h.eng.Degraded() != "" {
		t.Fatalf("still degraded: %q", h.eng.Degraded())
	}
}

// on states that the filter sends bodies; OSS installs keep asking and
// alerting (balanced defaults): neither refuses at the headers.
func TestBodyOnAndOSSAutoAskForTheBody(t *testing.T) {
	for name, mutate := range map[string]func(*Config, *Options){
		"managed on": func(c *Config, _ *Options) { c.Managed, c.BodyInspection = true, BodyOn },
		"oss auto":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, mutate)
			if h.eng.Degraded() != "" {
				t.Fatalf("degraded = %q", h.eng.Degraded())
			}
			s, cancel := open(t, dial(t, h))
			defer cancel()
			if r := exchange(t, s, mcpHeaders(mcpCall("x"))); r.GetModeOverride() == nil || r.GetImmediateResponse() != nil {
				t.Fatalf("got %v", r)
			}
		})
	}
}
