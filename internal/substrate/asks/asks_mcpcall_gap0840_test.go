// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package asks

import (
	"context"
	"testing"
)

// TestMCPCallRuleIsNotHostWideGAP0840: an MCP call ask covers that call
// only, never a host, and two calls of one tool with other digests are two
// pending asks.
func TestMCPCallRuleIsNotHostWideGAP0840(t *testing.T) {
	if HostWide(MCPCallRule("aa")) {
		t.Fatal("an MCP call rule is host-wide")
	}
	s := NewMemory()
	base := Ask{Atespace: "a", Actor: "n", UID: "u1", OwnerID: "o", Tool: "mcp__notes__publish"}
	one, two := base, base
	one.Rule, two.Rule = MCPCallRule("11"), MCPCallRule("22")
	a, err := s.OpenAsk(context.Background(), one)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.OpenAsk(context.Background(), two)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.OpenAsk(context.Background(), one)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID || c.ID != a.ID {
		t.Fatalf("asks %s %s %s: want two distinct, the repeat joined to the first", a.ID, b.ID, c.ID)
	}
}
