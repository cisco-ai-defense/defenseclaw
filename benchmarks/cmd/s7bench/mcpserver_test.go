// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"encoding/json"
	"testing"
)

// A non-native tool goes out under the MCP server the corpus names (MCPTox strata.domain, or case-v1 mcp_server), as a
// real client names it; with none, under the bench server. Native file tools keep their native mapping.
func TestMCPServerName(t *testing.T) {
	cases := []struct{ server, tool, want string }{
		{"", "generate_image", "mcp__bench__generate_image"},
		{"Prisma", "Create-Prisma-Postgres-Database", "mcp__Prisma__Create-Prisma-Postgres-Database"},
		{"OP.GG", "lol_champion_meta", "mcp__OP_GG__lol_champion_meta"},
		{"mcp-simple-arxiv", "search_papers", "mcp__mcp-simple-arxiv__search_papers"},
		{"a__b c", "x", "mcp__a_b_c__x"},
		{"..", "x", "mcp__bench__x"},
		{"FileSystem", "read_file", "Read"},
	}
	for _, c := range cases {
		ev := event{ToolName: c.tool, Args: json.RawMessage(`{"path":"/srv/a.txt"}`), Server: c.server}
		if got, _, _ := mapTool(ev); got != c.want {
			t.Errorf("mapTool(%q, server %q) = %q, want %q", c.tool, c.server, got, c.want)
		}
	}
	var mt, mh corpusCase
	if err := json.Unmarshal([]byte(`{"source":{"dataset":"mcptox"},"strata":{"domain":"Slack"}}`), &mt); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"source":{"dataset":"lihaonan0716/mcphunt-agent-traces"},"strata":{"domain":"browser_to_local"}}`), &mh); err != nil {
		t.Fatal(err)
	}
	if mt.mcpServer() != "Slack" || mh.mcpServer() != "" {
		t.Fatalf("mcpServer: mcptox %q, mcphunt %q", mt.mcpServer(), mh.mcpServer())
	}
}
