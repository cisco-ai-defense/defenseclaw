// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

func TestClaudeMCPVariadicConfigAndPrintPrompt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		process string
		cmdline string
		server  bool
	}{
		{"second configuration value", "claude", `claude --mcp-config first.json mcp_server.json`, false},
		{"second configuration value on Windows", "claude.exe", `claude.exe --mcp-config first.json second-mcp_server.json`, false},
		{"strict second configuration value", "claude", `claude --strict-mcp-config --mcp-config first.json @modelcontextprotocol/server-filesystem`, false},
		{"print prompt starts with package", "claude", `claude -p "@modelcontextprotocol/server-filesystem"`, false},
		{"long print prompt starts with package", "claude", `claude --print "mcp_server is a package"`, false},
		{"configuration followed by print prompt", "claude", `claude --mcp-config first.json -p "@modelcontextprotocol/server-filesystem"`, false},
		{"JSON configuration value with option text", "claude", `claude --mcp-config {"mcpServers":{"sample":{"command":"echo -- @modelcontextprotocol/server-filesystem"}}}`, false},
		{"attached JSON configuration value", "claude", `claude --mcp-config={"mcpServers":{"sample":{"command":"echo -- @modelcontextprotocol/server-filesystem"}}}`, false},
		{"JSON configuration followed by positional server", "claude", `claude --mcp-config {"mcpServers":{"sample":{"command":"echo -- @modelcontextprotocol/server-filesystem"}}} -- @modelcontextprotocol/server-filesystem`, true},
		{"incomplete JSON configuration", "claude", `claude --mcp-config {"mcpServers":{"sample":"@modelcontextprotocol/server-filesystem"`, true},
		{"print prompt with braces", "claude", `claude -p {mcp_server is a package`, false},
		{"positional server after option terminator", "claude", `claude --mcp-config first.json -- @modelcontextprotocol/server-filesystem /workspace`, true},
		{"positional server after attached configuration", "claude", `claude --mcp-config=first.json @modelcontextprotocol/server-filesystem /workspace`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, ok := Classify(Observation{Kind: KindExec, Name: tc.process, ClaudeClient: true, Cmdline: tc.cmdline}, IndicatorSet{})
			server := ok && match.Tactic == LocalInference && match.SignalID == "agent_local_mcp_server"
			if server != tc.server {
				t.Fatalf("server classification = %t, want %t (match=%+v)", server, tc.server, match)
			}
		})
	}
}

func TestClaudeMCPClientOwnershipRequiresImageIdentity(t *testing.T) {
	for _, tc := range []struct {
		name        string
		observation Observation
		wantServer  bool
	}{
		{"unverified print", Observation{Kind: KindExec, Name: "claude", Cmdline: `claude -p @modelcontextprotocol/server-filesystem`}, true},
		{"unverified configuration", Observation{Kind: KindExec, Name: "claude", Cmdline: `claude --mcp-config @modelcontextprotocol/server-filesystem`}, true},
		{"identified print", Observation{Kind: KindExec, Name: "claude", ClaudeClient: true, Cmdline: `claude -p @modelcontextprotocol/server-filesystem`}, false},
		{"identified configuration", Observation{Kind: KindExec, Name: "claude", ClaudeClient: true, Cmdline: `claude --mcp-config @modelcontextprotocol/server-filesystem`}, false},
		{"identified positional server", Observation{Kind: KindExec, Name: "claude", ClaudeClient: true, Cmdline: `claude @modelcontextprotocol/server-filesystem /workspace`}, true},
		{"identified image under another process name", Observation{Kind: KindExec, Name: "indicator-task", ClaudeClient: true, Cmdline: `claude -p @modelcontextprotocol/server-filesystem`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, ok := Classify(tc.observation, IndicatorSet{})
			server := ok && match.Tactic == LocalInference && match.SignalID == "agent_local_mcp_server"
			if server != tc.wantServer {
				t.Fatalf("server classification = %t, want %t (match=%+v)", server, tc.wantServer, match)
			}
		})
	}
}
