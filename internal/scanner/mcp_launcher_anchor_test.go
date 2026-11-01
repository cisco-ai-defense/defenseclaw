// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

// rel-1-0-6:GAP-0364: only the scanner's own launcher refusal, where its
// message starts, is final. Text that quotes one (an MCP error that carries
// the server's words, a server's stderr echoed by the scanner, stderr after
// a timeout) is a failure that is retried.
func TestMCPLauncherRefusalOnlyAtTheScannerMessageStart(t *testing.T) {
	quoted := "refusing to scan local MCP server 'x': command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx)"
	for text, want := range map[string]bool{
		// The scanner's own refusal, as each path reports it.
		"scanner failure (fail-closed): scanner mcp-scanner exited 1 (scan failed: " + quoted + "; stderr=)":                                                                                                                                               true,
		"scanner failure (fail-closed): scanner: mcp-scanner exited 1: ValueError: " + quoted:                                                                                                                                                              true,
		"scanner mcp-scanner exited 1 (the server was not started in its folder /h/p; it ran in the scanner folder instead: scan failed: " + quoted + "; stderr=)":                                                                                         true,
		`scanner: mcp-scanner exited 1: [npx stderr] mcp as-user scan: the hook enumerator did not start the server: MCP server "x" is not started: an npx argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd`: true,
		// Text that only quotes one.
		"scanner failure (fail-closed): scanner mcp-scanner exited 1 (scan failed: McpError: " + quoted + "; stderr=)":                                                              false,
		"scanner: mcp-scanner exited 1: TimeoutError: no answer; it said: " + quoted:                                                                                                false,
		"scanner: mcp-scanner exited 1: [node stderr] " + quoted:                                                                                                                    false,
		"scanner mcp-scanner exited 1 (scan failed: timed out waiting for the server; stderr=ValueError: " + quoted + ")":                                                           false,
		`scanner: mcp-scanner exited 1: [npx stderr] hello MCP server "x" is not started: an npx argument contains a Windows command metacharacter`:                                 false,
		"scanner mcp-scanner exited 1 (scan failed: refusing to scan local MCP server 'x': the folder is not a path; command 'node' is not an allowlisted stdio launcher; stderr=)": false,
	} {
		if got := MCPLauncherRefusal(text); got != want {
			t.Errorf("MCPLauncherRefusal(%q) = %v, want %v", text, got, want)
		}
	}
}
