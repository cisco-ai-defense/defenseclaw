// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

// rel-1-0-6:GAP-0258: only a refusal of the definition's own launcher is
// final. One that comes from the host is retried.
func TestMCPLauncherRefusalIsTheDefinitionOnly(t *testing.T) {
	for text, want := range map[string]bool{
		"ValueError: refusing to scan local MCP server 'a': command 'node' is not an allowlisted stdio launcher (allowed: npx, uvx)":                   true,
		"ValueError: refusing to scan local MCP server 'a': command '/usr/bin/npx' is a path, and paths are never an allowlisted stdio launcher":       true,
		"ValueError: refusing to scan local MCP server 'a': launcher 'npx' uses forbidden execution flag '-c'":                                         true,
		"ValueError: refusing to scan local MCP server 'a': launcher 'uvx' requires a package/server argument":                                         true,
		`MCP server "a" is not started: command "C:\\npx.cmd" is a path; a scan starts only the bare names npx or uvx`:                                 true,
		`MCP server "a" is not started: an npx argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd`:         true,
		`MCP server "a" is not started: the npx.cmd path contains a Windows command metacharacter`:                                                     false,
		`MCP server "a" is not started: npx.cmd is not on the PATH the server starts with`:                                                             false,
		`MCP server "a" is not started in server: the folder is not an absolute path`:                                                                  false,
		"ValueError: refusing to scan MCP URL 'http://127.0.0.1/': private address":                                                                    false,
		"MCPStdioLaunchError: local MCP launcher 'npx' argument contains a Windows command metacharacter that cannot be passed safely through npx.cmd": false,
		"scanner: mcp-scanner exited 1: TimeoutError":                                                                                                  false,
		"command 'node' is not an allowlisted stdio launcher":                                                                                          false, // not a scan refusal
	} {
		if got := MCPLauncherRefusal(text); got != want {
			t.Errorf("MCPLauncherRefusal(%q) = %v, want %v", text, got, want)
		}
	}
}
