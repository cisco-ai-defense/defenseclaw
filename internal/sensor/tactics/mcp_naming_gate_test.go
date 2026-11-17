// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

// TestNamingAnMCPServerDoesNotMakeAnAgentRoot pins GAP-1163. An argument
// that names an MCP server package or config file is not an agent: before
// the fix the unanchored "MCP server entry point" and "MCP server package"
// patterns made each of these command lines an agent root of its own, so
// the host plane reported local_inference T1059 for an interactive shell
// with no agent above it. The command lines are the ones a cert host showed.
func TestNamingAnMCPServerDoesNotMakeAnAgentRoot(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, exe, cmdline string }{
		{"python inline code with a positional argument", "python3", "python3 -c import time; time.sleep(45) mcp-server-dccert"},
		{"cat of a config file", "cat", "cat /srv/dccert-redo-L35/mcp-server-dccert.json"},
		{"shell command string", "bash", "bash -c cat /srv/dccert/mcp-server-dccert.json"},
		{"copy of a config", "cp", "cp mcp-server-x.json /tmp/backup/"},
		{"grep for a package", "grep", "grep -r @modelcontextprotocol/ ."},
		{"installing is not running", "npm", "npm install @modelcontextprotocol/server-filesystem"},
		{"node inline code", "node", "node -e console.log(1) mcp-server-x"},
		{"uv pip install", "uv", "uv pip install mcp-server-fetch"},
	} {
		if reason := AgentCmdlineReason(test.cmdline); reason != "" {
			t.Errorf("%s: AgentCmdlineReason(%q) = %q, want no agent", test.name, test.cmdline, reason)
		}
		if root := IdentifyAgent("/usr/bin/"+test.exe, test.exe, test.cmdline); root.Name != "" {
			t.Errorf("%s: IdentifyAgent(%q) = %q, want no agent root", test.name, test.cmdline, root.Name)
		}
	}
}

// TestMCPServerLaunchShapesStayAgents keeps the true positives the removed
// patterns used to catch: a package runner names a subcommand before the
// server it runs.
func TestMCPServerLaunchShapesStayAgents(t *testing.T) {
	t.Parallel()
	for _, cmdline := range []string{
		"uv run mcp-server-git --repository .",
		"uv tool run mcp-server-fetch",
		"pipx run mcp-server-time",
		"npm exec @modelcontextprotocol/server-filesystem /tmp",
		"npm exec -- @modelcontextprotocol/server-filesystem /tmp",
		"pnpm dlx @modelcontextprotocol/server-memory",
		"yarn dlx @modelcontextprotocol/server-memory",
		"bunx @modelcontextprotocol/server-filesystem /tmp",
		"bun x mcp-server-fetch",
		"deno run --allow-net /srv/mcp-server-weather/main.ts",
		"deno /srv/mcp-server-weather/main.ts",
		"npx -y @modelcontextprotocol/server-filesystem /tmp",
		"node /opt/mcp-server-fs/index.js",
		"python3 -m mcp_server_git",
		"/opt/tools/mcp-server-filesystem --root /",
	} {
		if reason := AgentCmdlineReason(cmdline); reason != "MCP server process" {
			t.Errorf("AgentCmdlineReason(%q) = %q, want MCP server process", cmdline, reason)
		}
	}
}
