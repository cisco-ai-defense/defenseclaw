// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import "testing"

// GAP-1273: the filesystem MCP server Claude Code starts runs as
// "npm exec @modelcontextprotocol/server-filesystem <project>", one process
// title. A project folder named claude made the title's last path read as
// the Claude Code CLI, so verify reported an uninspected Claude session. A
// package runner's title is not an agent; real agent processes still are.
func TestAgentCLIOfDoesNotTakeAPackageRunnerTitleForTheAgent(t *testing.T) {
	for _, argv := range [][]string{
		{"npm exec @modelcontextprotocol/server-filesystem /home/u/projects/claude"},
		{"npx -y @modelcontextprotocol/server-filesystem /Users/u/claude   "},
	} {
		if got := agentCLIOf(argv); got != "" {
			t.Fatalf("agentCLIOf(%q) = %q, want no agent", argv, got)
		}
	}
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"claude"}, "claude"},
		{[]string{"claude          "}, "claude"},
		{[]string{"/usr/bin/node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, "claude"},
		{[]string{"/home/u/.local/bin/codex", "exec"}, "codex"},
	} {
		if got := agentCLIOf(tc.argv); got != tc.want {
			t.Fatalf("agentCLIOf(%q) = %q, want %q", tc.argv, got, tc.want)
		}
	}
}
