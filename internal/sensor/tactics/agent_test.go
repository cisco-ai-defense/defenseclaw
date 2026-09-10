// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

// TestMCPDetectionRequiresRunningOneNotNamingOne is a lineage-gate defence.
//
// The MCP token used to be matched anywhere in the command line, so a text
// editor opening a file named mcp-server.py became an agent process. An agent
// identity opens the gate for that process and every descendant, so the
// editor became an agent root and ordinary work beneath it became scoreable.
// Naming a file must not do that.
func TestMCPDetectionRequiresRunningOneNotNamingOne(t *testing.T) {
	for _, test := range []struct {
		name    string
		cmdline string
		want    bool
	}{
		// Real launch shapes.
		{"the binary itself", "/opt/tools/mcp-server-filesystem --root /", true},
		{"through node", "node /opt/mcp-server-fs/index.js", true},
		{"through python -m", "python3 -m mcp_server_git --repo .", true},
		{"through npx", "npx @modelcontextprotocol/server-filesystem /tmp", true},
		{"through uvx", "uvx mcp-server-fetch", true},
		{"reversed token", "/usr/local/bin/server-mcp-sqlite", true},

		// Merely naming one.
		{"an editor opening a file", "vim mcp-server.py", false},
		{"grep over a log", "grep mcp_server /var/log/system.log", false},
		{"opening a note", "open notes/modelcontextprotocol.md", false},
		{"a copy", "cp mcp-server.json /tmp/backup/", false},
		{"an argument to something unrelated", "tar czf out.tgz mcp-server/", false},

		// An interpreter given a flag before the script still resolves.
		{"node with a flag first", "node --enable-source-maps /srv/mcp-server/main.js", true},
		{"node running something else entirely", "node /srv/app/index.js --mcp-server-url x", false},

		{"empty", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := AgentCmdlineReason(test.cmdline) == "MCP server process"
			if got != test.want {
				t.Fatalf("AgentCmdlineReason(%q) MCP = %v, want %v",
					test.cmdline, got, test.want)
			}
		})
	}
}

// TestAgentIdentityFromInstallPath covers the two shapes where the
// executable's own name says nothing.
//
// Both were found on a real macOS host. Claude Code's native install names
// the binary after its version, and a shell-script agent reaches Endpoint
// Security as /bin/bash with the script in argv -- Linux does not, because
// the kernel sets comm from the script. Either miss makes every child of
// the agent fail the lineage gate, which reports a busy machine as quiet.
func TestAgentIdentityFromInstallPath(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		exeName string
		cmdline string
		want    string
	}{
		{
			name:    "version-named binary under the agent's install root",
			exeName: "/Users/dev/.local/share/claude/versions/2.1.267",
			cmdline: "/Users/dev/.local/share/claude/versions/2.1.267 --print",
			want:    "claude",
		},
		{
			name:    "dot-prefixed install directory",
			exeName: "/Users/dev/.claude/bin/runner",
			cmdline: "/Users/dev/.claude/bin/runner",
			want:    "claude",
		},
		{
			name:    "shell script agent reaching us as its interpreter",
			exeName: "/bin/bash",
			cmdline: "/bin/bash /usr/local/bin/claude",
			want:    "claude",
		},
		{
			name:    "windows install path with backslashes",
			exeName: `C:\Users\dev\AppData\Local\cursor\app\host.exe`,
			cmdline: `C:\Users\dev\AppData\Local\cursor\app\host.exe`,
			want:    "cursor",
		},
		{
			name:    "executable name still wins when it matches",
			exeName: "/opt/anything/claude",
			cmdline: "/opt/anything/claude",
			want:    "claude",
		},
		// The false positives this must not produce. A path segment is only
		// an agent when the whole segment matches, so ordinary files that
		// merely sit near an agent-shaped word stay quiet.
		{
			name:    "a source checkout is not an agent",
			exeName: "/home/dev/src/claude-utils/build/tool",
			cmdline: "/home/dev/src/claude-utils/build/tool",
		},
		{
			name:    "a file inside a config dir is not the agent itself",
			exeName: "/usr/bin/grep",
			cmdline: "/usr/bin/grep -r token /home/dev/.claude/settings.json",
		},
		{
			name:    "an unrelated binary with no agent anywhere",
			exeName: "/usr/bin/sshd",
			cmdline: "/usr/bin/sshd -D",
		},
		{
			name:    "bare interpreter with no script",
			exeName: "/bin/bash",
			cmdline: "/bin/bash",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := AgentIdentity(test.exeName, test.cmdline); got != test.want {
				t.Fatalf("AgentIdentity(%q, %q) = %q, want %q",
					test.exeName, test.cmdline, got, test.want)
			}
		})
	}
}
