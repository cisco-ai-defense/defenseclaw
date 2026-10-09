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

// TestIdentifyAgentPrefersTheExecutablePath pins the Exe identity: a native
// Claude Code install runs as a version-numbered binary, so its name alone is
// nothing, while the resolved path names the install. The name stays the
// fallback for a backend that reports no path.
func TestIdentifyAgentPrefersTheExecutablePath(t *testing.T) {
	t.Parallel()
	native := IdentifyAgent("/home/dev/.local/share/claude/versions/2.1.292", "2.1.292", "")
	if native.Name != "claude" || native.Basis != BasisInstallPath || native.Connector != "claudecode" {
		t.Fatalf("native install = %+v, want claude by install path, connector claudecode", native)
	}
	if byName := IdentifyAgent("", "2.1.292", ""); byName.Name != "" {
		t.Fatalf("the version-number name alone identified %+v", byName)
	}
	if fallback := IdentifyAgent("", "claude", "claude"); fallback.Name != "claude" || fallback.Connector != "claudecode" {
		t.Fatalf("name fallback = %+v", fallback)
	}
	npm := IdentifyAgent("/usr/bin/node", "node", "/usr/bin/node /home/dev/.npm-global/bin/claude --resume")
	if npm.Name != "claude" || npm.Basis != BasisScript || npm.Connector != "claudecode" {
		t.Fatalf("npm install = %+v, want claude by script", npm)
	}
	if windows := IdentifyAgent(`C:\Tools\codex.exe`, "", ""); windows.Connector != "codex" {
		t.Fatalf("windows codex = %+v, want connector codex", windows)
	}
}

// TestIdentifyAgentMarksObserveOnlyRoots pins the D11 rule as the gateway
// sees it: heuristics and IDE-hosted surfaces attribute activity, but only a
// CLI connector named by its executable, install or script can ever be an
// enforcement root, and no argv match names a connector.
func TestIdentifyAgentMarksObserveOnlyRoots(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, exe, cmdline string
		wantName           string
		wantConnector      string
		wantObserveOnly    string
	}{
		{"cli connector", "/usr/local/bin/codex", "codex", "codex", "codex", ""},
		{"cursor cli", "/home/dev/.local/share/cursor-agent/versions/1/cursor-agent", "", "cursor-agent", "cursor", ""},
		{"cursor ide", `C:\Users\dev\AppData\Local\cursor\app\host.exe`, "", "cursor", "", RootIDEHosted},
		{"copilot language server", "/opt/ext/copilot-language-server", "", "copilot-language-server", "", RootIDEHosted},
		{"tmux named after a framework", "/usr/bin/tmux", "tmux new -s langchain", "tmux", "", RootHeuristic},
		{"framework module", "/usr/bin/python3", "python3 -m crewai run", "python3", "", RootHeuristic},
		{"mcp server", "/usr/bin/node", "node /opt/mcp-server-git/index.js", "node", "", RootHeuristic},
		{"pattern-named non-connector", "/usr/local/bin/aider", "aider", "aider", "", RootHeuristic},
		{"not an agent", "/usr/bin/grep", "grep -r token .", "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := IdentifyAgent(test.exe, "", test.cmdline)
			if root.Name != test.wantName || root.Connector != test.wantConnector || root.ObserveOnly != test.wantObserveOnly {
				t.Fatalf("IdentifyAgent(%q, %q) = %+v, want name %q connector %q observe-only %q",
					test.exe, test.cmdline, root, test.wantName, test.wantConnector, test.wantObserveOnly)
			}
		})
	}
	if got := ConnectorForAgent("Claude.exe"); got != "claudecode" {
		t.Fatalf("ConnectorForAgent(Claude.exe) = %q", got)
	}
	if got := ConnectorForAgent("tmux"); got != "" {
		t.Fatalf("ConnectorForAgent(tmux) = %q, want none", got)
	}
}
