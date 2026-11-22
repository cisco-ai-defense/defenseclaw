// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

// TestGAP1190MCPServerStartIsAnchored is rel-1-0-10 GAP-1190: the exec
// classifier reported "agent started a local MCP tool server" for any command
// line that named one (claude -> sh -> cat mcp-server-x.json). A server start
// is a command that runs the server, read past its launchers with the
// program table's wrapper rows, so a wrapped real launch still fires and a
// command that only names a server does not. The quiet half is red on
// a64bfdb931 (1.0.10); the firing half is green on both and guards against a
// reading that is weaker than 1.0.10.
func TestGAP1190MCPServerStartIsAnchored(t *testing.T) {
	t.Parallel()
	const home = "/home/dev"
	indicators := IndicatorsFor("linux")
	for _, tc := range []struct {
		name, process, cmdline string
		server                 bool
	}{
		// --- names a server, runs something else (red on 1.0.10) ---
		{"cat a server config", "cat", "cat mcp-server-x.json", false},
		{"cat under a shell", "bash", "bash -c 'cat /srv/dccert/mcp-server-dccert.json'", false},
		{"cat as a Claude Code tool call", "bash", claudeToolCall(home, "cat mcp-server-x.json"), false},
		{"grep a log", "grep", "grep -r mcp_server /var/log/app.log", false},
		{"page through the server source", "less", "less mcp-server.py", false},
		{"inline code names a server", "python3", "python3 -c 'print(1)' mcp-server-x", false},
		{"sudo reads a server config", "sudo", "sudo cat /etc/mcp-server/config.json", false},
		{"nohup tails a server log", "nohup", "nohup tail -f mcp-server.log", false},
		{"env runs grep", "env", "env LC_ALL=C grep -n mcp_server app.log", false},
		{"Windows type", "cmd.exe", `cmd.exe /c type C:\srv\mcp-server-x.json`, false},
		{"pipeline reads a server package list", "bash", "bash -c 'npm ls | grep @modelcontextprotocol/server-filesystem'", false},

		// --- runs a server (green on 1.0.10 and after) ---
		{"plain npx", "npx", "npx -y @modelcontextprotocol/server-filesystem /tmp", true},
		{"env assignment", "env", "env X=1 node mcp-server.js", true},
		{"sh -c", "sh", "sh -c 'node mcp-server.js'", true},
		{"docker run", "docker", "docker run -i --rm ghcr.io/acme/mcp-server-git", true},
		{"podman run with options", "podman", "podman run --rm -e TOKEN=x ghcr.io/acme/mcp-server-git", true},
		{"stdbuf", "stdbuf", "stdbuf -o0 node /opt/mcp-server-fs/index.js", true},
		{"timeout", "timeout", "timeout 5 uvx mcp-server-git", true},
		{"nohup", "nohup", "nohup node mcp-server.js", true},
		{"/usr/bin/env", "env", "/usr/bin/env node mcp-server.js", true},
		{"setsid", "setsid", "setsid node /opt/mcp-server-fs/index.js", true},
		{"setsid sh -c", "setsid", "setsid sh -c 'npx -y @modelcontextprotocol/server-filesystem /'", true},
		{"chroot", "chroot", "chroot /srv node mcp-server.js", true},
		{"nice nohup python -m", "nice", "nice -n 5 nohup python3 -m mcp_server_git --repository .", true},
		{"server binary", "mcp-server-fetch", "/usr/local/bin/mcp-server-fetch --port 0", true},
		{"Claude Code tool call starts a server", "bash", claudeToolCall(home, "nohup npx -y @modelcontextprotocol/server-filesystem /tmp &"), true},
		{"Windows node.exe", "node.exe", `"C:\Program Files\nodejs\node.exe" C:\srv\mcp-server-weather\index.js`, true},
		{"cmd /c npx.cmd", "cmd.exe", `cmd.exe /c npx.cmd -y @modelcontextprotocol/server-filesystem C:\data`, true},

		// --- the program is not certain or not modeled: the 1.0.10 name match stays ---
		{"unknown env option", "env", "env --some-new-option node mcp-server.js", true},
		{"launcher with no child", "env", "env DOCS=@modelcontextprotocol/server-everything", true},
		{"unmodeled program", "vim", "vim mcp-server.py", true},
		{"unmodeled launcher", "fake", "/tmp/x/fake 300 node mcp-server.js", true},
		{"dynamic program", "bash", "bash -c '$RUNNER mcp-server-x'", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, ok := Classify(Observation{Kind: KindExec, Name: tc.process, Cmdline: tc.cmdline}, indicators)
			server := ok && match.Tactic == LocalInference && match.SignalID == "agent_local_mcp_server"
			if server != tc.server {
				t.Fatalf("Classify(%q) MCP server start = %t, want %t (match=%+v)", tc.cmdline, server, tc.server, match)
			}
		})
	}
}
