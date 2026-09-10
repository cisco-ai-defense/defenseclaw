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
