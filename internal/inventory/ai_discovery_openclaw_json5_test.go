// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// AI discovery lists the MCP servers of an openclaw.json that OpenClaw reads
// as JSON5 (GAP-0907). The twin keeps the plain file and the other agents'
// shapes where they were.
func TestDiscoveryReadsMCPServersFromAJSON5OpenClawConfig(t *testing.T) {
	for name, in := range map[string]string{
		"plain json": `{"gateway":{"port":18789},"mcp":{"servers":{"demo":{"command":"echo"}}}}`,
		"json5":      "// mine\n{gateway:{port:0x4965,},mcp:{servers:{demo:{command:'echo',},},},}",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "openclaw.json")
			if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
				t.Fatal(err)
			}
			if shape := mcpConfigShape(path, "openclaw"); shape != mcpShapeOpenClaw {
				t.Fatalf("shape = %q, want %q", shape, mcpShapeOpenClaw)
			}
			got, err := parseMCPConfigForNames(path, "openclaw")
			if err != nil {
				t.Fatalf("parseMCPConfigForNames: %v", err)
			}
			if len(got) != 1 || got[0].Name != "demo" {
				t.Fatalf("servers = %+v, want demo", got)
			}
		})
	}
}

func TestDiscoveryKeepsZeptoClawConfigOnTheNestedShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zeptoclaw", "config.json")
	if shape := mcpConfigShape(path, "zeptoclaw"); shape != mcpShapeNestedServers {
		t.Fatalf("shape = %q, want %q", shape, mcpShapeNestedServers)
	}
}
