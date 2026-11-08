// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// The gateway MCP inventory lists the servers of an openclaw.json that
// OpenClaw reads as JSON5 (GAP-0907).
func TestInventoryReadsMCPServersFromAJSON5OpenClawConfig(t *testing.T) {
	for name, in := range map[string]string{
		"plain json": `{"gateway":{"port":18789},"mcp":{"servers":{"demo":{"command":"echo"}}}}`,
		"json5":      "// mine\n{gateway:{port:0x4965,},mcp:{servers:{demo:{command:'echo',},},},}",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".openclaw", "openclaw.json"), []byte(in), 0o600); err != nil {
				t.Fatal(err)
			}
			got := readMCPServersUnderHomeForOS("openclaw", home, "linux")
			if len(got) != 1 || len(got[0]) != 1 || got[0][0].Name != "demo" {
				t.Fatalf("servers = %+v, want the one server demo", got)
			}
		})
	}
}
