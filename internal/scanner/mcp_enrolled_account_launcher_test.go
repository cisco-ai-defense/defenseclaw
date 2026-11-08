// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A local server of an enrolled account that a managed Linux or macOS
// gateway lists (the hook reported it) is refused from its launcher before
// anything starts, in the words of the Python scanner, so the refusal is a
// verdict about the definition (GAP-0925). A launcher a scan starts is not
// decided here.
func TestEnrolledAccountLocalServerWithRefusedLauncherIsRefusedWithoutStarting(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		refused       bool
	}{
		{"interpreter", "python3", true},
		{"node", "node", true},
		{"command path", "/usr/bin/python3", true},
		{"allowlisted npx", "npx", false},
		{"allowlisted uvx", "uvx", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The binary does not exist: a scan that got past the refusal
			// would fail in the preflight with a different message.
			scan := &MCPScanner{
				Config: config.MCPScannerConfig{Binary: "/nonexistent/defenseclaw-scanner"},
				ServerEntry: &config.MCPServerEntry{Name: "localpy", Command: tc.command, Args: []string{"/home/eng1/server.py"},
					Connector: "claudecode", Home: "/home/eng1"},
			}
			_, err := scan.Scan(context.Background(), "localpy")
			if err == nil {
				t.Fatal("scan of a server with a missing scanner binary succeeded")
			}
			if got := MCPScanRefused(err) && MCPLauncherRefusal(err.Error()); got != tc.refused {
				t.Fatalf("command %q: launcher refusal=%v (%v), want %v", tc.command, got, err, tc.refused)
			}
			if tc.refused && !strings.Contains(err.Error(), "allowlisted stdio launcher") {
				t.Fatalf("refusal %q does not carry the scanner's wording", err)
			}
		})
	}
}

// The same definition without an account home is a per-user gateway's own
// server, scanned as before.
func TestLocalServerWithoutAccountHomeIsNotRefusedByTheEnrolledAccountCheck(t *testing.T) {
	scan := &MCPScanner{
		Config:      config.MCPScannerConfig{Binary: "/nonexistent/defenseclaw-scanner"},
		ServerEntry: &config.MCPServerEntry{Name: "localpy", Command: "python3", Args: []string{"server.py"}},
	}
	_, err := scan.Scan(context.Background(), "localpy")
	if err == nil || MCPLauncherRefusal(err.Error()) {
		t.Fatalf("a per-user gateway's server was refused by the enrolled-account check: %v", err)
	}
}
