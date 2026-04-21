// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
)

func TestAuditLogActivityRegistryParity(t *testing.T) {
	reg := BuildRegistry()
	var found bool
	for _, e := range reg {
		if e.TUIName == "audit log-activity" {
			found = true
			if e.CLIBinary != "defenseclaw" {
				t.Fatalf("binary=%q", e.CLIBinary)
			}
			if len(e.CLIArgs) < 2 || e.CLIArgs[0] != "audit" || e.CLIArgs[1] != "log-activity" {
				t.Fatalf("args=%v", e.CLIArgs)
			}
			break
		}
	}
	if !found {
		t.Fatal("BuildRegistry missing audit log-activity")
	}
}

func TestAuditActivityTempFileSkipsWhenNoChanges(t *testing.T) {
	p := NewSetupPanel(DefaultTheme(), nil, NewCommandExecutor())
	path, cleanup, err := p.AuditActivityTempFile()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}

func TestRenderVerdictLine_ScanTypes(t *testing.T) {
	line := `{"ts":"2026-04-20T12:00:00Z","event_type":"scan","severity":"INFO","scan":{"scan_id":"z","scanner":"mcp-scanner","target":"u","verdict":"clean"}}`
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parse")
	}
	s := renderVerdictLine(row)
	if !strings.Contains(s, "mcp-scanner") || !strings.Contains(s, "z") {
		t.Fatalf("%q", s)
	}
}
