// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

func TestSetupRevertKeyStaysInSetup(t *testing.T) {
	m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
	m.activePanel = PanelSetup
	m.setup.mode = setupModeConfig

	next, _ := m.handleKey(pressKey("R"))
	got := next.(Model)
	if got.activePanel != PanelSetup {
		t.Fatalf("R in setup should be handled by setup, got panel %s", panelNames[got.activePanel])
	}
}

func TestPanelSpecificRStaysPanelLocal(t *testing.T) {
	for _, panel := range []int{PanelOverview, PanelLogs, PanelSkills, PanelMCPs} {
		t.Run(panelNames[panel], func(t *testing.T) {
			m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
			m.activePanel = panel
			next, _ := m.handleKey(pressKey("R"))
			got := next.(Model)
			if got.activePanel == PanelRegistries && panel != PanelSkills && panel != PanelMCPs {
				t.Fatalf("R on %s should not jump directly to Registries", panelNames[panel])
			}
		})
	}
}

func TestPanelSpecificDigitsStayPanelLocal(t *testing.T) {
	cases := []struct {
		panel int
		key   string
	}{
		{PanelLogs, "2"},
		{PanelRegistries, "2"},
	}
	for _, tc := range cases {
		t.Run(panelNames[tc.panel], func(t *testing.T) {
			m := New(Deps{Config: config.DefaultConfig(), Version: "test"})
			m.activePanel = tc.panel
			next, _ := m.handleKey(pressKey(tc.key))
			got := next.(Model)
			if got.activePanel != tc.panel {
				t.Fatalf("%s in %s should stay panel-local, got %s", tc.key, panelNames[tc.panel], panelNames[got.activePanel])
			}
		})
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
