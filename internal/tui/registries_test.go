// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// writeIndex creates a fake on-disk verdict index for sourceID under
// dataDir, mirroring the layout written by
// cli/defenseclaw/registries/cache.py::save_index.
func writeIndex(t *testing.T, dataDir, sourceID string, index map[string]any) {
	t.Helper()
	dir := filepath.Join(dataDir, "registries", sourceID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "index.json")
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func newRegistriesPanelForTest(t *testing.T) (*RegistriesPanel, string) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{
		DataDir: dataDir,
		Registries: config.RegistriesConfig{
			Sources: []config.RegistrySource{
				{
					ID:      "corp-skills",
					Kind:    "http_yaml",
					URL:     "https://catalog.example.com/skills.yaml",
					Content: "skill",
					Enabled: true,
				},
				{
					ID:      "smithery-public",
					Kind:    "smithery",
					Content: "mcp",
					Enabled: false,
				},
			},
		},
	}
	p := NewRegistriesPanel(cfg, nil)
	p.SetSize(120, 40)
	return &p, dataDir
}

func TestRegistriesPanelLoadsSources(t *testing.T) {
	p, _ := newRegistriesPanelForTest(t)
	if got := p.RowCount(); got != 2 {
		t.Fatalf("RowCount = %d, want 2 (sources tab)", got)
	}
	src := p.SelectedSource()
	if src == nil {
		t.Fatal("SelectedSource returned nil on Sources tab")
	}
	// Sources are sorted by id, so corp-skills sorts before
	// smithery-public.
	if src.ID != "corp-skills" {
		t.Fatalf("first source id = %q, want corp-skills", src.ID)
	}
}

func TestRegistriesPanelTabSwitchResetsCursor(t *testing.T) {
	p, _ := newRegistriesPanelForTest(t)
	p.CursorDown()
	if p.Cursor() != 1 {
		t.Fatalf("Cursor() = %d, want 1", p.Cursor())
	}
	p.SetTab(registriesTabEntries)
	if p.Cursor() != 0 {
		t.Fatalf("tab change should reset cursor; got %d", p.Cursor())
	}
	if p.CurrentTab() != registriesTabEntries {
		t.Fatalf("CurrentTab = %d, want %d", p.CurrentTab(), registriesTabEntries)
	}
}

func TestRegistriesPanelEntriesTabReadsIndex(t *testing.T) {
	p, dataDir := newRegistriesPanelForTest(t)
	writeIndex(t, dataDir, "corp-skills", map[string]any{
		"source_id": "corp-skills",
		"verdicts": []map[string]any{
			{
				"name":     "demo-skill",
				"type":     "skill",
				"status":   "clean",
				"approved": false,
			},
			{
				"name":     "blocked-skill",
				"type":     "skill",
				"status":   "blocked",
				"severity": "HIGH",
			},
		},
	})
	p.Refresh()
	p.SetTab(registriesTabEntries)
	if p.RowCount() != 2 {
		t.Fatalf("entries RowCount = %d, want 2", p.RowCount())
	}
	row := p.SelectedEntry()
	if row == nil {
		t.Fatal("SelectedEntry returned nil")
	}
	if row.SourceID != "corp-skills" {
		t.Errorf("SourceID = %q", row.SourceID)
	}
}

func TestRegistriesPanelApprovedFilter(t *testing.T) {
	p, dataDir := newRegistriesPanelForTest(t)
	writeIndex(t, dataDir, "corp-skills", map[string]any{
		"verdicts": []map[string]any{
			{"name": "a", "type": "skill", "status": "clean", "approved": true},
			{"name": "b", "type": "skill", "status": "clean", "approved": false},
		},
	})
	p.Refresh()
	p.SetTab(registriesTabApproved)
	if p.RowCount() != 1 {
		t.Fatalf("approved RowCount = %d, want 1", p.RowCount())
	}
	row := p.SelectedEntry()
	if row == nil || row.Name != "a" {
		t.Fatalf("approved row = %+v, want name=a", row)
	}
}

func TestRegistriesPanelFocusEntry(t *testing.T) {
	p, dataDir := newRegistriesPanelForTest(t)
	writeIndex(t, dataDir, "corp-skills", map[string]any{
		"verdicts": []map[string]any{
			{"name": "a", "type": "skill", "status": "clean"},
			{"name": "b", "type": "skill", "status": "clean"},
		},
	})
	p.Refresh()
	p.FocusEntry("skill", "b")
	if p.CurrentTab() != registriesTabEntries {
		t.Fatalf("FocusEntry should switch to Entries tab")
	}
	row := p.SelectedEntry()
	if row == nil || row.Name != "b" {
		t.Fatalf("FocusEntry didn't land on requested entry: %+v", row)
	}
}

func TestRegistriesPanelHandleKeyTabs(t *testing.T) {
	p, _ := newRegistriesPanelForTest(t)
	if handled, _, _, _ := p.HandleKey("2"); !handled {
		t.Fatal("'2' should switch to Entries tab")
	}
	if p.CurrentTab() != registriesTabEntries {
		t.Fatalf("after '2', CurrentTab = %d", p.CurrentTab())
	}
	if handled, _, _, _ := p.HandleKey("3"); !handled {
		t.Fatal("'3' should switch to Approved tab")
	}
	if p.CurrentTab() != registriesTabApproved {
		t.Fatalf("after '3', CurrentTab = %d", p.CurrentTab())
	}
}

func TestRegistriesPanelHandleKeySync(t *testing.T) {
	p, _ := newRegistriesPanelForTest(t)
	handled, label, args, _ := p.HandleKey("s")
	if !handled {
		t.Fatal("'s' should be handled")
	}
	if !strings.Contains(label, "registry sync") {
		t.Fatalf("label = %q", label)
	}
	if len(args) < 3 || args[0] != "registry" || args[1] != "sync" {
		t.Fatalf("args = %v, want [registry sync corp-skills ...]", args)
	}
}

func TestRegistriesPanelHandleKeyApproveRequiresSelection(t *testing.T) {
	p, _ := newRegistriesPanelForTest(t)
	p.SetTab(registriesTabEntries)
	handled, label, args, hint := p.HandleKey("a")
	if !handled {
		t.Fatal("'a' on Entries tab should be handled")
	}
	if label != "" || args != nil {
		t.Fatalf("approve with no rows should not dispatch a command (label=%q, args=%v)",
			label, args)
	}
	if !strings.Contains(hint, "no entry selected") {
		t.Fatalf("hint = %q", hint)
	}
}

func TestLoadRegistryIndexRejectsUnsafeIDs(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../escape", "a/b", "x.y"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := loadRegistryIndex(dir, bad); err == nil {
				t.Errorf("loadRegistryIndex(%q) should fail", bad)
			}
		})
	}
}

func TestLoadRegistryIndexMissingFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadRegistryIndex(dir, "no-such"); err == nil {
		t.Fatal("missing index file should produce an error")
	}
}
