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
	"reflect"
	"strings"
	"testing"
)

// TestInventory_LoadCmdArgs_NoScope verifies the default case: no
// --only flag when scope is nil, so the scan covers everything.
// This is the CLI default and must survive round-trips through
// SetCategoryScope(nil).
func TestInventory_LoadCmdArgs_NoScope(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	got := p.loadCmdArgs()
	want := []string{"aibom", "scan", "--json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no-scope argv: got %v want %v", got, want)
	}
	p.SetCategoryScope(nil)
	if !reflect.DeepEqual(p.loadCmdArgs(), want) {
		t.Fatalf("SetCategoryScope(nil) should leave argv unchanged")
	}
	p.SetCategoryScope([]string{})
	if !reflect.DeepEqual(p.loadCmdArgs(), want) {
		t.Fatalf("SetCategoryScope([]) should behave like nil")
	}
}

// TestInventory_LoadCmdArgs_WithScope asserts that a non-empty
// scope translates to `--only cat1,cat2,...` in declared order,
// which is what cli/defenseclaw/commands/cmd_aibom.py expects
// (comma-separated, no spaces).
func TestInventory_LoadCmdArgs_WithScope(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	p.SetCategoryScope([]string{"skills", "plugins"})
	got := p.loadCmdArgs()
	want := []string{"aibom", "scan", "--json", "--only", "skills,plugins"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scoped argv: got %v want %v", got, want)
	}
}

// TestInventory_SetCategoryScope_FiltersUnknown makes sure a
// malformed scope (e.g. persisted from an older binary that knew
// extra categories) doesn't land a bogus value on the CLI. Unknown
// entries are silently dropped.
func TestInventory_SetCategoryScope_FiltersUnknown(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	p.SetCategoryScope([]string{"skills", "bogus", "plugins"})
	got := p.CategoryScope()
	want := []string{"skills", "plugins"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filter-unknown: got %v want %v", got, want)
	}

	p.SetCategoryScope([]string{"nothing", "real", "here"})
	if p.CategoryScope() != nil {
		t.Fatalf("all-unknown should clear scope, got %v", p.CategoryScope())
	}
}

// TestInventory_ToggleCategory exercises the per-chip toggle. This
// is not wired to a key today but is the building block for future
// per-chip hotkeys, so it must round-trip cleanly.
func TestInventory_ToggleCategory(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)

	p.ToggleCategory("skills")
	if !reflect.DeepEqual(p.CategoryScope(), []string{"skills"}) {
		t.Fatalf("toggle add: got %v", p.CategoryScope())
	}

	p.ToggleCategory("plugins")
	if !reflect.DeepEqual(p.CategoryScope(), []string{"skills", "plugins"}) {
		t.Fatalf("toggle add 2: got %v", p.CategoryScope())
	}

	p.ToggleCategory("skills")
	if !reflect.DeepEqual(p.CategoryScope(), []string{"plugins"}) {
		t.Fatalf("toggle remove: got %v", p.CategoryScope())
	}

	p.ToggleCategory("plugins")
	if p.CategoryScope() != nil {
		t.Fatalf("toggle to empty should be nil, got %v", p.CategoryScope())
	}

	// Unknown category is a no-op; the scope must stay nil so
	// a typo doesn't silently add garbage to --only.
	p.ToggleCategory("bogus")
	if p.CategoryScope() != nil {
		t.Fatalf("toggle unknown should not mutate, got %v", p.CategoryScope())
	}
}

// TestInventory_ToggleFastScan is the key used by the 'o' keybind.
// Cycle: nil -> fastScanCategories -> nil. Critical path.
func TestInventory_ToggleFastScan(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)

	p.ToggleFastScan()
	if !p.isFastScan() {
		t.Fatalf("first toggle should enable fast scan, got %v", p.CategoryScope())
	}
	if !reflect.DeepEqual(p.CategoryScope(), fastScanCategories) {
		t.Fatalf("fast scope mismatch: got %v want %v", p.CategoryScope(), fastScanCategories)
	}

	p.ToggleFastScan()
	if p.CategoryScope() != nil {
		t.Fatalf("second toggle should clear scope, got %v", p.CategoryScope())
	}
	if p.isFastScan() {
		t.Fatalf("cleared scope should not be fast-scan")
	}
}

// TestInventory_ToggleFastScan_FromManualScope makes sure the
// fast toggle doesn't try to union/intersect with an in-progress
// manual scope — it should replace outright so operators have a
// reliable "reset to fast" path.
func TestInventory_ToggleFastScan_FromManualScope(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	p.SetCategoryScope([]string{"agents", "models"})
	p.ToggleFastScan()
	if !p.isFastScan() {
		t.Fatalf("fast toggle from manual scope should replace: got %v", p.CategoryScope())
	}
}

// TestInventory_IsFastScan_OrderIndependent guards against a
// naive reflect.DeepEqual that would mis-classify a reordered but
// equivalent scope.
func TestInventory_IsFastScan_OrderIndependent(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	p.SetCategoryScope([]string{"mcp", "skills", "plugins"})
	if !p.isFastScan() {
		t.Fatalf("reordered fast scope should still be fast, got %v", p.CategoryScope())
	}
}

// TestInventory_Categories_MatchCLI locks in the category list so
// a CLI change forces us to update both sides. If this ever
// fails, update InventoryCategories and the CLI choice list in
// cli/defenseclaw/commands/cmd_aibom.py together.
func TestInventory_Categories_MatchCLI(t *testing.T) {
	want := []string{"skills", "plugins", "mcp", "agents", "tools", "models", "memory"}
	if !reflect.DeepEqual(InventoryCategories, want) {
		t.Fatalf("InventoryCategories drifted from CLI --only choices: got %v want %v",
			InventoryCategories, want)
	}
}

// TestInventory_FastPresetStability ensures the fast preset is
// the security-review subset (skills/plugins/mcp) — if this ever
// changes update the hint text in inventoryHint() and the docs.
func TestInventory_FastPresetStability(t *testing.T) {
	want := []string{"skills", "plugins", "mcp"}
	if !reflect.DeepEqual(fastScanCategories, want) {
		t.Fatalf("fast preset changed: got %v want %v", fastScanCategories, want)
	}
}

// TestInventory_LoadCmdArgs_OnlyFlagFormat validates the exact
// string format of the --only value — the CLI expects comma-
// separated with no whitespace.
func TestInventory_LoadCmdArgs_OnlyFlagFormat(t *testing.T) {
	p := NewInventoryPanel(nil, nil, nil)
	p.SetCategoryScope([]string{"skills", "plugins", "mcp"})
	argv := p.loadCmdArgs()
	// Find --only and inspect its value.
	found := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--only" {
			v := argv[i+1]
			if strings.Contains(v, " ") {
				t.Fatalf("--only value must not contain spaces: %q", v)
			}
			if v != "skills,plugins,mcp" {
				t.Fatalf("--only value: got %q want %q", v, "skills,plugins,mcp")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("--only flag missing from argv: %v", argv)
	}
}
