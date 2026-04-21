// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// newTestModelWithPlugin constructs a Model with a single plugin row
// preloaded so we can test the Plugins action-menu wiring without
// relying on `defenseclaw plugin list --json`. `Deps.Store` is left nil
// on purpose — action dispatch doesn't touch the audit store, and
// exercising the SQLite layer here would obscure what we're actually
// validating (CLI arg construction).
func newTestModelWithPlugin(item pluginItem) Model {
	m := New(Deps{
		Store:           nil,
		Config:          &config.Config{},
		OpenshellBinary: "openshell",
		AnchorName:      "openclaw",
		Version:         "test",
	})
	m.activePanel = PanelPlugins
	m.plugins.items = []pluginItem{item}
	m.plugins.loaded = true
	m.plugins.cursor = 0
	m.width = 120
	m.height = 40
	return m
}

// pressKey simulates a single key event. We use tea.KeyPressMsg because
// that's what handleKey's Update receives in production; synthesizing
// a raw rune here lets us test the key routing without opening a TTY.
func pressKey(key string) tea.KeyPressMsg {
	switch key {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	default:
		return tea.KeyPressMsg{Code: rune(key[0]), Text: key}
	}
}

func TestHandlePluginsKey_O_OpensActionMenuForSelection(t *testing.T) {
	m := newTestModelWithPlugin(pluginItem{
		Name:    "tutor",
		ID:      "plug_tutor",
		Version: "1.2.3",
		Origin:  "local",
		Status:  "installed",
		Verdict: "clean",
		Enabled: true,
	})

	if m.actionMenu.IsVisible() {
		t.Fatal("precondition: action menu must start hidden")
	}

	newM, cmd := m.handlePluginsKey(pressKey("o"))
	if cmd != nil {
		t.Fatalf("opening the action menu must not return a tea.Cmd (we're not running anything yet), got %v", cmd)
	}
	mm, ok := newM.(Model)
	if !ok {
		t.Fatalf("handlePluginsKey must return Model, got %T", newM)
	}
	if !mm.actionMenu.IsVisible() {
		t.Fatal("pressing 'o' with a selected plugin must surface the action menu")
	}
	if mm.actionMenu.title != "tutor" {
		t.Errorf("action menu title should be plugin name, got %q", mm.actionMenu.title)
	}
	if mm.actionMenu.status != "installed" {
		t.Errorf("action menu status should be plugin.Status, got %q", mm.actionMenu.status)
	}
	// Sanity-check the info pairs contain ID and Verdict — those are
	// the fields an operator wants visible while they pick a verb.
	pairs := map[string]string{}
	for _, kv := range mm.actionMenu.info {
		pairs[kv[0]] = kv[1]
	}
	if pairs["ID"] != "plug_tutor" {
		t.Errorf("info should include ID row, got %v", pairs)
	}
	if pairs["Verdict"] != "clean" {
		t.Errorf("info should include Verdict row, got %v", pairs)
	}
}

func TestHandlePluginsKey_O_UsesIDWhenNameBlank(t *testing.T) {
	// Some plugin manifests omit `name`. Falling back to ID keeps
	// the CLI dispatch correct (plugin allow needs *some* identifier)
	// and keeps the menu title informative instead of blank.
	m := newTestModelWithPlugin(pluginItem{
		Name:    "",
		ID:      "bare_id_42",
		Verdict: "clean",
		Status:  "installed",
	})
	newM, _ := m.handlePluginsKey(pressKey("o"))
	mm := newM.(Model)
	if mm.actionMenu.title != "bare_id_42" {
		t.Errorf("blank name should fall back to ID, got %q", mm.actionMenu.title)
	}
}

func TestHandlePluginsKey_O_NoopWithoutSelection(t *testing.T) {
	m := New(Deps{Config: &config.Config{}})
	m.activePanel = PanelPlugins
	m.plugins.loaded = true

	newM, cmd := m.handlePluginsKey(pressKey("o"))
	if cmd != nil {
		t.Errorf("empty plugin list must not produce a cmd, got %v", cmd)
	}
	mm := newM.(Model)
	if mm.actionMenu.IsVisible() {
		t.Error("action menu must stay hidden when there is no selection")
	}
}

// TestExecuteActionMenuItem_PluginDispatch verifies that every key
// surfaced by PluginActions is mapped to a real `defenseclaw plugin …`
// invocation. Missing entries would leave the menu silently no-op'ing
// on the operator, which is the exact class of bug P0-#2 is trying to
// prevent.
func TestExecuteActionMenuItem_PluginDispatch(t *testing.T) {
	m := newTestModelWithPlugin(pluginItem{
		Name:    "tutor",
		ID:      "plug_tutor",
		Status:  "installed",
		Verdict: "clean",
		Enabled: true,
	})

	// Union of keys across all PluginActions branches we care about.
	// Derive from PluginActions itself so the test re-syncs if new
	// verbs are added (we assert all PluginActions keys dispatch).
	seen := map[string]bool{}
	for _, verdict := range []string{"blocked", "allowed", "clean", "warning"} {
		for _, status := range []string{"installed", "quarantined"} {
			for _, enabled := range []bool{true, false} {
				for _, a := range PluginActions(verdict, status, enabled) {
					seen[a.Key] = true
				}
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("PluginActions returned no actions across test matrix — wiring broken")
	}

	for key := range seen {
		key := key
		t.Run("key_"+key, func(t *testing.T) {
			cmd := m.executeActionMenuItem(key)
			if cmd == nil {
				t.Fatalf("executeActionMenuItem(%q) returned nil — every PluginActions key must map to a CLI verb", key)
			}
		})
	}
}

func TestExecuteActionMenuItem_PluginDispatch_NilSelectionSafe(t *testing.T) {
	m := New(Deps{Config: &config.Config{}})
	m.activePanel = PanelPlugins
	// No items loaded — Selected() returns nil.
	if cmd := m.executeActionMenuItem("s"); cmd != nil {
		t.Errorf("executeActionMenuItem on empty plugin list must be a safe no-op, got %v", cmd)
	}
}
