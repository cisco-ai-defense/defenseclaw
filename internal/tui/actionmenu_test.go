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
	"strings"
	"testing"
)

func testTheme() *Theme {
	return DefaultTheme()
}

func TestActionMenuVisibility(t *testing.T) {
	menu := NewActionMenu(testTheme())

	if menu.IsVisible() {
		t.Error("new menu should not be visible")
	}

	actions := []ActionItem{
		{Key: "s", Label: "Scan"},
		{Key: "b", Label: "Block"},
	}
	menu.Show("test-skill", "clean", nil, actions)

	if !menu.IsVisible() {
		t.Error("menu should be visible after Show")
	}

	menu.Hide()

	if menu.IsVisible() {
		t.Error("menu should not be visible after Hide")
	}
}

func TestActionMenuCursorNavigation(t *testing.T) {
	menu := NewActionMenu(testTheme())
	actions := []ActionItem{
		{Key: "s", Label: "Scan"},
		{Key: "b", Label: "Block"},
		{Key: "a", Label: "Allow"},
	}
	menu.Show("test", "clean", nil, actions)

	t.Run("initial_cursor_at_zero", func(t *testing.T) {
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "s" {
			t.Errorf("expected first action 's', got %v", sel)
		}
	})

	t.Run("cursor_down", func(t *testing.T) {
		menu.CursorDown()
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "b" {
			t.Errorf("expected 'b' after CursorDown, got %v", sel)
		}
	})

	t.Run("cursor_down_again", func(t *testing.T) {
		menu.CursorDown()
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "a" {
			t.Errorf("expected 'a' after second CursorDown, got %v", sel)
		}
	})

	t.Run("cursor_down_at_bottom_stays", func(t *testing.T) {
		menu.CursorDown()
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "a" {
			t.Errorf("expected 'a' (no change), got %v", sel)
		}
	})

	t.Run("cursor_up", func(t *testing.T) {
		menu.CursorUp()
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "b" {
			t.Errorf("expected 'b' after CursorUp, got %v", sel)
		}
	})

	t.Run("cursor_up_at_top_stays", func(t *testing.T) {
		menu.CursorUp()
		menu.CursorUp()
		sel := menu.SelectedAction()
		if sel == nil || sel.Key != "s" {
			t.Errorf("expected 's' (no change), got %v", sel)
		}
	})
}

func TestActionMenuShowResetsCursor(t *testing.T) {
	menu := NewActionMenu(testTheme())
	actions := []ActionItem{
		{Key: "s", Label: "Scan"},
		{Key: "b", Label: "Block"},
	}
	menu.Show("first", "", nil, actions)
	menu.CursorDown()

	menu.Show("second", "", nil, actions)
	sel := menu.SelectedAction()
	if sel == nil || sel.Key != "s" {
		t.Errorf("Show should reset cursor to 0, got %v", sel)
	}
}

func TestActionMenuViewHiddenReturnsEmpty(t *testing.T) {
	menu := NewActionMenu(testTheme())
	if menu.View() != "" {
		t.Error("hidden menu should return empty View")
	}
}

func TestActionMenuViewVisibleNotEmpty(t *testing.T) {
	menu := NewActionMenu(testTheme())
	menu.SetSize(80, 40)
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run scan"},
	}
	menu.Show("test-skill", "clean", [][2]string{{"Last scan", "2h ago"}}, actions)

	view := menu.View()
	if view == "" {
		t.Error("visible menu should return non-empty View")
	}
}

func TestSkillActions(t *testing.T) {
	// Post-P0-#4 rules: branches match the CLI's `skill` verbs
	// 1:1, and "restore" is gated on the quarantined status (not
	// the blocked one — a blocked skill is unrelated to quarantine
	// and offering restore there confused operators).
	t.Run("blocked_skill", func(t *testing.T) {
		actions := SkillActions("blocked")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "blocked should have scan")
		assertContains(t, keys, "i", "blocked should have info")
		assertContains(t, keys, "u", "blocked should have unblock")
		assertContains(t, keys, "a", "blocked should have allow (move to allow-list)")
		assertNotContains(t, keys, "b", "blocked should not have block")
		assertNotContains(t, keys, "r", "blocked should not have restore (that's for quarantined)")
	})

	t.Run("allowed_skill", func(t *testing.T) {
		actions := SkillActions("allowed")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "allowed should have scan")
		assertContains(t, keys, "b", "allowed should have block")
		assertContains(t, keys, "d", "allowed should have disable (runtime toggle)")
		assertNotContains(t, keys, "a", "allowed should not have allow (already allowed)")
		assertNotContains(t, keys, "u", "allowed should not have unblock")
	})

	t.Run("quarantined_skill", func(t *testing.T) {
		actions := SkillActions("quarantined")
		keys := actionKeys(actions)
		assertContains(t, keys, "r", "quarantined should have restore")
		assertNotContains(t, keys, "b", "quarantined should not offer block")
		assertNotContains(t, keys, "a", "quarantined should not offer allow")
	})

	t.Run("disabled_skill", func(t *testing.T) {
		actions := SkillActions("disabled")
		keys := actionKeys(actions)
		assertContains(t, keys, "e", "disabled should have enable")
		assertContains(t, keys, "b", "disabled should allow block (one-step lock-down)")
	})

	t.Run("default_skill", func(t *testing.T) {
		actions := SkillActions("clean")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "default should have scan")
		assertContains(t, keys, "i", "default should have info")
		assertContains(t, keys, "b", "default should have block")
		assertContains(t, keys, "a", "default should have allow")
		assertContains(t, keys, "d", "default should have disable")
		assertContains(t, keys, "q", "default should have quarantine")
		assertContains(t, keys, "n", "default should expose install")
	})

	t.Run("always_has_scan_and_info", func(t *testing.T) {
		for _, status := range []string{"blocked", "allowed", "clean", "warning", ""} {
			actions := SkillActions(status)
			keys := actionKeys(actions)
			assertContains(t, keys, "s", status+" should have scan")
			assertContains(t, keys, "i", status+" should have info")
		}
	})

	t.Run("no_duplicate_keys", func(t *testing.T) {
		for _, status := range []string{"blocked", "allowed", "quarantined", "disabled", "clean", ""} {
			seen := map[string]bool{}
			for _, a := range SkillActions(status) {
				if seen[a.Key] {
					t.Errorf("status=%s: duplicate key %q — would shadow on press", status, a.Key)
				}
				seen[a.Key] = true
			}
		}
	})
}

func TestMCPActions(t *testing.T) {
	t.Run("blocked_mcp", func(t *testing.T) {
		actions := MCPActions("blocked", "openclaw")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "blocked should have scan")
		assertContains(t, keys, "u", "blocked should have unblock")
		assertContains(t, keys, "x", "blocked should have unset")
		assertNotContains(t, keys, "b", "blocked should not have block")
	})

	t.Run("allowed_mcp", func(t *testing.T) {
		actions := MCPActions("allowed", "openclaw")
		keys := actionKeys(actions)
		assertContains(t, keys, "b", "allowed should have block")
		assertContains(t, keys, "x", "allowed should have unset")
		assertNotContains(t, keys, "u", "allowed should not have unblock")
	})

	t.Run("default_mcp", func(t *testing.T) {
		actions := MCPActions("clean", "openclaw")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "default should have scan")
		assertContains(t, keys, "b", "default should have block")
		assertContains(t, keys, "a", "default should have allow")
		assertNotContains(t, keys, "x", "default should not have unset")
	})

	t.Run("always_has_scan_and_info", func(t *testing.T) {
		for _, status := range []string{"blocked", "allowed", "clean", ""} {
			actions := MCPActions(status, "openclaw")
			keys := actionKeys(actions)
			assertContains(t, keys, "s", status+" should have scan")
			assertContains(t, keys, "i", status+" should have info")
		}
	})

	t.Run("zeptoclaw_unset_marked_read_only", func(t *testing.T) {
		actions := MCPActions("blocked", "zeptoclaw")
		var unset *ActionItem
		for i := range actions {
			if actions[i].Key == "x" {
				unset = &actions[i]
				break
			}
		}
		if unset == nil {
			t.Fatal("zeptoclaw should still surface the Unset action key (just with a read-only hint)")
			return
		}
		if !strings.Contains(strings.ToLower(unset.Description), "read-only") {
			t.Errorf("zeptoclaw unset description should mention read-only; got %q", unset.Description)
		}
	})

	t.Run("connector_specific_unset_target", func(t *testing.T) {
		cases := map[string]string{
			"openclaw":   "OpenClaw config",
			"claudecode": "~/.claude/settings.json",
			"codex":      "./.mcp.json",
			"zeptoclaw":  "~/.zeptoclaw/config.json",
		}
		for connector, want := range cases {
			actions := MCPActions("blocked", connector)
			var got string
			for _, a := range actions {
				if a.Key == "x" {
					got = a.Description
					break
				}
			}
			if !strings.Contains(got, want) {
				t.Errorf("connector=%q: unset description %q should mention %q", connector, got, want)
			}
		}
	})
}

func TestPluginActions(t *testing.T) {
	t.Run("blocked_and_disabled_surfaces_unblock_enable_quarantine", func(t *testing.T) {
		actions := PluginActions("blocked", "installed", false)
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "blocked should have scan")
		assertContains(t, keys, "i", "blocked should have info")
		assertContains(t, keys, "u", "blocked should expose unblock")
		assertContains(t, keys, "e", "disabled should expose enable")
		assertContains(t, keys, "q", "non-quarantined should expose quarantine")
		assertContains(t, keys, "x", "every plugin should expose remove")
		assertNotContains(t, keys, "b", "blocked must not re-expose block")
		assertNotContains(t, keys, "a", "blocked must not expose allow (unblock == allow)")
		assertNotContains(t, keys, "d", "disabled must not expose disable")
		assertNotContains(t, keys, "r", "non-quarantined must not expose restore")
	})

	t.Run("allowed_and_enabled_surfaces_block_disable_quarantine", func(t *testing.T) {
		actions := PluginActions("allowed", "installed", true)
		keys := actionKeys(actions)
		assertContains(t, keys, "b", "allowed should expose block")
		assertContains(t, keys, "d", "enabled should expose disable")
		assertContains(t, keys, "q", "non-quarantined should expose quarantine")
		assertContains(t, keys, "x", "every plugin should expose remove")
		assertNotContains(t, keys, "u", "allowed must not expose unblock")
		assertNotContains(t, keys, "a", "allowed must not re-expose allow")
		assertNotContains(t, keys, "e", "enabled must not expose enable")
	})

	t.Run("clean_plugin_exposes_block_and_allow", func(t *testing.T) {
		actions := PluginActions("clean", "installed", true)
		keys := actionKeys(actions)
		assertContains(t, keys, "b", "clean should expose block")
		assertContains(t, keys, "a", "clean should expose allow")
		assertContains(t, keys, "d", "enabled should expose disable")
	})

	t.Run("quarantined_plugin_exposes_restore_not_quarantine", func(t *testing.T) {
		actions := PluginActions("blocked", "quarantined", false)
		keys := actionKeys(actions)
		assertContains(t, keys, "r", "quarantined should expose restore")
		assertNotContains(t, keys, "q", "quarantined must not expose quarantine again")
	})

	t.Run("always_has_scan_info_remove", func(t *testing.T) {
		cases := []struct {
			verdict string
			status  string
			enabled bool
		}{
			{"blocked", "quarantined", false},
			{"allowed", "installed", true},
			{"clean", "", false},
			{"warning", "installed", true},
			{"", "", false},
		}
		for _, c := range cases {
			actions := PluginActions(c.verdict, c.status, c.enabled)
			keys := actionKeys(actions)
			label := c.verdict + "/" + c.status
			assertContains(t, keys, "s", label+": scan")
			assertContains(t, keys, "i", label+": info")
			assertContains(t, keys, "x", label+": remove")
		}
	})

	t.Run("no_duplicate_keys", func(t *testing.T) {
		// Duplicate keys would make the ActionMenu dispatcher
		// ambiguous — the first match wins and the second action
		// becomes unreachable. Guarding this in a unit test keeps
		// future maintainers honest as new verbs are added.
		cases := [][3]any{
			{"blocked", "installed", false},
			{"allowed", "installed", true},
			{"clean", "quarantined", true},
			{"warning", "installed", true},
		}
		for _, c := range cases {
			actions := PluginActions(c[0].(string), c[1].(string), c[2].(bool))
			seen := map[string]bool{}
			for _, a := range actions {
				if seen[a.Key] {
					t.Errorf("duplicate key %q in PluginActions(%v)", a.Key, c)
				}
				seen[a.Key] = true
			}
		}
	})
}

func actionKeys(actions []ActionItem) map[string]bool {
	keys := make(map[string]bool)
	for _, a := range actions {
		keys[a.Key] = true
	}
	return keys
}

func assertContains(t *testing.T, keys map[string]bool, key, msg string) {
	t.Helper()
	if !keys[key] {
		t.Errorf("%s (missing key %q)", msg, key)
	}
}

func assertNotContains(t *testing.T, keys map[string]bool, key, msg string) {
	t.Helper()
	if keys[key] {
		t.Errorf("%s (unexpected key %q)", msg, key)
	}
}
