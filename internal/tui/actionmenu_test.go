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

import "testing"

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
	t.Run("blocked_skill", func(t *testing.T) {
		actions := SkillActions("blocked")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "blocked should have scan")
		assertContains(t, keys, "i", "blocked should have info")
		assertContains(t, keys, "u", "blocked should have unblock")
		assertContains(t, keys, "r", "blocked should have restore")
		assertNotContains(t, keys, "b", "blocked should not have block")
		assertNotContains(t, keys, "a", "blocked should not have allow")
	})

	t.Run("allowed_skill", func(t *testing.T) {
		actions := SkillActions("allowed")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "allowed should have scan")
		assertContains(t, keys, "b", "allowed should have block")
		assertNotContains(t, keys, "a", "allowed should not have allow (already allowed)")
		assertNotContains(t, keys, "u", "allowed should not have unblock")
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
	})

	t.Run("always_has_scan_and_info", func(t *testing.T) {
		for _, status := range []string{"blocked", "allowed", "clean", "warning", ""} {
			actions := SkillActions(status)
			keys := actionKeys(actions)
			assertContains(t, keys, "s", status+" should have scan")
			assertContains(t, keys, "i", status+" should have info")
		}
	})
}

func TestMCPActions(t *testing.T) {
	t.Run("blocked_mcp", func(t *testing.T) {
		actions := MCPActions("blocked")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "blocked should have scan")
		assertContains(t, keys, "u", "blocked should have unblock")
		assertContains(t, keys, "x", "blocked should have unset")
		assertNotContains(t, keys, "b", "blocked should not have block")
	})

	t.Run("allowed_mcp", func(t *testing.T) {
		actions := MCPActions("allowed")
		keys := actionKeys(actions)
		assertContains(t, keys, "b", "allowed should have block")
		assertContains(t, keys, "x", "allowed should have unset")
		assertNotContains(t, keys, "u", "allowed should not have unblock")
	})

	t.Run("default_mcp", func(t *testing.T) {
		actions := MCPActions("clean")
		keys := actionKeys(actions)
		assertContains(t, keys, "s", "default should have scan")
		assertContains(t, keys, "b", "default should have block")
		assertContains(t, keys, "a", "default should have allow")
		assertNotContains(t, keys, "x", "default should not have unset")
	})

	t.Run("always_has_scan_and_info", func(t *testing.T) {
		for _, status := range []string{"blocked", "allowed", "clean", ""} {
			actions := MCPActions(status)
			keys := actionKeys(actions)
			assertContains(t, keys, "s", status+" should have scan")
			assertContains(t, keys, "i", status+" should have info")
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
