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
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestUninstallModal_DefaultsToDryRun(t *testing.T) {
	m := NewUninstallModal(DefaultTheme())
	m.Show()

	if !m.IsVisible() {
		t.Fatal("Show must mark uninstall modal visible")
	}
	if got := m.Selected(); got != UninstallDryRun {
		t.Fatalf("default selection=%v want dry-run", got)
	}
	m.CursorDown()
	if got := m.Selected(); got != UninstallKeepData {
		t.Fatalf("after down selection=%v want keep-data uninstall", got)
	}
	if !m.SelectByHotkey('a') {
		t.Fatal("hotkey a should select wipe-data uninstall")
	}
	if got := m.Selected(); got != UninstallWipeData {
		t.Fatalf("hotkey selection=%v want wipe-data uninstall", got)
	}
	m.Hide()
	if m.IsVisible() {
		t.Fatal("Hide must clear uninstall modal visibility")
	}
}

func TestUninstallModal_ViewWarnsAboutDestructiveRows(t *testing.T) {
	m := NewUninstallModal(DefaultTheme())
	m.SetSize(100, 30)
	m.Show()

	view := m.View()
	for _, want := range []string{
		"Uninstall DefenseClaw",
		"Preview plan",
		"Uninstall, keep data",
		"Uninstall and wipe data",
		"--yes",
		"dry-run",
		"[Enter]",
		"[esc]",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("uninstall modal missing %q\n%s", want, view)
		}
	}
}

func TestUninstallArgsForOption(t *testing.T) {
	cases := []struct {
		option      UninstallOption
		wantArgs    string
		wantDisplay string
	}{
		{UninstallDryRun, "uninstall --dry-run", "uninstall dry-run"},
		{UninstallKeepData, "uninstall --yes", "uninstall --yes"},
		{UninstallWipeData, "uninstall --all --yes", "uninstall --all --yes"},
	}
	for _, tc := range cases {
		args, display := uninstallArgsForOption(tc.option)
		if got := strings.Join(args, " "); got != tc.wantArgs {
			t.Fatalf("args=%q want %q", got, tc.wantArgs)
		}
		if display != tc.wantDisplay {
			t.Fatalf("display=%q want %q", display, tc.wantDisplay)
		}
	}
}

func TestConfirmUninstallHidesModalAndRunsActivity(t *testing.T) {
	m := Model{
		executor:       NewCommandExecutor(),
		uninstallModal: NewUninstallModal(DefaultTheme()),
	}
	m.uninstallModal.Show()
	m.uninstallModal.CursorDown()

	next, cmd := m.confirmUninstall()
	if cmd == nil {
		t.Fatal("confirmUninstall must return a command")
	}
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("confirmUninstall returned %T, want Model", next)
	}
	if got.uninstallModal.IsVisible() {
		t.Fatal("uninstall modal should be hidden after confirm")
	}
	if got.activePanel != PanelActivity {
		t.Fatalf("activePanel=%d want Activity", got.activePanel)
	}
}

func TestOverviewUninstallActionOpensModal(t *testing.T) {
	m := New(Deps{Version: "test"})
	m.activePanel = PanelOverview

	next, cmd := m.handleOverviewKey(tea.KeyPressMsg(tea.Key{Text: "X", Code: 'X'}))
	if cmd != nil {
		t.Fatal("opening uninstall modal should not run a command")
	}
	got := next.(Model)
	if !got.uninstallModal.IsVisible() {
		t.Fatal("X on Overview should open the uninstall modal")
	}
}

func TestOverviewQuickActionHitTestIncludesUninstall(t *testing.T) {
	p := OverviewPanel{}
	pos := 4
	for _, action := range quickActionDefs {
		if action.key == "X" {
			if got := p.QuickActionHitTest(pos); got != "X" {
				t.Fatalf("hit test at uninstall position=%q want X", got)
			}
			return
		}
		pos += action.width + 4
	}
	t.Fatal("quickActionDefs missing X uninstall action")
}
