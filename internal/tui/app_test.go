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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestModelInitDoesNotQueueAutoInit(t *testing.T) {
	model := New(Deps{Version: "test"})
	cmd := model.Init()
	if cmd == nil {
		t.Fatal("Init should return startup commands")
	}

	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("Init() returned %T, want tea.BatchMsg", msg)
	}

	for _, subcmd := range batch {
		name := runtime.FuncForPC(reflect.ValueOf(subcmd).Pointer()).Name()
		if strings.Contains(name, "autoInit") {
			t.Fatalf("unexpected auto-init command scheduled: %s", name)
		}
	}
}

func TestHandleKeyAlertsDigitsStayLocal(t *testing.T) {
	model := New(Deps{Version: "test"})
	model.activePanel = PanelAlerts
	model.alerts.items = []audit.Event{
		{ID: "a1", Severity: "CRITICAL"},
		{ID: "a2", Severity: "LOW"},
	}
	model.alerts.applyFilter()

	next, _ := model.handleKey(digitKey("2"))
	got := next.(Model)

	if got.activePanel != PanelAlerts {
		t.Fatalf("activePanel = %d, want PanelAlerts", got.activePanel)
	}
	if got.alerts.SevFilter() != "CRITICAL" {
		t.Fatalf("severity filter = %q, want CRITICAL", got.alerts.SevFilter())
	}
}

func TestHandleKeyInventoryDigitsStayLocal(t *testing.T) {
	model := New(Deps{Version: "test"})
	model.activePanel = PanelInventory
	model.inventory.inv = &aibomInventory{
		Skills: []aibomSkill{{ID: "s1", Eligible: true}},
	}
	model.inventory.activeSub = invSubSkills

	next, _ := model.handleKey(digitKey("2"))
	got := next.(Model)

	if got.activePanel != PanelInventory {
		t.Fatalf("activePanel = %d, want PanelInventory", got.activePanel)
	}
	if got.inventory.Filter() != "eligible" {
		t.Fatalf("inventory filter = %q, want eligible", got.inventory.Filter())
	}
}

func TestHandleAuditKeyExportsJSON(t *testing.T) {
	store := newTestAuditStore(t)
	if err := store.LogEvent(audit.Event{
		Action:   "scan",
		Target:   "skill/export-me",
		Details:  "export me",
		Severity: "HIGH",
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	model := New(Deps{Store: store, Version: "test"})
	model.activePanel = PanelAudit

	next, cmd := model.handleAuditKey(tea.KeyPressMsg(tea.Key{Text: "e", Code: 'e'}))
	if cmd != nil {
		t.Fatal("export should not shell out to an async command")
	}

	got := next.(Model)
	exportPath := filepath.Join(tempDir, "defenseclaw-audit-export.json")
	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", exportPath, err)
	}
	if !strings.Contains(string(data), "export me") {
		t.Fatalf("export output missing expected event details: %s", data)
	}
	if got.activity.Count() != 1 {
		t.Fatalf("activity entries = %d, want 1", got.activity.Count())
	}
}

func digitKey(text string) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Text: text, Code: []rune(text)[0]})
}

// TestGlobalQDoesNotQuit pins the user-visible contract that "q"
// alone never shuts the TUI down. Previously the global key router
// treated q as a synonym for Ctrl+C, which turned closing an
// in-panel overlay (e.g., the policy YAML viewer dismiss key) into
// an accidental exit — see the B-rolling bugfix plan's "remove q
// for quit" entry.
func TestGlobalQDoesNotQuit(t *testing.T) {
	model := New(Deps{Version: "test"})
	model.activePanel = PanelOverview

	_, cmd := model.handleKey(digitKey("q"))

	if cmd != nil {
		// tea.Quit is the only cmd that would return a QuitMsg
		// when invoked; we reject any non-nil cmd from the q
		// path because the only acceptable outcome is "panel got
		// the key and did nothing" (nil) or "panel returned a
		// benign cmd". The Overview panel binds nothing to q so
		// nil is the expected shape here.
		if msg := cmd(); msg != nil {
			if _, isQuit := msg.(tea.QuitMsg); isQuit {
				t.Fatalf("q triggered tea.Quit; must only be Ctrl+C")
			}
		}
	}
}

// TestCtrlCStillQuits guards the inverse: removing q must not have
// also severed the one intentional quit key.
func TestCtrlCStillQuits(t *testing.T) {
	model := New(Deps{Version: "test"})
	ctrlC := tea.KeyPressMsg(tea.Key{Text: "", Code: 'c', Mod: tea.ModCtrl})

	_, cmd := model.handleKey(ctrlC)
	if cmd == nil {
		t.Fatalf("Ctrl+C returned nil cmd; want tea.Quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("Ctrl+C cmd did not produce QuitMsg")
	}
}

// TestPanelExclusiveBlocksPanelSwitch verifies that when a panel
// has an overlay open, digit shortcuts route to the panel instead
// of hopping to another panel. This is the "don't let clicks/keys
// leak through to panels above" guarantee the user asked for.
func TestPanelExclusiveBlocksPanelSwitch(t *testing.T) {
	model := New(Deps{Version: "test"})
	model.activePanel = PanelPolicy
	model.policy.policyDetailOpen = true
	model.policy.policyDetailYAML = "name: demo"
	model.policy.policyDetailName = "demo"

	next, _ := model.handleKey(digitKey("3"))
	got := next.(Model)

	if got.activePanel != PanelPolicy {
		t.Fatalf("digit while overlay open switched panels to %d, want PanelPolicy", got.activePanel)
	}
	// Overlay should still be open — digit must not dismiss it
	// either, since only esc / enter / q inside the overlay
	// close it.
	if !got.policy.policyDetailOpen {
		t.Fatalf("overlay was dismissed by digit; want preserved")
	}
}

// TestPolicyOverlayQClosesOverlay verifies the specific user-reported
// bug: pressing "q" inside an open policy YAML overlay must close
// the overlay in-place, not quit the whole TUI.
func TestPolicyOverlayQClosesOverlay(t *testing.T) {
	model := New(Deps{Version: "test"})
	model.activePanel = PanelPolicy
	model.policy.policyDetailOpen = true
	model.policy.policyDetailYAML = "name: demo"
	model.policy.policyDetailName = "demo"

	next, cmd := model.handleKey(digitKey("q"))
	got := next.(Model)

	if cmd != nil {
		if msg := cmd(); msg != nil {
			if _, isQuit := msg.(tea.QuitMsg); isQuit {
				t.Fatalf("q inside policy overlay triggered Quit")
			}
		}
	}
	if got.policy.policyDetailOpen {
		t.Fatalf("q inside policy overlay did not close it")
	}
}

func newTestAuditStore(t *testing.T) *audit.Store {
	t.Helper()

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return store
}
