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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// newTestModelWithSkill is the Skills-side peer of
// newTestModelWithPlugin. We deliberately bypass the audit store —
// CLI dispatch does not read from it, and wiring in a SQLite handle
// would only slow the test suite for no additional coverage.
func newTestModelWithSkill(item skillItem) Model {
	m := New(Deps{
		Store:   nil,
		Config:  &config.Config{},
		Version: "test",
	})
	m.activePanel = PanelSkills
	m.skills.items = []skillItem{item}
	m.skills.filtered = m.skills.items
	m.skills.cursor = 0
	m.width = 120
	m.height = 40
	return m
}

// TestHandleSkillsKey_B_RoutesToCLI is the regression anchor for
// P0-#4: before the fix, pressing 'b' mutated the local audit store
// via m.skills.ToggleBlock() which bypassed the admission gate, the
// gateway RPC notification, and the formal audit event. The fix
// replaces that with a `defenseclaw skill block` dispatch — assert
// the dispatch happens (non-nil tea.Cmd) and the active panel flips
// to Activity so the operator sees the stream.
func TestHandleSkillsKey_B_RoutesToCLI(t *testing.T) {
	m := newTestModelWithSkill(skillItem{
		Name:   "tutor",
		Status: "active",
	})
	newM, cmd := m.handleSkillsKey(pressKey("b"))
	if cmd == nil {
		t.Fatal("pressing 'b' must dispatch `defenseclaw skill block`, not mutate local state")
	}
	mm := newM.(Model)
	if mm.activePanel != PanelActivity {
		t.Errorf("pressing 'b' should switch to PanelActivity so output is visible, got %d", mm.activePanel)
	}
}

func TestHandleSkillsKey_A_RoutesToCLI(t *testing.T) {
	// 'a' historically only un-blocked (when Status==blocked); we
	// widened it to always mean "allow". Operators wanting a pure
	// unblock can use 'u' from the action menu.
	m := newTestModelWithSkill(skillItem{
		Name:   "tutor",
		Status: "active",
	})
	_, cmd := m.handleSkillsKey(pressKey("a"))
	if cmd == nil {
		t.Fatal("'a' must dispatch `defenseclaw skill allow` for any status")
	}
}

func TestHandleSkillsKey_NoSelection_Safe(t *testing.T) {
	m := New(Deps{Config: &config.Config{}})
	m.activePanel = PanelSkills
	m.width = 120
	m.height = 40
	for _, k := range []string{"b", "a", "s"} {
		if _, cmd := m.handleSkillsKey(pressKey(k)); cmd != nil {
			t.Errorf("handleSkillsKey(%q) on empty list must be a no-op, got cmd=%v", k, cmd)
		}
	}
}

// TestExecuteActionMenuItem_SkillDispatch guarantees every key
// surfaced by any SkillActions branch resolves to a real CLI verb.
// Regressions here are exactly the "silent no-op on a labelled
// button" class of bug we're explicitly trying to prevent.
func TestExecuteActionMenuItem_SkillDispatch(t *testing.T) {
	m := newTestModelWithSkill(skillItem{
		Name:   "tutor",
		Status: "active",
	})
	seen := map[string]bool{}
	for _, status := range []string{"blocked", "allowed", "quarantined", "disabled", "active", ""} {
		for _, a := range SkillActions(status) {
			seen[a.Key] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("SkillActions returned no actions across status matrix")
	}
	for key := range seen {
		key := key
		t.Run("key_"+key, func(t *testing.T) {
			if cmd := m.executeActionMenuItem(key); cmd == nil {
				t.Fatalf("executeActionMenuItem(%q) returned nil — every SkillActions key must map to a CLI verb", key)
			}
		})
	}
}

// TestExecuteActionMenuItem_SkillDispatch_NilSelectionSafe is paired
// with the corresponding Tool and Plugin safety tests; it ensures
// the dispatcher can't be tricked into spawning `defenseclaw skill
// <verb> <empty>` when the operator triggers a key with no row
// selected (e.g. via quick-action buttons or mouse click in an
// otherwise empty list).
func TestExecuteActionMenuItem_SkillDispatch_NilSelectionSafe(t *testing.T) {
	m := New(Deps{Config: &config.Config{}})
	m.activePanel = PanelSkills
	for _, k := range []string{"b", "a", "u", "d", "e", "q", "r", "n", "s", "i"} {
		if cmd := m.executeActionMenuItem(k); cmd != nil {
			t.Errorf("executeActionMenuItem(%q) must be a no-op when no skill is selected", k)
		}
	}
}
