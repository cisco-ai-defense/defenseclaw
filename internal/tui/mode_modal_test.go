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

// TestModePickerModal_DefaultsToCurrent verifies the contract that
// re-opening the picker always highlights whatever connector is
// currently active. This is what makes "press [m] then enter" a safe
// no-op — the cursor lands on the row that won't change anything.
func TestModePickerModal_DefaultsToCurrent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		current string
		want    string
	}{
		{"openclaw", "openclaw"},
		{"zeptoclaw", "zeptoclaw"},
		{"codex", "codex"},
		{"claudecode", "claudecode"},
		// Whitespace and case must round-trip (operators sometimes
		// have stray spaces in config files).
		{"  CodeX  ", "codex"},
		// Unknown values fall through to whatever index 0 is — we
		// don't crash, but Selected returns the first option.
		{"unknown", "openclaw"},
		{"", "openclaw"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.current, func(t *testing.T) {
			t.Parallel()
			p := NewModePickerModal(nil)
			p.Show(tc.current)
			if !p.IsVisible() {
				t.Fatalf("Show should mark modal visible")
			}
			if got := p.Selected(); got != tc.want {
				t.Fatalf("Selected() after Show(%q) = %q, want %q", tc.current, got, tc.want)
			}
		})
	}
}

// TestModePickerModal_HotkeysCoverEveryConnector ensures every
// connector has a unique single-letter shortcut wired up — a
// regression where a key collides or stops responding would silently
// break the "muscle memory" contract documented on the modal.
func TestModePickerModal_HotkeysCoverEveryConnector(t *testing.T) {
	t.Parallel()
	wires := map[string]bool{}
	keys := map[rune]string{}
	for _, ch := range modePickerChoices {
		if wires[ch.wire] {
			t.Fatalf("duplicate wire name in modePickerChoices: %q", ch.wire)
		}
		wires[ch.wire] = true
		if existing, dup := keys[ch.hotkey]; dup {
			t.Fatalf("hotkey %q maps to two connectors: %q and %q", string(ch.hotkey), existing, ch.wire)
		}
		keys[ch.hotkey] = ch.wire
	}
	want := []string{"openclaw", "zeptoclaw", "claudecode", "codex"}
	for _, w := range want {
		if !wires[w] {
			t.Fatalf("missing modePickerChoices entry for %q", w)
		}
	}

	p := NewModePickerModal(nil)
	p.Show("openclaw")
	for r, expectedWire := range keys {
		if ok := p.SelectByHotkey(r); !ok {
			t.Fatalf("SelectByHotkey(%q) returned false", string(r))
		}
		if got := p.Selected(); got != expectedWire {
			t.Fatalf("after SelectByHotkey(%q) Selected() = %q, want %q", string(r), got, expectedWire)
		}
	}

	if ok := p.SelectByHotkey('q'); ok {
		t.Fatalf("SelectByHotkey('q') should return false (q is not a connector)")
	}
}

// TestModePickerModal_CursorBoundsClamp pins the small contract that
// CursorUp/Down clamp at the ends instead of wrapping. Wrapping
// cursors in a 4-row list would just confuse users who expected to
// reach the end and see "I'm at the end".
func TestModePickerModal_CursorBoundsClamp(t *testing.T) {
	t.Parallel()
	p := NewModePickerModal(nil)
	p.Show("openclaw") // cursor=0

	// Already at top: CursorUp is a no-op.
	p.CursorUp()
	if p.cursor != 0 {
		t.Fatalf("cursor should clamp at 0, got %d", p.cursor)
	}

	// Walk to the bottom.
	for i := 0; i < len(modePickerChoices)+5; i++ {
		p.CursorDown()
	}
	if p.cursor != len(modePickerChoices)-1 {
		t.Fatalf("cursor should clamp at last index, got %d", p.cursor)
	}
}

// TestModePickerModal_PreviewMatchesInheritanceRules covers the
// contract that the preview line correctly describes what the
// matching `defenseclaw setup mode` invocation will do — so the TUI
// doesn't lie about a switch's effects. We exercise all four
// transition kinds.
func TestModePickerModal_PreviewMatchesInheritanceRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		from, to string
		wantSub  string
	}{
		// openclaw ↔ zeptoclaw → inheritance
		{"openclaw", "zeptoclaw", "Inherits current guardrail config"},
		{"zeptoclaw", "openclaw", "Inherits current guardrail config"},
		// → codex/claudecode → observability-only
		{"openclaw", "codex", "observability-only"},
		{"zeptoclaw", "claudecode", "observability-only"},
		{"codex", "claudecode", "observability-only"},
		{"claudecode", "codex", "observability-only"},
		// codex/claudecode → openclaw/zeptoclaw → observe mode (no auto-enforce)
		{"codex", "openclaw", "observe mode (no auto-enforcement)"},
		{"claudecode", "zeptoclaw", "observe mode (no auto-enforcement)"},
		// no-op
		{"openclaw", "openclaw", "Already active"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.from+"_to_"+tc.to, func(t *testing.T) {
			t.Parallel()
			p := NewModePickerModal(nil)
			p.Show(tc.from)
			got := p.previewForSwitch(tc.to)
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("preview(%s→%s) = %q, expected substring %q",
					tc.from, tc.to, got, tc.wantSub)
			}
		})
	}
}

// TestModePickerModal_HideClearsVisibility makes sure Hide actually
// hides — a leaked-visible modal would block all overview keys.
func TestModePickerModal_HideClearsVisibility(t *testing.T) {
	t.Parallel()
	p := NewModePickerModal(nil)
	p.Show("openclaw")
	if !p.IsVisible() {
		t.Fatalf("Show should make picker visible")
	}
	p.Hide()
	if p.IsVisible() {
		t.Fatalf("Hide should clear visibility")
	}
}

// TestModePickerModal_ViewMentionsAllChoices exercises the renderer
// to confirm every connector label appears, the preview line is
// rendered, and the help line is present. Stripping ANSI escapes
// keeps the test stable across terminal backends.
func TestModePickerModal_ViewMentionsAllChoices(t *testing.T) {
	t.Parallel()
	p := NewModePickerModal(DefaultTheme())
	p.SetSize(120, 40)
	p.Show("openclaw")
	out := stripANSI(p.View())
	for _, ch := range modePickerChoices {
		if !strings.Contains(out, ch.label) {
			t.Fatalf("View missing connector label %q. Output:\n%s", ch.label, out)
		}
	}
	if !strings.Contains(out, "(active)") {
		t.Fatalf("View should mark the current connector with (active). Output:\n%s", out)
	}
	if !strings.Contains(out, "esc close") {
		t.Fatalf("View should show the help footer. Output:\n%s", out)
	}
	if !strings.Contains(out, "hash-checked backups") {
		t.Fatalf("View should explain teardown backup safety. Output:\n%s", out)
	}
}

// TestModePickerModal_NotVisibleViewIsEmpty makes sure callers who
// always render the modal output (without checking IsVisible first)
// don't paint a phantom empty modal.
func TestModePickerModal_NotVisibleViewIsEmpty(t *testing.T) {
	t.Parallel()
	p := NewModePickerModal(DefaultTheme())
	if got := p.View(); got != "" {
		t.Fatalf("View() while hidden should be empty, got: %q", got)
	}
}
