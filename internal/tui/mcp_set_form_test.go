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
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestMCPSetForm_NavigatesFields verifies tab / shift+tab wrap
// cleanly and that the field index stays within bounds. This is a
// regression guard for a bug class we've hit elsewhere: modulo on a
// signed int can go negative if the subtraction is applied before
// the `+ count`, which would crash View() on the next render.
func TestMCPSetForm_NavigatesFields(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	if got := f.CurrentField(); got != mcpFieldName {
		t.Fatalf("Open() should focus Name, got %d", got)
	}
	// Tab forward past the last field should wrap to Name.
	for i := 0; i < int(mcpFieldCount); i++ {
		f.HandleKey("tab")
	}
	if got := f.CurrentField(); got != mcpFieldName {
		t.Errorf("tab wrap-around broken: expected Name, got %d", got)
	}
	// Shift+Tab from Name should wrap to the last field.
	f.HandleKey("shift+tab")
	if got := f.CurrentField(); got != mcpFieldCount-1 {
		t.Errorf("shift+tab wrap-around broken: expected %d, got %d", mcpFieldCount-1, got)
	}
}

// TestMCPSetForm_InputAppends exercises the append-on-keypress path
// and Backspace, including a UTF-8 deletion to make sure we trim
// whole runes (not bytes) — a regression of the old bug where
// deleting the "é" from "café" used to leave a stray continuation
// byte behind.
func TestMCPSetForm_InputAppends(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	for _, k := range []string{"c", "a", "f", "é"} {
		f.HandleKey(k)
	}
	if got := f.Value(mcpFieldName); got != "café" {
		t.Errorf("Name after typing 'café': %q", got)
	}
	f.HandleKey("backspace")
	if got := f.Value(mcpFieldName); got != "caf" {
		t.Errorf("Name after backspace: %q (want 'caf' — must trim one rune)", got)
	}
	// ctrl+u clears the field entirely.
	f.HandleKey("ctrl+u")
	if got := f.Value(mcpFieldName); got != "" {
		t.Errorf("Name after ctrl+u: %q (want empty)", got)
	}
}

// TestMCPSetForm_NamedKeysAreNotAppended ensures we don't treat
// named keys like "f5" or "home" as literal text input. The
// previous implementation used a blanket "else append key" which
// produced "f5" embedded in the Name field when the operator
// tapped a function key.
func TestMCPSetForm_NamedKeysAreNotAppended(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	for _, k := range []string{"f5", "home", "end", "pageup", "pgdn"} {
		f.HandleKey(k)
	}
	if got := f.Value(mcpFieldName); got != "" {
		t.Errorf("named keys leaked into Name field: %q", got)
	}
}

// TestMCPSetForm_BuildCommand_RequiresName is the contract anchor
// for the pre-submit validator. Without it the CLI would raise a
// click error which is clumsier for the operator than staying in
// the form with an inline status line.
func TestMCPSetForm_BuildCommand_RequiresName(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	if _, err := f.BuildCommand(); err == nil {
		t.Error("empty form must fail validation")
	}
	f.SetValue(mcpFieldName, "context7")
	if _, err := f.BuildCommand(); err == nil {
		t.Error("missing command AND url must fail validation")
	}
	f.SetValue(mcpFieldCommand, "uvx")
	if _, err := f.BuildCommand(); err != nil {
		t.Errorf("name + command should validate, got: %v", err)
	}
}

// TestMCPSetForm_BuildCommand_ArgvShape pins the argv layout.
// Changes to this shape are fine but require double-checking
// against cli/defenseclaw/commands/cmd_mcp.py::set_server flag
// names; an undetected drift would silently drop fields.
func TestMCPSetForm_BuildCommand_ArgvShape(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	f.SetValue(mcpFieldName, "context7")
	f.SetValue(mcpFieldCommand, "uvx")
	f.SetValue(mcpFieldArgs, "context7-mcp")
	f.SetValue(mcpFieldURL, "https://example.com/mcp")
	f.SetValue(mcpFieldTransport, "sse")
	f.SetValue(mcpFieldEnv, "API_KEY=xxx, REGION=us-east-1")
	f.SetValue(mcpFieldSkipScan, "y")

	argv, err := f.BuildCommand()
	if err != nil {
		t.Fatalf("BuildCommand: %v", err)
	}
	want := []string{
		"mcp", "set", "context7",
		"--command", "uvx",
		"--args", "context7-mcp",
		"--url", "https://example.com/mcp",
		"--transport", "sse",
		"--env", "API_KEY=xxx",
		"--env", "REGION=us-east-1",
		"--skip-scan",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv mismatch\n got: %v\nwant: %v", argv, want)
	}
}

// TestMCPSetForm_BuildCommand_EnvValidates rejects malformed env
// pairs before dispatch. The CLI would raise the same error, but
// catching it here lets us keep the operator in the form with the
// faulty value still visible.
func TestMCPSetForm_BuildCommand_EnvValidates(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	f.SetValue(mcpFieldName, "s")
	f.SetValue(mcpFieldCommand, "uvx")
	f.SetValue(mcpFieldEnv, "NO_EQUALS_HERE")
	if _, err := f.BuildCommand(); err == nil {
		t.Error("env without '=' must fail validation")
	}
}

// TestMCPSetForm_BuildCommand_SkipScanTruthy makes sure we accept
// both "y" and "yes" (and reject the implicit default), matching
// how operators tend to type checkbox-ish prompts.
func TestMCPSetForm_BuildCommand_SkipScanTruthy(t *testing.T) {
	cases := map[string]bool{
		"":     false,
		"n":    false,
		"no":   false,
		"y":    true,
		"Y":    true,
		"yes":  true,
		"YES":  true,
		"true": true,
		"1":    true,
	}
	for in, want := range cases {
		var f MCPSetForm
		f.Open("")
		f.SetValue(mcpFieldName, "s")
		f.SetValue(mcpFieldCommand, "uvx")
		f.SetValue(mcpFieldSkipScan, in)
		argv, err := f.BuildCommand()
		if err != nil {
			t.Fatalf("BuildCommand(skip=%q): %v", in, err)
		}
		got := false
		for _, a := range argv {
			if a == "--skip-scan" {
				got = true
				break
			}
		}
		if got != want {
			t.Errorf("skip=%q: got --skip-scan=%v, want %v", in, got, want)
		}
	}
}

// TestMCPSetForm_EnterAdvancesThenSubmits exercises the Enter-key
// flow end to end: Enter on non-last field advances; Enter on the
// last field submits.
func TestMCPSetForm_EnterAdvancesThenSubmits(t *testing.T) {
	var f MCPSetForm
	f.Open("")
	f.SetValue(mcpFieldName, "s")
	f.SetValue(mcpFieldCommand, "uvx")
	// Enter on first field should just advance.
	submit, _, _, _ := f.HandleKey("enter")
	if submit {
		t.Fatal("enter on first field must not submit")
	}
	if f.CurrentField() != mcpFieldCommand {
		t.Errorf("enter should advance to Command, got %d", f.CurrentField())
	}
	// Jump to last field and submit.
	for f.CurrentField() != mcpFieldCount-1 {
		f.HandleKey("tab")
	}
	submit, bin, argv, display := f.HandleKey("enter")
	if !submit {
		t.Fatal("enter on last field must submit")
	}
	if bin != "defenseclaw" {
		t.Errorf("binary = %q, want defenseclaw", bin)
	}
	if len(argv) == 0 || argv[0] != "mcp" || argv[1] != "set" {
		t.Errorf("argv prefix wrong: %v", argv)
	}
	if !strings.HasPrefix(display, "mcp set ") {
		t.Errorf("display = %q; expected 'mcp set <name>'", display)
	}
}

// TestMCPSetForm_EscCloses is the cancel path — we need the form
// to go away without emitting a command.
func TestMCPSetForm_EscCloses(t *testing.T) {
	var f MCPSetForm
	f.Open("edit-me")
	submit, _, _, _ := f.HandleKey("esc")
	if submit {
		t.Error("esc must not submit")
	}
	if f.IsActive() {
		t.Error("esc must close the form")
	}
}

// TestHandleMCPsKey_B_RoutesToCLI is the regression anchor for
// P0-#5 — the mirror of TestHandleSkillsKey_B_RoutesToCLI. Pre-fix
// the TUI called ToggleBlock() which mutated the audit store
// directly; the fix routes through `defenseclaw mcp block <url>`.
func TestHandleMCPsKey_B_RoutesToCLI(t *testing.T) {
	m := New(Deps{Config: &config.Config{}, Version: "test"})
	m.activePanel = PanelMCPs
	m.mcps.items = []mcpItem{{URL: "context7", Status: "active"}}
	m.mcps.filtered = m.mcps.items
	m.mcps.cursor = 0
	m.width = 120
	m.height = 40
	_, cmd := m.handleMCPsKey(pressKey("b"))
	if cmd == nil {
		t.Fatal("'b' must dispatch `defenseclaw mcp block`, not mutate in-memory state")
	}
}

func TestHandleMCPsKey_A_RoutesToCLI_ForAllStatuses(t *testing.T) {
	// Pre-P0-#5 'a' only unblocked when Status==blocked. After the
	// fix 'a' always means allow (add to allow-list), regardless
	// of current status. Iterate through every status we expose so
	// a future status branch doesn't accidentally short-circuit 'a'.
	for _, status := range []string{"active", "blocked", "allowed", "warning"} {
		m := New(Deps{Config: &config.Config{}, Version: "test"})
		m.activePanel = PanelMCPs
		m.mcps.items = []mcpItem{{URL: "s", Status: status}}
		m.mcps.filtered = m.mcps.items
		m.width = 120
		m.height = 40
		if _, cmd := m.handleMCPsKey(pressKey("a")); cmd == nil {
			t.Errorf("status=%s: 'a' must dispatch allow", status)
		}
	}
}

// TestHandleMCPsKey_N_OpensSetForm exercises the new 'n' keybinding
// that brings up the MCPSetForm.
func TestHandleMCPsKey_N_OpensSetForm(t *testing.T) {
	m := New(Deps{Config: &config.Config{}, Version: "test"})
	m.activePanel = PanelMCPs
	m.width = 120
	m.height = 40
	newM, cmd := m.handleMCPsKey(pressKey("n"))
	if cmd != nil {
		t.Error("'n' must only open the form, not dispatch a command")
	}
	mm := newM.(Model)
	if !mm.mcpSetForm.IsActive() {
		t.Error("'n' must activate the Set form")
	}
}

// TestHandleMCPsKey_FormOwnsKeyboard verifies that once the form is
// open, subsequent keypresses are routed to the form instead of the
// list view. This is the interaction contract that prevents double
// handling (e.g. 'j' moving the list cursor while the operator is
// typing into the Command field).
func TestHandleMCPsKey_FormOwnsKeyboard(t *testing.T) {
	m := New(Deps{Config: &config.Config{}, Version: "test"})
	m.activePanel = PanelMCPs
	m.width = 120
	m.height = 40
	m.mcpSetForm.Open("")
	// Typing 'j' with the form open should become form input, not
	// a cursor-down on the underlying list.
	newM, _ := m.handleMCPsKey(pressKey("j"))
	mm := newM.(Model)
	if mm.mcpSetForm.Value(mcpFieldName) != "j" {
		t.Errorf("form did not consume 'j': Name=%q", mm.mcpSetForm.Value(mcpFieldName))
	}
}

// TestExecuteActionMenuItem_MCPDispatch ensures every key surfaced
// by any MCPActions branch resolves to a real CLI verb (parity
// check with the Skills/Tools/Plugins version).
func TestExecuteActionMenuItem_MCPDispatch(t *testing.T) {
	m := New(Deps{Config: &config.Config{}, Version: "test"})
	m.activePanel = PanelMCPs
	m.mcps.items = []mcpItem{{URL: "s", Status: "active"}}
	m.mcps.filtered = m.mcps.items
	seen := map[string]bool{}
	for _, status := range []string{"blocked", "allowed", "active", ""} {
		for _, a := range MCPActions(status) {
			seen[a.Key] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("MCPActions returned no actions")
	}
	for key := range seen {
		if cmd := m.executeActionMenuItem(key); cmd == nil {
			t.Errorf("executeActionMenuItem(%q) returned nil — MCPActions surfaces it but dispatch doesn't", key)
		}
	}
}
