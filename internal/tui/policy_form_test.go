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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// PolicyCreateForm — unit tests
// ------------------------------------------------------------------

// TestPolicyCreateForm_Navigation locks in the tab-order navigation
// contract. Regressions here silently break the form's feel (e.g.
// Enter-to-advance replaced with immediate-submit).
func TestPolicyCreateForm_Navigation(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	if f.CurrentField() != policyFieldName {
		t.Fatalf("initial field = %d, want %d", f.CurrentField(), policyFieldName)
	}

	// Enter on non-last field must advance.
	submit, _, _, _ := f.HandleKey("enter")
	if submit {
		t.Fatal("Enter on first field must not submit")
	}
	if f.CurrentField() != policyFieldDescription {
		t.Fatalf("Enter should advance Name → Description, got field %d", f.CurrentField())
	}

	// Shift+Tab wraps backwards.
	f.HandleKey("shift+tab")
	if f.CurrentField() != policyFieldName {
		t.Fatalf("shift+tab from Description should go to Name, got %d", f.CurrentField())
	}
	f.HandleKey("shift+tab")
	if f.CurrentField() != policyFieldCount-1 {
		t.Fatalf("shift+tab from Name should wrap to last, got %d", f.CurrentField())
	}
}

// TestPolicyCreateForm_InputAppends_UTF8Safe checks that backspace
// trims by rune, not by byte. A regression here corrupts policy
// names typed with non-ASCII characters (e.g. for i18n'd
// descriptions).
func TestPolicyCreateForm_InputAppends_UTF8Safe(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	// Type "prö" into Name — 4 bytes, 3 runes.
	for _, r := range "prö" {
		f.HandleKey(string(r))
	}
	if got := f.Value(policyFieldName); got != "prö" {
		t.Fatalf("after typing 'prö', got %q", got)
	}
	f.HandleKey("backspace")
	if got := f.Value(policyFieldName); got != "pr" {
		t.Fatalf("after backspace, got %q, want \"pr\"", got)
	}
}

// TestPolicyCreateForm_NamedKeysAreNotAppended ensures that Bubble
// Tea's named key strings (like "f5", "home") don't end up in the
// field value. The filter is a len([]rune) == 1 check.
func TestPolicyCreateForm_NamedKeysAreNotAppended(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	for _, k := range []string{"f5", "home", "pgup", "ctrl+a", "shift+c"} {
		f.HandleKey(k)
	}
	if got := f.Value(policyFieldName); got != "" {
		t.Fatalf("named keys should not append, got %q", got)
	}
}

// TestPolicyCreateForm_BuildCommand_RequiresName anchors the
// required-name contract. The CLI would reject an empty name
// anyway but the TUI should catch it at the boundary so the
// operator gets an inline status, not a stderr dump.
func TestPolicyCreateForm_BuildCommand_RequiresName(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	if _, err := f.BuildCommand(); err == nil {
		t.Fatal("BuildCommand with blank Name must error")
	}
}

// TestPolicyCreateForm_BuildCommand_RejectsBadName enforces the
// _sanitize_policy_name contract client-side. Any character outside
// alnum/_/- must be rejected.
func TestPolicyCreateForm_BuildCommand_RejectsBadName(t *testing.T) {
	for _, bad := range []string{"name with space", "semi;colon", "slash/path", "../escape"} {
		f := NewPolicyCreateForm()
		f.Open()
		f.SetValue(policyFieldName, bad)
		if _, err := f.BuildCommand(); err == nil {
			t.Errorf("BuildCommand accepted invalid Name %q", bad)
		}
	}
}

// TestPolicyCreateForm_BuildCommand_ArgvShape verifies the argv
// matches the `defenseclaw policy create` option surface exactly.
func TestPolicyCreateForm_BuildCommand_ArgvShape(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.SetValue(policyFieldName, "prod-strict")
	f.SetValue(policyFieldDescription, "Production policy")
	f.SetValue(policyFieldPreset, "strict")
	f.SetValue(policyFieldCritical, "block")
	f.SetValue(policyFieldHigh, "block")
	f.SetValue(policyFieldMedium, "warn")
	f.SetValue(policyFieldLow, "allow")

	argv, err := f.BuildCommand()
	if err != nil {
		t.Fatalf("BuildCommand failed: %v", err)
	}
	want := []string{
		"policy", "create", "prod-strict",
		"--description", "Production policy",
		"--from-preset", "strict",
		"--critical-action", "block",
		"--high-action", "block",
		"--medium-action", "warn",
		"--low-action", "allow",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv mismatch:\n got: %v\nwant: %v", argv, want)
	}
}

// TestPolicyCreateForm_BuildCommand_BlankSeverityAllowed confirms
// that blank severity fields are simply dropped, letting the
// preset default apply. A regression here would force every field
// to be filled, contradicting the CLI contract.
func TestPolicyCreateForm_BuildCommand_BlankSeverityAllowed(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.SetValue(policyFieldName, "p")
	argv, err := f.BuildCommand()
	if err != nil {
		t.Fatalf("BuildCommand with only Name failed: %v", err)
	}
	for _, flag := range []string{"--critical-action", "--high-action", "--medium-action", "--low-action", "--from-preset"} {
		for _, arg := range argv {
			if arg == flag {
				t.Errorf("argv unexpectedly contains %q with blank form: %v", flag, argv)
			}
		}
	}
}

// TestPolicyCreateForm_BuildCommand_RejectsBadAction catches typos
// in the severity-action cells before dispatch. "block" / "warn" /
// "allow" / blank are the only valid values.
func TestPolicyCreateForm_BuildCommand_RejectsBadAction(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.SetValue(policyFieldName, "p")
	f.SetValue(policyFieldHigh, "reject") // not a valid choice
	if _, err := f.BuildCommand(); err == nil {
		t.Fatal("BuildCommand should reject high-action=reject")
	}
}

// TestPolicyCreateForm_BuildCommand_RejectsBadPreset mirrors the
// severity check for the preset field.
func TestPolicyCreateForm_BuildCommand_RejectsBadPreset(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.SetValue(policyFieldName, "p")
	f.SetValue(policyFieldPreset, "medium") // not a valid preset
	if _, err := f.BuildCommand(); err == nil {
		t.Fatal("BuildCommand should reject preset=medium")
	}
}

// TestPolicyCreateForm_EnterAdvancesThenSubmits walks every field
// and confirms only the final Enter dispatches.
func TestPolicyCreateForm_EnterAdvancesThenSubmits(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.SetValue(policyFieldName, "p")
	for i := 0; i < int(policyFieldCount)-1; i++ {
		submit, _, _, _ := f.HandleKey("enter")
		if submit {
			t.Fatalf("Enter on field %d should advance, not submit", i)
		}
	}
	submit, bin, args, display := f.HandleKey("enter")
	if !submit {
		t.Fatal("Enter on final field should submit")
	}
	if bin != "defenseclaw" || len(args) < 3 || args[0] != "policy" || args[1] != "create" {
		t.Errorf("unexpected submit: bin=%q args=%v", bin, args)
	}
	if !strings.Contains(display, "policy create p") {
		t.Errorf("display should name the policy, got %q", display)
	}
}

// TestPolicyCreateForm_EscCloses verifies the safety exit.
func TestPolicyCreateForm_EscCloses(t *testing.T) {
	f := NewPolicyCreateForm()
	f.Open()
	f.HandleKey("esc")
	if f.IsActive() {
		t.Fatal("Esc should close the form")
	}
}

// ------------------------------------------------------------------
// PolicyPanel Policies sub-tab — integration tests
// ------------------------------------------------------------------

// newTestPolicyPanel spins up a PolicyPanel with a temp PolicyDir
// containing the supplied policy files. Keeps the tests
// hermetic — no dependency on a real ~/.defenseclaw.
func newTestPolicyPanel(t *testing.T, names ...string) (*PolicyPanel, string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		path := filepath.Join(dir, n+".yaml")
		if err := os.WriteFile(path, []byte("name: "+n+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	cfg := &config.Config{PolicyDir: dir}
	p := NewPolicyPanel(nil, cfg)
	p.activeTab = policyTabPolicies
	return &p, dir
}

func TestHandlePoliciesKey_NavigationAndCLIDispatch(t *testing.T) {
	p, _ := newTestPolicyPanel(t, "a", "b", "c")
	p.loadPolicies()

	if len(p.policies) != 3 {
		t.Fatalf("loadPolicies: want 3 entries, got %d (%v)", len(p.policies), p.policies)
	}

	// j/down moves cursor
	p.handlePoliciesKey("j")
	if p.policyCursor != 1 {
		t.Errorf("after 'j', cursor=%d, want 1", p.policyCursor)
	}

	// enter on selection → activate CLI dispatch
	bin, args, name := p.handlePoliciesKey("enter")
	if bin != "defenseclaw" || len(args) != 3 || args[0] != "policy" || args[1] != "activate" || args[2] != "b" {
		t.Errorf("Enter must dispatch `policy activate b`, got bin=%q args=%v", bin, args)
	}
	if !strings.Contains(name, "activate b") {
		t.Errorf("display name should mention the target, got %q", name)
	}

	// 's' → show
	if _, args, _ := p.handlePoliciesKey("s"); len(args) != 3 || args[1] != "show" {
		t.Errorf("'s' must dispatch `policy show`, got %v", args)
	}
	// 'd' → delete
	if _, args, _ := p.handlePoliciesKey("d"); len(args) != 3 || args[1] != "delete" {
		t.Errorf("'d' must dispatch `policy delete`, got %v", args)
	}
	// 'l' → list
	if _, args, _ := p.handlePoliciesKey("l"); len(args) != 2 || args[1] != "list" {
		t.Errorf("'l' must dispatch `policy list`, got %v", args)
	}
	// 'v' → validate
	if _, args, _ := p.handlePoliciesKey("v"); len(args) != 2 || args[1] != "validate" {
		t.Errorf("'v' must dispatch `policy validate`, got %v", args)
	}
}

// TestHandlePoliciesKey_NoSelection_Safe is the paired safety
// test: on an empty list the action keys must not dispatch.
func TestHandlePoliciesKey_NoSelection_Safe(t *testing.T) {
	p, _ := newTestPolicyPanel(t) // empty dir → no policies
	p.loadPolicies()
	for _, k := range []string{"enter", "a", "s", "d"} {
		bin, _, _ := p.handlePoliciesKey(k)
		if bin != "" {
			t.Errorf("'%s' on empty list must not dispatch, got bin=%q", k, bin)
		}
	}
}

// TestHandlePoliciesKey_N_OpensCreateForm confirms the overlay
// handoff — once the form is open, list-level keys must not
// dispatch.
func TestHandlePoliciesKey_N_OpensCreateForm(t *testing.T) {
	p, _ := newTestPolicyPanel(t, "a")
	p.loadPolicies()
	p.handlePoliciesKey("n")
	if !p.policyForm.IsActive() {
		t.Fatal("'n' must open the create form")
	}

	// With the form active, HandleKey should route to the form.
	// Typing a rune must land in the Name field, not crash.
	p.HandleKey("x")
	if p.policyForm.Value(policyFieldName) != "x" {
		t.Errorf("HandleKey should route to form; Name=%q", p.policyForm.Value(policyFieldName))
	}

	// Esc closes.
	p.HandleKey("esc")
	if p.policyForm.IsActive() {
		t.Error("Esc should close the form")
	}
}

// TestHandleOPAKey_T_RunsPolicyTest is the P1-#8 regression test.
// Before the fix, capital-T silently did nothing on the OPA tab.
func TestHandleOPAKey_T_RunsPolicyTest(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	bin, args, _ := p.handleOPAKey("T")
	if bin != "defenseclaw" {
		t.Fatalf("'T' must dispatch defenseclaw, got %q", bin)
	}
	if len(args) != 2 || args[0] != "policy" || args[1] != "test" {
		t.Errorf("'T' must dispatch `policy test`, got %v", args)
	}
}

// TestHandleOPAKey_LowerT_StillToggles guards against collapsing
// the distinct meanings of 't' (toggle) vs 'T' (run).
func TestHandleOPAKey_LowerT_StillToggles(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	before := p.showTests
	bin, _, _ := p.handleOPAKey("t")
	if bin != "" {
		t.Errorf("'t' must NOT dispatch a CLI command, got %q", bin)
	}
	if p.showTests == before {
		t.Error("'t' must toggle showTests")
	}
}

// TestLoadPolicies_ActiveMarker verifies the active.yaml symlink
// is detected and hoisted onto activePolicy without appearing in
// the regular list.
func TestLoadPolicies_ActiveMarker(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		_ = os.WriteFile(filepath.Join(dir, n+".yaml"), []byte("name: "+n), 0o600)
	}
	// Create active.yaml as a symlink to b.yaml.
	if err := os.Symlink(filepath.Join(dir, "b.yaml"), filepath.Join(dir, "active.yaml")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	p := NewPolicyPanel(nil, &config.Config{PolicyDir: dir})
	p.loadPolicies()
	if p.activePolicy != "b" {
		t.Errorf("activePolicy = %q, want \"b\"", p.activePolicy)
	}
	for _, n := range p.policies {
		if n == "active" {
			t.Error("policies list must not include the active marker file")
		}
	}
}
