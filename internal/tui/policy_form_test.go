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
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
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

	// B3a: Enter (and 's') now open an in-panel YAML overlay
	// instead of dispatching `policy show` to the Activity panel.
	// The overlay stays on the Policies tab, so bin must be empty
	// and policyDetailOpen must flip to true with the selected
	// policy's content loaded.
	bin, args, _ := p.handlePoliciesKey("enter")
	if bin != "" || len(args) != 0 {
		t.Errorf("Enter must not dispatch a CLI command (overlay only), got bin=%q args=%v", bin, args)
	}
	if !p.policyDetailOpen || p.policyDetailName != "b" {
		t.Errorf("Enter must open the detail overlay for 'b', got open=%v name=%q", p.policyDetailOpen, p.policyDetailName)
	}

	// Closing the overlay via HandleKey lets the next dispatch
	// path run normally again.
	p.HandleKey("esc")
	if p.policyDetailOpen {
		t.Fatal("esc must close the policy detail overlay")
	}

	// 'a' → activate (previously handled by Enter).
	bin, args, name := p.handlePoliciesKey("a")
	if bin != "defenseclaw" || len(args) != 3 || args[0] != "policy" || args[1] != "activate" || args[2] != "b" {
		t.Errorf("'a' must dispatch `policy activate b`, got bin=%q args=%v", bin, args)
	}
	if !strings.Contains(name, "activate b") {
		t.Errorf("display name should mention the target, got %q", name)
	}

	// 's' → open the overlay (same behaviour as Enter).
	if _, _, _ = p.handlePoliciesKey("s"); !p.policyDetailOpen {
		t.Errorf("'s' must open the detail overlay")
	}
	p.HandleKey("esc")

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
// B3d moved the dispatch into a pendingCmd (so the output lands
// in-panel rather than routing through the Activity panel), so
// the assertion now checks that a Cmd is queued and the OPA output
// placeholder is populated rather than looking for CLI args.
func TestHandleOPAKey_T_RunsPolicyTest(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	bin, _, _ := p.handleOPAKey("T")
	if bin != "" {
		t.Fatalf("'T' must not dispatch via the Activity panel; got bin=%q", bin)
	}
	if cmd := p.TakeCmd(); cmd == nil {
		t.Fatal("'T' must queue a pending tea.Cmd for in-panel execution")
	}
	if p.regoOutput == "" {
		t.Error("'T' must seed regoOutput with a running indicator")
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

func TestPolicyPanelLoad_IncludesEmbeddedExfilJudgePrompt(t *testing.T) {
	packDir := t.TempDir()
	p := NewPolicyPanel(nil, &config.Config{
		Guardrail: config.GuardrailConfig{RulePackDir: packDir},
	})
	p.load()

	if _, ok := p.judgeYAMLs["exfil"]; !ok {
		t.Fatalf("embedded exfil judge was not loaded; judges=%v", p.judgeNames)
	}
	if !stringSliceContains(p.judgeNames, "exfil") {
		t.Fatalf("Judge Prompts list omitted exfil; judges=%v", p.judgeNames)
	}

	p.judgeCursor = stringSliceIndex(p.judgeNames, "exfil")
	out := p.viewJudge(120, 40)
	for _, needle := range []string{
		"exfil",
		"data-exfiltration safety classifier",
		"Sensitive File Access",
		"Exfiltration Channel",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("exfil prompt view missing %q:\n%s", needle, out)
		}
	}
}

func TestOrderedJudgeNames_PreservesKnownOrderAndIncludesExtras(t *testing.T) {
	got := orderedJudgeNames(map[string]*guardrail.JudgeYAML{
		"custom":         {},
		"pii":            {},
		"exfil":          {},
		"injection":      {},
		"tool-injection": {},
		"aaa":            {},
	})
	want := []string{"injection", "pii", "tool-injection", "exfil", "aaa", "custom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderedJudgeNames=%v, want %v", got, want)
	}
}

func stringSliceContains(values []string, needle string) bool {
	return stringSliceIndex(values, needle) >= 0
}

func stringSliceIndex(values []string, needle string) int {
	for i, value := range values {
		if value == needle {
			return i
		}
	}
	return -1
}

// TestRuleDetailEdit_LaunchesEditorOnSourceFile is the follow-up to
// the user report "how do I edit the rule?" — the rule detail
// overlay must expose an editor path so they're not stuck reading
// an un-editable YAML viewer. We assert that (a) opening the detail
// overlay on a disk-backed rule captures the source path, and (b)
// pressing 'e' inside the overlay queues a pending Cmd rather than
// silently doing nothing. We can't execute the Cmd in unit tests
// (it would exec “$EDITOR“), so the pending Cmd's existence is
// the behavioural contract.
func TestRuleDetailEdit_LaunchesEditorOnSourceFile(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.packRules = []*guardrail.RulesFileYAML{
		{
			Version:    1,
			Category:   "c2",
			SourcePath: "/etc/defenseclaw/rule-packs/default/rules/c2.yaml",
			Rules: []guardrail.RuleDefYAML{
				{ID: "C2-WEBHOOK-SITE", Pattern: "(?i)webhook\\.site", Title: "webhook.site", Severity: "HIGH"},
			},
		},
	}
	p.ruleCursor = 0

	p.openRuleDetail()
	if !p.ruleDetailOpen {
		t.Fatal("openRuleDetail did not flip the overlay flag")
	}
	if p.ruleDetailPath != "/etc/defenseclaw/rule-packs/default/rules/c2.yaml" {
		t.Fatalf("ruleDetailPath = %q, want the backing file", p.ruleDetailPath)
	}

	// Pressing 'e' inside the overlay must queue a pending Cmd;
	// the app-level EditorClosedMsg handler reloads the pack
	// when the editor exits.
	p.HandleKey("e")
	if cmd := p.TakeCmd(); cmd == nil {
		t.Fatal("'e' inside rule detail overlay must queue a launchEditor Cmd")
	}
}

// TestRuleDetailEdit_EmbeddedDefaultIsReadOnly protects the "don't
// promise an edit we can't deliver" case: rules loaded from the
// embedded defaults have no SourcePath, so 'e' must be a no-op and
// the overlay header switches to the read-only hint.
func TestRuleDetailEdit_EmbeddedDefaultIsReadOnly(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.packRules = []*guardrail.RulesFileYAML{
		{
			Version:  1,
			Category: "c2",
			// SourcePath intentionally empty — embedded default.
			Rules: []guardrail.RuleDefYAML{{ID: "X", Title: "x"}},
		},
	}
	p.ruleCursor = 0
	p.openRuleDetail()
	if p.ruleDetailPath != "" {
		t.Fatalf("embedded default leaked a source path: %q", p.ruleDetailPath)
	}

	p.HandleKey("e")
	if cmd := p.TakeCmd(); cmd != nil {
		t.Fatal("'e' on embedded-default rule must be a no-op")
	}
}

// TestRuleFilePathAtCursor_FlatIndex guards the invariant that
// packDetail's 'e' shortcut and openRuleDetail both resolve
// ruleCursor against the same flat index across (file → rule) —
// if they ever drift the 'e' key will edit a different file than
// the preview overlay shows.
func TestRuleFilePathAtCursor_FlatIndex(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.packRules = []*guardrail.RulesFileYAML{
		{Version: 1, Category: "a", SourcePath: "/a.yaml", Rules: []guardrail.RuleDefYAML{{ID: "a1"}, {ID: "a2"}}},
		{Version: 1, Category: "b", SourcePath: "/b.yaml", Rules: []guardrail.RuleDefYAML{{ID: "b1"}}},
	}

	cases := []struct {
		cursor int
		want   string
	}{
		{0, "/a.yaml"},
		{1, "/a.yaml"},
		{2, "/b.yaml"},
		{3, ""}, // out of range → no path
	}
	for _, tc := range cases {
		p.ruleCursor = tc.cursor
		if got := p.ruleFilePathAtCursor(); got != tc.want {
			t.Errorf("ruleCursor=%d: got %q, want %q", tc.cursor, got, tc.want)
		}
	}
}

// ------------------------------------------------------------------
// Overlay viewport clamping (policy + rule detail)
// ------------------------------------------------------------------

// longYAML returns a deterministic multi-line YAML body of exactly N
// lines (no trailing newline, so strings.Split returns exactly N
// elements — matching what we want the overlay footer to report).
func longYAML(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("- id: line-")
		b.WriteString(itoa(i))
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// TestPolicyDetailOverlay_ClampsToViewport pins the contract that a
// long YAML body never spills past the supplied (w, h). This is the
// regression we caught after PR #117: sensitive-paths YAMLs can be
// ~80 lines and used to overflow into the help bar / neighbouring
// panels.
func TestPolicyDetailOverlay_ClampsToViewport(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.policyDetailOpen = true
	p.policyDetailName = "sensitive-paths"
	p.policyDetailYAML = longYAML(80)

	out := p.renderPolicyDetailOverlay(60, 12)
	lines := strings.Split(out, "\n")
	if len(lines) > 12 {
		t.Fatalf("overlay exceeded height=12: got %d lines\n%s", len(lines), out)
	}
	// Footer must report the total even when we only show a slice.
	if !strings.Contains(out, "/ 80") {
		t.Errorf("expected '/ 80' in footer, got:\n%s", out)
	}
	// First body line should be visible when scroll is 0.
	if !strings.Contains(out, "line-0") {
		t.Errorf("expected first line visible, got:\n%s", out)
	}
}

// TestPolicyDetailOverlay_ScrollAdvances makes sure the scroll state
// we wired up in HandleKey actually reaches the renderer and that
// EOF is clamped so G / large-scroll doesn't strand the body off-screen.
func TestPolicyDetailOverlay_ScrollAdvances(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.policyDetailOpen = true
	p.policyDetailYAML = longYAML(40)

	// Scroll down 5 lines — line-0..4 should be hidden, line-5 visible.
	p.policyDetailScroll = 5
	out := p.renderPolicyDetailOverlay(60, 10)
	if strings.Contains(out, "id: line-0\n") {
		t.Errorf("expected line-0 to be scrolled off, got:\n%s", out)
	}
	if !strings.Contains(out, "line-5") {
		t.Errorf("expected line-5 to be visible after scroll=5, got:\n%s", out)
	}

	// Over-scroll sentinel (emulates the 'G' / end key) must clamp to
	// the last page, not silently render an empty body.
	p.policyDetailScroll = 1 << 30
	out = p.renderPolicyDetailOverlay(60, 10)
	if !strings.Contains(out, "/ 40") {
		t.Errorf("expected footer to still show /40 at EOF, got:\n%s", out)
	}
	if !strings.Contains(out, "line-39") {
		t.Errorf("expected last line-39 visible after end-jump, got:\n%s", out)
	}
	if p.policyDetailScroll >= 40 {
		t.Errorf("expected scroll to be clamped below total (40), got %d", p.policyDetailScroll)
	}
}

// TestRuleDetailOverlay_ClampsAndFitsFooter mirrors the policy
// overlay test. We also check that the "file:" footer is preserved
// since ruleDetailPath drives the editor shortcut.
func TestRuleDetailOverlay_ClampsAndFitsFooter(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.ruleDetailOpen = true
	p.ruleDetailPath = "/tmp/rules/injection.yaml"
	p.ruleDetailYAML = longYAML(50)

	out := p.renderRuleDetailOverlay(40, 14)
	lines := strings.Split(out, "\n")
	if len(lines) > 14 {
		t.Fatalf("rule overlay exceeded height=14: got %d lines\n%s", len(lines), out)
	}
	if !strings.Contains(out, "file: /tmp/rules/injection.yaml") {
		t.Errorf("expected file footer, got:\n%s", out)
	}
	if !strings.Contains(out, "/ 50") {
		t.Errorf("expected '/ 50' in footer, got:\n%s", out)
	}
}

// TestPolicyDetailOverlay_HandleKey_ScrollAndClose exercises the
// HandleKey pathway end-to-end to prove the scroll keys actually
// update policyDetailScroll (and that esc/enter/q still close the
// overlay the way the original review expected).
func TestPolicyDetailOverlay_HandleKey_ScrollAndClose(t *testing.T) {
	p := NewPolicyPanel(nil, &config.Config{})
	p.policyDetailOpen = true
	p.policyDetailYAML = longYAML(30)
	p.policyDetailName = "x"

	p.HandleKey("down")
	p.HandleKey("down")
	if p.policyDetailScroll != 2 {
		t.Fatalf("expected scroll=2 after two 'down', got %d", p.policyDetailScroll)
	}
	p.HandleKey("pgup")
	if p.policyDetailScroll != 0 {
		t.Errorf("expected scroll to clamp to 0 after pgup from 2, got %d", p.policyDetailScroll)
	}

	p.HandleKey("esc")
	if p.policyDetailOpen {
		t.Errorf("expected esc to close the overlay")
	}
	if p.policyDetailScroll != 0 {
		t.Errorf("expected scroll reset on close, got %d", p.policyDetailScroll)
	}
}

// TestClampYAMLBody_SmallViewport covers the pathological terminal
// sizes the existing review flagged: very narrow width and 1-row
// height. The helper must never return a string that blows past
// either bound or panics on empty input.
func TestClampYAMLBody_SmallViewport(t *testing.T) {
	scroll := 0
	// 3 rows of 200-char lines, 1-row viewport, 20-col width.
	yaml := strings.Repeat(strings.Repeat("a", 200)+"\n", 3)
	rendered, first, last, total := clampYAMLBody(yaml, 20, 1, &scroll)
	for _, line := range strings.Split(rendered, "\n") {
		if len(line) > 20 {
			t.Errorf("line exceeded width=20: len=%d", len(line))
		}
	}
	if total < 3 {
		t.Errorf("expected total>=3, got %d", total)
	}
	if first != 1 || last != 1 {
		t.Errorf("expected first=last=1 in 1-row viewport, got %d..%d", first, last)
	}

	// Empty input must not panic and must report total=1 (strings.Split
	// of "" returns a single empty element).
	scroll = 0
	_, _, _, total = clampYAMLBody("", 20, 4, &scroll)
	if total != 1 {
		t.Errorf("expected total=1 for empty yaml, got %d", total)
	}
}
