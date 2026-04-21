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
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// keyPress crafts a KeyPressMsg from a single-character key. Matches
// the helper used in app_test.go; kept local to avoid cross-file
// coupling.
func keyPress(text string) tea.KeyPressMsg {
	if text == "" {
		return tea.KeyPressMsg(tea.Key{})
	}
	return tea.KeyPressMsg(tea.Key{Text: text, Code: []rune(text)[0]})
}

// newTestEditor wires the editor to a deterministic lister so tests
// don't exec the real `defenseclaw` binary (which wouldn't be on PATH
// in the go test environment).
func newTestEditor(rows []sinkRow, listErr error) *SinkEditorModel {
	m := NewSinkEditorModel()
	m.SetLister(func() ([]sinkRow, error) {
		if listErr != nil {
			return nil, listErr
		}
		out := make([]sinkRow, len(rows))
		copy(out, rows)
		return out, nil
	})
	return &m
}

// dummyRows returns a canonical mix of sink kinds so tests can exercise
// enable/disable/kind-specific rendering against a single fixture.
func dummyRows() []sinkRow {
	return []sinkRow{
		{
			Name: "splunk-prod", Kind: "splunk_hec", Enabled: true,
			PresetID: "splunk-hec",
			Endpoint: "https://splunk.example.com:8088/services/collector",
		},
		{
			Name: "otel-dev", Kind: "otlp_logs", Enabled: false,
			PresetID: "grafana-cloud",
			Endpoint: "otel-collector:4317",
		},
		{
			Name: "webhook", Kind: "http_jsonl", Enabled: true,
			PresetID: "generic-jsonl",
			Endpoint: "https://siem.example.com/ingest",
		},
	}
}

func TestSinkEditor_OpenLoadsRowsAndClearsError(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	if !m.IsActive() {
		t.Fatal("editor not active after Open")
	}
	if m.loadErr != "" {
		t.Errorf("loadErr=%q want empty", m.loadErr)
	}
	if len(m.sinks) != 3 {
		t.Errorf("got %d sinks want 3", len(m.sinks))
	}
	if m.cursor != 0 {
		t.Errorf("cursor=%d want 0 on first open", m.cursor)
	}
}

func TestSinkEditor_OpenSurfacesLoadError(t *testing.T) {
	m := newTestEditor(nil, errors.New("config.yaml missing"))
	m.Open()

	if m.loadErr == "" {
		t.Fatal("expected loadErr to be populated")
	}
	if len(m.sinks) != 0 {
		t.Errorf("expected sinks to be cleared on error, got %d", len(m.sinks))
	}
	out := m.View()
	if !strings.Contains(out, "Error loading sinks") {
		t.Errorf("View must surface load error: %q", out)
	}
}

func TestSinkEditor_NavigationClampsBoundaries(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	// Cannot go above 0.
	m.HandleKey("up")
	if m.cursor != 0 {
		t.Errorf("up at top: cursor=%d want 0", m.cursor)
	}

	m.HandleKey("down")
	m.HandleKey("down")
	m.HandleKey("down") // one past end
	if m.cursor != 2 {
		t.Errorf("down at bottom: cursor=%d want 2", m.cursor)
	}

	m.HandleKey("G")
	if m.cursor != 2 {
		t.Errorf("G: cursor=%d want 2", m.cursor)
	}
	m.HandleKey("g")
	if m.cursor != 0 {
		t.Errorf("g: cursor=%d want 0", m.cursor)
	}
}

func TestSinkEditor_EnableDisableShellOut(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	t.Run("enable no-op when already enabled", func(t *testing.T) {
		// cursor on splunk-prod, already enabled
		run, _, _, _ := m.HandleKey("e")
		if run {
			t.Fatal("enable on already-enabled should be no-op")
		}
		if !strings.Contains(m.status, "already enabled") {
			t.Errorf("status=%q want 'already enabled'", m.status)
		}
	})

	t.Run("enable shells out on disabled sink", func(t *testing.T) {
		m.HandleKey("down") // otel-dev (disabled)
		run, bin, args, name := m.HandleKey("e")
		if !run {
			t.Fatal("enable on disabled sink must shell out")
		}
		if bin != "defenseclaw" {
			t.Errorf("bin=%q want 'defenseclaw'", bin)
		}
		want := []string{"setup", "observability", "enable", "otel-dev"}
		if strings.Join(args, " ") != strings.Join(want, " ") {
			t.Errorf("args=%v want %v", args, want)
		}
		if !strings.Contains(name, "enable") || !strings.Contains(name, "otel-dev") {
			t.Errorf("display name=%q missing verb or sink name", name)
		}
		if !m.resumePend {
			t.Error("resumePend=false after mutation; editor won't refresh")
		}
	})

	t.Run("disable shells out", func(t *testing.T) {
		m.HandleKey("g") // splunk-prod
		run, _, args, _ := m.HandleKey("d")
		if !run {
			t.Fatal("disable must shell out")
		}
		if args[3] != "splunk-prod" {
			t.Errorf("args=%v want disable splunk-prod", args)
		}
	})
}

func TestSinkEditor_RemoveRequiresConfirmation(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	run, _, _, _ := m.HandleKey("r")
	if run {
		t.Fatal("r must NOT shell out without confirmation")
	}
	if !m.confirmRm {
		t.Fatal("confirmRm=false after pressing r")
	}

	view := m.View()
	if !strings.Contains(view, "Remove") || !strings.Contains(view, "[y/N]") {
		t.Errorf("confirmation prompt missing from view: %q", view)
	}

	// N cancels.
	run, _, _, _ = m.HandleKey("N")
	if run {
		t.Fatal("N should cancel, not shell out")
	}
	if m.confirmRm {
		t.Error("confirmRm still true after cancel")
	}

	// Y confirms and must pass --yes.
	m.HandleKey("r")
	run, bin, args, name := m.HandleKey("y")
	if !run || bin != "defenseclaw" {
		t.Fatalf("y after r must shell out: run=%v bin=%q", run, bin)
	}
	hasYes := false
	for _, a := range args {
		if a == "--yes" {
			hasYes = true
			break
		}
	}
	if !hasYes {
		t.Errorf("remove args=%v missing --yes flag (would hang on CLI prompt)", args)
	}
	if !strings.Contains(name, "remove") {
		t.Errorf("display name=%q missing 'remove'", name)
	}
}

func TestSinkEditor_TestAction(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	run, bin, args, name := m.HandleKey("t")
	if !run {
		t.Fatal("t should shell out")
	}
	if bin != "defenseclaw" {
		t.Errorf("bin=%q want 'defenseclaw'", bin)
	}
	if len(args) < 4 || args[2] != "test" || args[3] != "splunk-prod" {
		t.Errorf("args=%v want [setup observability test splunk-prod]", args)
	}
	if !strings.Contains(name, "test") {
		t.Errorf("display=%q missing 'test'", name)
	}
}

func TestSinkEditor_AddOpensObservabilityWizard(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	run, _, _, _ := m.HandleKey("a")
	if run {
		t.Error("a should NOT shell out directly — must open wizard")
	}
	if !m.WantsObservabilityWizard() {
		t.Error("WantsObservabilityWizard()=false after 'a'")
	}
	// WantsObservabilityWizard is one-shot.
	if m.WantsObservabilityWizard() {
		t.Error("WantsObservabilityWizard() should be one-shot")
	}
	if m.IsActive() {
		t.Error("editor should be closed after handing off to wizard")
	}
}

func TestSinkEditor_MigrateSplunkIsIdempotent(t *testing.T) {
	// migrate-splunk is safe to run repeatedly (see CLI docstring);
	// the editor just shells out and lets the CLI handle no-op case.
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	run, bin, args, _ := m.HandleKey("m")
	if !run {
		t.Fatal("m must shell out")
	}
	if bin != "defenseclaw" {
		t.Errorf("bin=%q", bin)
	}
	hasApply := false
	for _, a := range args {
		if a == "--apply" {
			hasApply = true
			break
		}
	}
	if !hasApply {
		t.Errorf("migrate-splunk args=%v missing --apply (would be dry-run only)", args)
	}
}

func TestSinkEditor_EscClosesEditor(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	m.HandleKey("esc")
	if m.IsActive() {
		t.Error("editor still active after esc")
	}
}

func TestSinkEditor_RefreshKeyReloadsList(t *testing.T) {
	// First call returns one sink, second call returns two — a real
	// refresh happens if the lister is re-invoked.
	calls := 0
	m := NewSinkEditorModel()
	m.SetLister(func() ([]sinkRow, error) {
		calls++
		switch calls {
		case 1:
			return []sinkRow{{Name: "a", Kind: "splunk_hec", Enabled: true}}, nil
		default:
			return []sinkRow{
				{Name: "a", Kind: "splunk_hec", Enabled: true},
				{Name: "b", Kind: "otlp_logs", Enabled: false},
			}, nil
		}
	})
	m.Open()
	if len(m.sinks) != 1 {
		t.Fatalf("after open: got %d sinks", len(m.sinks))
	}
	m.HandleKey("ctrl+r")
	if len(m.sinks) != 2 {
		t.Fatalf("after refresh: got %d sinks (calls=%d)", len(m.sinks), calls)
	}
	if !strings.Contains(m.status, "refreshed") {
		t.Errorf("status=%q want 'refreshed'", m.status)
	}
}

func TestSinkEditor_DrainResumeOnlyOnce(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	m.ResumeAfterCommand()
	if !m.DrainResume() {
		t.Fatal("DrainResume returned false despite pending flag")
	}
	if m.DrainResume() {
		t.Error("DrainResume must be one-shot")
	}
}

func TestSinkEditor_NoSelectionIsSafe(t *testing.T) {
	m := newTestEditor(nil, nil)
	m.Open()

	// No rows — every action should either be a no-op or emit a
	// status message, never a nil-deref.
	for _, k := range []string{"e", "d", "r", "t"} {
		run, _, _, _ := m.HandleKey(k)
		if run {
			t.Errorf("%q shelled out with empty list", k)
		}
	}
}

func TestParseSinkListJSON_RoundTripSchema(t *testing.T) {
	// The JSON shape is authored by cmd_setup_observability.py
	// `_dest_to_dict`. Keep this fixture in sync — if the Python
	// writer drops a field, this parser will silently zero it out.
	raw := `[
	  {
	    "name": "splunk-prod",
	    "target": "audit_sinks",
	    "kind": "splunk_hec",
	    "enabled": true,
	    "preset_id": "splunk-hec",
	    "endpoint": "https://splunk.example.com:8088/services/collector",
	    "signals": null
	  }
	]`
	rows, err := parseSinkListJSON([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	r := rows[0]
	if r.Name != "splunk-prod" || r.Kind != "splunk_hec" ||
		!r.Enabled || r.PresetID != "splunk-hec" ||
		r.Target != "audit_sinks" ||
		r.Endpoint != "https://splunk.example.com:8088/services/collector" {
		t.Errorf("row decoded wrong: %+v", r)
	}
}

func TestParseSinkListJSON_EmptyReturnsNil(t *testing.T) {
	rows, err := parseSinkListJSON([]byte("   "))
	if err != nil || rows != nil {
		t.Fatalf("empty input: rows=%v err=%v", rows, err)
	}

	rows, err = parseSinkListJSON([]byte("[]"))
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty array: rows=%v err=%v", rows, err)
	}
}

func TestParseSinkListJSON_BadInput(t *testing.T) {
	_, err := parseSinkListJSON([]byte("{not json"))
	if err == nil {
		t.Fatal("expected parse error on malformed JSON")
	}
}

func TestTruncMid_PreservesHeadAndTail(t *testing.T) {
	cases := []struct {
		in, want string
		width    int
	}{
		{"short", "short", 10},
		{"exactlyten", "exactlyten", 10},
		{"this is a very long sink name", "this i…k name", 13},
		{"", "", 10},
	}
	for _, c := range cases {
		got := truncMid(c.in, c.width)
		if got != c.want {
			t.Errorf("truncMid(%q, %d)=%q want %q", c.in, c.width, got, c.want)
		}
	}

	// Degenerate widths must not panic.
	if got := truncMid("abcdef", 0); got != "" {
		t.Errorf("width=0: got %q", got)
	}
	if got := truncMid("abcdef", 2); got != "ab" {
		t.Errorf("width=2: got %q", got)
	}
}

func TestSinkEditor_ViewHighlightsCursor(t *testing.T) {
	m := newTestEditor(dummyRows(), nil)
	m.Open()

	out := m.View()
	for _, want := range []string{
		"Audit Sinks",
		"splunk-prod", "otel-dev", "webhook",
		"NAME", "KIND", "ENABLED", "PRESET", "ENDPOINT",
		"j/k nav",
		"migrate-splunk",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q\n----\n%s", want, out)
		}
	}
}

func TestSinkEditor_ViewEmptyRendersAddHint(t *testing.T) {
	m := newTestEditor(nil, nil)
	m.Open()

	out := m.View()
	for _, want := range []string{
		"no sinks configured",
		"press 'a'",
		"Observability wizard",
		"migrate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("empty view missing %q\n----\n%s", want, out)
		}
	}
}

// newTestSetupPanel builds a SetupPanel with a stubbed sink lister
// pointing at `dummyRows()` so integration tests can exercise the full
// key-routing path without needing the real `defenseclaw` binary.
func newTestSetupPanel(t *testing.T) *SetupPanel {
	t.Helper()
	cfg := &config.Config{}
	p := NewSetupPanel(nil, cfg, NewCommandExecutor())
	p.sinkEditor.SetLister(func() ([]sinkRow, error) {
		return dummyRows(), nil
	})
	return &p
}

// findSectionIdx returns the index of the named config section, failing
// the test if missing. The config editor infra keys off the name rather
// than an enum, so we look it up by string.
func findSectionIdx(t *testing.T, p *SetupPanel, name string) int {
	t.Helper()
	for i, s := range p.sections {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("section %q not found (have %v)", name, sectionNames(p))
	return -1
}

func sectionNames(p *SetupPanel) []string {
	out := make([]string, 0, len(p.sections))
	for _, s := range p.sections {
		out = append(out, s.Name)
	}
	return out
}

func TestSetupPanel_EOpensSinkEditorOnAuditSinksSection(t *testing.T) {
	p := newTestSetupPanel(t)
	p.mode = setupModeConfig
	p.activeSection = findSectionIdx(t, p, "Audit Sinks")

	run, _, _, _ := p.HandleKey(keyPress("E"))
	if run {
		t.Fatal("E should not produce a CLI command directly")
	}
	if !p.IsSinkEditorActive() {
		t.Fatal("sink editor not active after 'E' on Audit Sinks section")
	}
	if len(p.sinkEditor.sinks) != 3 {
		t.Errorf("stub lister not invoked on Open; got %d sinks", len(p.sinkEditor.sinks))
	}
}

func TestSetupPanel_EIgnoredOutsideAuditSinksSection(t *testing.T) {
	p := newTestSetupPanel(t)
	p.mode = setupModeConfig
	p.activeSection = findSectionIdx(t, p, "General")

	_, _, _, _ = p.HandleKey(keyPress("E"))
	if p.IsSinkEditorActive() {
		t.Error("editor opened while General section was active — key must be section-scoped")
	}
}

func TestSetupPanel_SinkEditorEnableShellOutRoutesThroughWizardTerminal(t *testing.T) {
	p := newTestSetupPanel(t)
	p.mode = setupModeConfig
	p.activeSection = findSectionIdx(t, p, "Audit Sinks")
	p.sinkEditor.Open()
	// Move cursor to the disabled sink so enable actually shells out.
	p.sinkEditor.cursor = 1 // otel-dev

	run, bin, args, name := p.HandleKey(keyPress("e"))
	if !run {
		t.Fatalf("expected run=true; args=%v name=%q", args, name)
	}
	if bin != "defenseclaw" {
		t.Errorf("binary=%q want 'defenseclaw'", bin)
	}
	if !p.wizRunning {
		t.Error("wizRunning=false after editor mutation; wizard terminal won't render")
	}
	if !p.sinkEditorResume {
		t.Error("sinkEditorResume=false after editor mutation; editor won't re-open")
	}
	if p.IsSinkEditorActive() {
		t.Error("editor should hide while command streams")
	}
	if len(p.wizOutput) == 0 {
		t.Error("wizOutput empty — terminal banner missing")
	}
}

func TestSetupPanel_SinkEditorResumesAfterCommand(t *testing.T) {
	p := newTestSetupPanel(t)
	p.mode = setupModeConfig
	p.activeSection = findSectionIdx(t, p, "Audit Sinks")
	p.sinkEditor.Open()
	p.sinkEditor.cursor = 1

	// Kick off an enable — transitions into wizard terminal.
	p.HandleKey(keyPress("e"))

	// Simulate CommandDoneMsg flow.
	p.WizardFinished(0)

	// Esc out of wizard terminal — should restore the editor.
	p.HandleKey(keyPress("esc"))

	if !p.IsSinkEditorActive() {
		t.Fatal("editor not re-opened after command finished + esc")
	}
	if p.sinkEditorResume {
		t.Error("sinkEditorResume should be cleared after restoration")
	}
}

func TestSetupPanel_SinkEditorAddOpensObservabilityWizard(t *testing.T) {
	p := newTestSetupPanel(t)
	p.mode = setupModeConfig
	p.activeSection = findSectionIdx(t, p, "Audit Sinks")
	p.sinkEditor.Open()

	_, _, _, _ = p.HandleKey(keyPress("a"))
	if p.IsSinkEditorActive() {
		t.Error("editor still active after 'a' — should close to hand off to wizard")
	}
	if !p.IsFormActive() {
		t.Error("Observability wizard form not active after 'a'")
	}
	if p.wizRunIdx != wizardObservability {
		t.Errorf("wizRunIdx=%d want wizardObservability (%d)", p.wizRunIdx, wizardObservability)
	}
}

func TestSinkEditor_SetListerAcceptsNilSafely(t *testing.T) {
	// Paranoia: SetLister(nil) should not blow up the default lister.
	m := NewSinkEditorModel()
	m.SetLister(nil)
	if m.lister == nil {
		t.Fatal("SetLister(nil) clobbered the default lister")
	}
}

// TestSinkEditor_RefreshInvokesListerError asserts that a list-listing
// error leaves the editor usable but surfaces the message. Without this
// guard, an unreachable CLI would produce a silently-empty list which
// would look like "all sinks removed" — a dangerous illusion.
func TestSinkEditor_RefreshInvokesListerError(t *testing.T) {
	var invoked int
	m := NewSinkEditorModel()
	m.SetLister(func() ([]sinkRow, error) {
		invoked++
		return nil, errors.New("boom")
	})
	m.Open()

	if invoked != 1 {
		t.Fatalf("lister invoked %d times, want 1", invoked)
	}
	if m.loadErr == "" {
		t.Error("loadErr missing on stub error")
	}
	if !strings.Contains(m.View(), "boom") {
		t.Errorf("view missing error text: %s", m.View())
	}
}
