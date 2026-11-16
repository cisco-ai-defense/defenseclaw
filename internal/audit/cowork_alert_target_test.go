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

package audit

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"
)

type coworkAlertTargetFixture struct {
	Rows []struct {
		ID         string         `json:"id"`
		Action     string         `json:"action"`
		Severity   string         `json:"severity"`
		Target     string         `json:"target"`
		Connector  string         `json:"connector"`
		RequestID  string         `json:"request_id"`
		Details    string         `json:"details"`
		Structured map[string]any `json:"structured"`
		Enforced   bool           `json:"enforced"`
	} `json:"rows"`
	Selections []struct {
		Alert    string   `json:"alert"`
		Printed  string   `json:"printed"`
		Selected []string `json:"selected"`
	} `json:"selections"`
	NotCowork []struct {
		Alert        string `json:"alert"`
		CoworkTarget string `json:"cowork_target"`
	} `json:"not_cowork"`
}

// Cowork audit M1: alerts print cowork:PreToolUse for a Claude Cowork
// finding (stored claudecode:PreToolUse) and "cowork PreToolUse" for a Cowork
// hook block (stored PreToolUse). That Target, given to dismiss or
// acknowledge --target, selects the Cowork alert and never the Claude Code
// terminal alert with the same stored target. The CLI half of the round trip
// (alerts prints `printed`) is test_cmd_alerts_finding_rows.py.
func TestAlertTargetSelectorTakesThePrintedCoworkTarget(t *testing.T) {
	raw, err := os.ReadFile("testdata/cowork_alert_target.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture coworkAlertTargetFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 5, 16, 0, 0, 0, time.UTC)
	for i, row := range fixture.Rows {
		if err := store.LogEvent(Event{
			ID: row.ID, Timestamp: base.Add(time.Duration(i) * time.Second), Action: row.Action,
			Severity: row.Severity, Target: row.Target, Connector: row.Connector, RequestID: row.RequestID,
			Details: row.Details, Structured: row.Structured, Enforced: row.Enforced,
		}); err != nil {
			t.Fatal(err)
		}
	}
	selected := func(selector AlertAcknowledgementSelector) []string {
		t.Helper()
		got, err := store.SelectAlertAcknowledgementTargets(t.Context(), selector)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, item := range got {
			ids = append(ids, item.AlertID)
		}
		slices.Sort(ids)
		return ids
	}
	if len(fixture.Selections) == 0 {
		t.Fatal("fixture has no selections")
	}
	for _, sel := range fixture.Selections {
		want := slices.Clone(sel.Selected)
		slices.Sort(want)
		for _, selector := range []AlertAcknowledgementSelector{
			{Target: sel.Printed},
			{Target: sel.Printed, Connector: "claudecode"},
		} {
			if got := selected(selector); !slices.Equal(got, want) {
				t.Errorf("%s: selector %+v selected %v, want %v", sel.Alert, selector, got, want)
			}
		}
	}
	// The stored spelling (alerts --json target) is still compared exactly.
	if got, want := selected(AlertAcknowledgementSelector{Target: "claudecode:PreToolUse"}),
		[]string{"cowork-finding", "spoof-finding", "terminal-finding"}; !slices.Equal(got, want) {
		t.Errorf("claudecode:PreToolUse selected %v, want %v", got, want)
	}
	// Audit review 2 N1: surface=cowork in the free text of a row with a
	// structured payload (an unquoted reason=, a raw_payload=) is no marker.
	if len(fixture.NotCowork) == 0 {
		t.Fatal("fixture has no not_cowork rows")
	}
	for _, row := range fixture.NotCowork {
		if got := selected(AlertAcknowledgementSelector{Target: row.CoworkTarget}); slices.Contains(got, row.Alert) {
			t.Errorf("--target %q selected terminal row %s (%v)", row.CoworkTarget, row.Alert, got)
		}
	}
	for _, target := range []string{"cowork:", "cowork", "cowork:SessionStart", "cowork Stop"} {
		if got := selected(AlertAcknowledgementSelector{Target: target}); len(got) != 0 {
			t.Errorf("--target %q selected %v, want none", target, got)
		}
	}
}

func TestCoworkAlertTargetMapsOnlyCoworkSpellings(t *testing.T) {
	for target, want := range map[string]string{
		"cowork:PreToolUse":     "claudecode:PreToolUse",
		" Cowork:PostToolUse ":  "claudecode:PostToolUse",
		"cowork PreToolUse":     "PreToolUse",
		"cowork skill://one":    "skill://one",
		"cowork:":               "",
		"cowork":                "",
		"claudecode:PreToolUse": "",
		"coworker:PreToolUse":   "",
		"PreToolUse":            "",
	} {
		got, ok := coworkAlertTarget(target)
		if got != want || ok != (want != "") {
			t.Errorf("coworkAlertTarget(%q) = %q, %v; want %q", target, got, ok, want)
		}
	}
}

// Audit review 2 N1: a native v8 row keeps its fields in payload_json and
// leaves structured_json NULL. Its defenseclaw.agent.surface marks a Cowork
// call, as alerts read it (StructuredJSONReadSQL, _structured_sql in
// cli/defenseclaw/db.py), and its details, a free-text reason, never do.
func TestCoworkMarkerReadsTheV8PayloadNotItsReason(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 5, 16, 0, 0, 0, time.UTC)
	for i, call := range []struct{ request, payload, details string }{
		{"req-v8-cowork", `{"defenseclaw.agent.surface":"cowork"}`, "hook decision"},
		{"req-v8-terminal", `{"reason":"run echo surface=cowork now"}`, "run echo surface=cowork now"},
	} {
		finding := Event{
			ID: "finding-" + call.request, Timestamp: base.Add(time.Duration(i) * time.Second), Action: "scan-finding",
			Severity: "CRITICAL", Target: "claudecode:PreToolUse", Connector: "claudecode", RequestID: call.request,
			Details: "finding.observed", Structured: map[string]any{"defenseclaw.finding.rule_id": "SF2-MARKER-BLOCK"},
		}
		decision := Event{
			ID: "decision-" + call.request, Timestamp: finding.Timestamp, Action: "hook_decision", Severity: "INFO",
			Target: "PreToolUse", Connector: "claudecode", RequestID: call.request, Details: call.details,
		}
		for _, event := range []Event{finding, decision} {
			if err := store.LogEvent(event); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.db.Exec(`UPDATE audit_events SET structured_json = NULL, event_name = 'hook.decision',
			payload_json = ? WHERE id = ?`, call.payload, decision.ID); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.SelectAlertAcknowledgementTargets(t.Context(), AlertAcknowledgementSelector{Target: "cowork:PreToolUse"})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(got))
	for _, item := range got {
		ids = append(ids, item.AlertID)
	}
	if want := []string{"finding-req-v8-cowork"}; !slices.Equal(ids, want) {
		t.Errorf("cowork:PreToolUse selected %v, want %v", ids, want)
	}
}
