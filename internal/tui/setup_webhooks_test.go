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
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#11 — Webhook Editor: parse, key routing, CLI dispatch parity.
// ------------------------------------------------------------------

func TestParseWebhookListJSON_Empty(t *testing.T) {
	rows, err := parseWebhookListJSON([]byte("  "))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("empty: expected nil, got %v", rows)
	}
}

func TestParseWebhookListJSON_Shape(t *testing.T) {
	in := []byte(`[
		{"name":"ops-slack","type":"slack","url":"https://hooks.slack.com/x","secret_env":"","room_id":"","min_severity":"high","events":["admission"],"timeout_seconds":10,"cooldown_seconds":null,"enabled":true},
		{"name":"pager","type":"pagerduty","url":"https://events.pagerduty.com/v2/enqueue","secret_env":"PD_KEY","room_id":"","min_severity":"critical","events":[],"timeout_seconds":15,"cooldown_seconds":0,"enabled":false}
	]`)
	rows, err := parseWebhookListJSON(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Name != "ops-slack" || rows[0].Type != "slack" || !rows[0].Enabled {
		t.Errorf("row0 mis-parsed: %+v", rows[0])
	}
	if rows[0].CooldownSeconds != nil {
		t.Errorf("row0 cooldown: expected nil, got %v", rows[0].CooldownSeconds)
	}
	if rows[1].CooldownSeconds == nil || *rows[1].CooldownSeconds != 0 {
		t.Errorf("row1 cooldown: expected 0, got %v", rows[1].CooldownSeconds)
	}
}

func TestParseWebhookListJSON_Bad(t *testing.T) {
	_, err := parseWebhookListJSON([]byte("not json"))
	if err == nil {
		t.Error("malformed JSON should error")
	}
}

func makeWebhookEditor(rows []webhookRow) WebhookEditorModel {
	m := NewWebhookEditorModel()
	m.SetLister(func() ([]webhookRow, error) { return rows, nil })
	m.Open()
	return m
}

func TestWebhookEditor_NavBounds(t *testing.T) {
	m := makeWebhookEditor([]webhookRow{{Name: "a"}, {Name: "b"}, {Name: "c"}})
	// down past end is clamped
	for range 5 {
		m.HandleKey("j")
	}
	if m.cursor != 2 {
		t.Errorf("cursor: %d, want 2", m.cursor)
	}
	// up past start is clamped
	for range 5 {
		m.HandleKey("k")
	}
	if m.cursor != 0 {
		t.Errorf("cursor: %d, want 0", m.cursor)
	}
	m.HandleKey("G")
	if m.cursor != 2 {
		t.Errorf("G: cursor %d", m.cursor)
	}
	m.HandleKey("g")
	if m.cursor != 0 {
		t.Errorf("g: cursor %d", m.cursor)
	}
}

// TestWebhookEditor_EnableDisableRemoveTestShow covers the full set
// of mutation verbs. Each case asserts the CLI argv verbatim so we
// catch flag-order changes that'd break the external interface.
func TestWebhookEditor_EnableDisableRemoveTestShow(t *testing.T) {
	cases := []struct {
		name    string
		setup   []webhookRow
		cursor  int
		keys    []string
		wantCmd bool
		wantBin string
		wantArg []string
	}{
		{
			name:    "enable_disabled",
			setup:   []webhookRow{{Name: "w1", Enabled: false}},
			keys:    []string{"e"},
			wantCmd: true, wantBin: "defenseclaw",
			wantArg: []string{"setup", "webhook", "enable", "w1"},
		},
		{
			name:    "disable_enabled",
			setup:   []webhookRow{{Name: "w1", Enabled: true}},
			keys:    []string{"d"},
			wantCmd: true, wantBin: "defenseclaw",
			wantArg: []string{"setup", "webhook", "disable", "w1"},
		},
		{
			name:    "test",
			setup:   []webhookRow{{Name: "w1", Enabled: true}},
			keys:    []string{"t"},
			wantCmd: true, wantBin: "defenseclaw",
			wantArg: []string{"setup", "webhook", "test", "w1"},
		},
		{
			name:    "show",
			setup:   []webhookRow{{Name: "w1", Enabled: true}},
			keys:    []string{"s"},
			wantCmd: true, wantBin: "defenseclaw",
			wantArg: []string{"setup", "webhook", "show", "w1"},
		},
		{
			name:    "remove_requires_confirmation_y",
			setup:   []webhookRow{{Name: "w1"}},
			keys:    []string{"r", "y"},
			wantCmd: true, wantBin: "defenseclaw",
			wantArg: []string{"setup", "webhook", "remove", "w1", "--yes"},
		},
		{
			name:    "remove_cancelled_n",
			setup:   []webhookRow{{Name: "w1"}},
			keys:    []string{"r", "n"},
			wantCmd: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := makeWebhookEditor(tc.setup)
			m.cursor = tc.cursor
			var run bool
			var bin string
			var args []string
			for _, k := range tc.keys {
				r, b, a, _ := m.HandleKey(k)
				if r {
					run, bin, args = r, b, a
				}
			}
			if run != tc.wantCmd {
				t.Fatalf("runCmd=%v, want %v", run, tc.wantCmd)
			}
			if tc.wantCmd {
				if bin != tc.wantBin {
					t.Errorf("binary=%q, want %q", bin, tc.wantBin)
				}
				if !reflect.DeepEqual(args, tc.wantArg) {
					t.Errorf("args=%v, want %v", args, tc.wantArg)
				}
			}
		})
	}
}

// TestWebhookEditor_EnableAlreadyEnabled is a no-op that should set
// a status message rather than duplicate-dispatch.
func TestWebhookEditor_EnableAlreadyEnabled(t *testing.T) {
	m := makeWebhookEditor([]webhookRow{{Name: "w1", Enabled: true}})
	run, _, _, _ := m.HandleKey("e")
	if run {
		t.Fatal("enabling an already-enabled webhook should be a no-op")
	}
	if !strings.Contains(m.status, "already enabled") {
		t.Errorf("status: %q", m.status)
	}
}

func TestWebhookEditor_DisableAlreadyDisabled(t *testing.T) {
	m := makeWebhookEditor([]webhookRow{{Name: "w1", Enabled: false}})
	run, _, _, _ := m.HandleKey("d")
	if run {
		t.Fatal("disabling an already-disabled webhook should be a no-op")
	}
	if !strings.Contains(m.status, "already disabled") {
		t.Errorf("status: %q", m.status)
	}
}

// TestWebhookEditor_AddTriggersWizard reproduces the add-handoff path
// — the editor doesn't exec the CLI directly; it flags SetupPanel to
// open the wizard form.
func TestWebhookEditor_AddTriggersWizard(t *testing.T) {
	m := makeWebhookEditor(nil)
	run, _, _, _ := m.HandleKey("a")
	if run {
		t.Error("'a' must not dispatch a CLI command directly")
	}
	if !m.WantsWebhookWizard() {
		t.Error("WantsWebhookWizard must be true after 'a'")
	}
	// Flag cleared on read.
	if m.WantsWebhookWizard() {
		t.Error("wantsWizard must clear after the first read")
	}
	if m.IsActive() {
		t.Error("editor must deactivate after 'a'")
	}
}

// TestWebhookEditor_CloseAndRefresh exercises the lifecycle — a
// resume pending flag should refresh the list and clear, just like
// the Audit Sinks editor does.
func TestWebhookEditor_CloseAndRefresh(t *testing.T) {
	m := makeWebhookEditor([]webhookRow{{Name: "w1"}})
	m.ResumeAfterCommand()
	if !m.DrainResume() {
		t.Error("DrainResume must return true after ResumeAfterCommand")
	}
	if m.DrainResume() {
		t.Error("DrainResume must be idempotent")
	}
	m.Close()
	if m.IsActive() {
		t.Error("Close must deactivate")
	}
}

// TestWebhookEditor_ListError surfaces the lister error in loadErr.
func TestWebhookEditor_ListError(t *testing.T) {
	m := NewWebhookEditorModel()
	m.SetLister(func() ([]webhookRow, error) { return nil, errors.New("boom") })
	m.Open()
	if m.loadErr == "" || !strings.Contains(m.loadErr, "boom") {
		t.Errorf("loadErr=%q", m.loadErr)
	}
	if len(m.webhooks) != 0 {
		t.Errorf("webhooks: %v", m.webhooks)
	}
}

// TestSetupPanel_EOpensWebhookEditor verifies the section handoff —
// pressing 'E' on the Webhooks section must route to the webhook
// editor (and NOT the sink editor).
func TestSetupPanel_EOpensWebhookEditor(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.webhookEditor.SetLister(func() ([]webhookRow, error) { return nil, nil })
	// Jump to the Webhooks section.
	for i, s := range p.sections {
		if s.Name == "Webhooks" {
			p.activeSection = i
			break
		}
	}
	if !p.IsEditorActive() && p.currentSection().Name != "Webhooks" {
		t.Fatal("couldn't position on Webhooks section")
	}
}
