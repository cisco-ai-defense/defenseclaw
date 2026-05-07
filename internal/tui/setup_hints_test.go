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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestSetupSections_EveryInteractiveFieldHasHint locks in the rule
// that every editable field in the Config Editor ships with a one-
// line hint. We exclude Kind=header rows (visual dividers carry no
// hint) and the list-summary rows whose Kind is "header" but that
// we surface via their section Summary/Help instead.
//
// Without this test, a reviewer can easily add a new knob to
// loadSections() and forget the Hint, silently regressing the UX
// the user explicitly requested.
func TestSetupSections_EveryInteractiveFieldHasHint(t *testing.T) {
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.loadSections()

	for _, sec := range p.sections {
		for _, f := range sec.Fields {
			if f.Kind == "header" {
				continue
			}
			if strings.TrimSpace(f.Hint) == "" {
				t.Errorf("section %q field %q (key=%s) missing Hint — add a one-line description in loadSections()",
					sec.Name, f.Label, f.Key)
			}
		}
	}
}

// TestSetupSections_EverySectionHasSummary asserts every tab in the
// Config Editor has a one-line orientation string. Operators rely on
// this to know which tab owns which config knobs without leaving the
// TUI for the docs.
func TestSetupSections_EverySectionHasSummary(t *testing.T) {
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.loadSections()

	for _, sec := range p.sections {
		if strings.TrimSpace(sec.Summary) == "" {
			t.Errorf("section %q missing Summary — add one-line orientation in loadSections()", sec.Name)
		}
	}
}

func TestSetupConfigSectionTabsWrapAndHitTest(t *testing.T) {
	p := SetupPanel{
		width:         34,
		height:        24,
		mode:          setupModeConfig,
		activeSection: 0,
		activeLine:    0,
		scroll:        3,
		sections: []configSection{
			{Name: "General", Summary: "summary", Fields: []configField{{Label: "A", Kind: "string"}}},
			{Name: "Agent", Summary: "summary", Fields: []configField{{Label: "B", Kind: "string"}}},
			{Name: "Privacy", Summary: "summary", Fields: []configField{{Label: "C", Kind: "string"}}},
			{Name: "Connector Hooks", Summary: "summary", Fields: []configField{{Label: "D", Kind: "string"}}},
			{Name: "OpenTelemetry", Summary: "summary", Fields: []configField{{Label: "E", Kind: "string"}}},
		},
	}

	rows := p.configSectionTabRows()
	if len(rows) < 2 {
		t.Fatalf("expected wrapped section tabs, got %d row(s): %+v", len(rows), rows)
	}

	target := rows[1][0]
	p.handleConfigClick(target.start, 3)
	if p.activeSection != target.index {
		t.Fatalf("click on wrapped tab selected section %d, want %d", p.activeSection, target.index)
	}
	if p.scroll != 0 {
		t.Fatalf("section tab click should reset scroll, got %d", p.scroll)
	}

	fieldY := p.configFieldsStartY()
	if fieldY <= 4 {
		t.Fatalf("field start y=%d did not account for wrapped tabs + summary", fieldY)
	}
	p.activeLine = -1
	p.handleConfigClick(0, fieldY)
	if p.activeLine != 0 {
		t.Fatalf("field click selected activeLine=%d want 0", p.activeLine)
	}
}

// TestApplyConfigField_GatewayExtraFields covers the three knobs we
// newly surfaced in the TUI (TLSSkipVerify, ApprovalTimeout,
// DeviceKeyFile). They existed in config.yaml already but the
// Config Editor used to silently drop edits.
func TestApplyConfigField_GatewayExtraFields(t *testing.T) {
	c := &config.Config{}

	applyConfigField(c, "gateway.tls_skip_verify", "true")
	if !c.Gateway.TLSSkipVerify {
		t.Error("gateway.tls_skip_verify didn't stick")
	}

	applyConfigField(c, "gateway.approval_timeout_s", "45")
	if c.Gateway.ApprovalTimeout != 45 {
		t.Errorf("gateway.approval_timeout_s = %d, want 45", c.Gateway.ApprovalTimeout)
	}

	applyConfigField(c, "gateway.device_key_file", "/tmp/device.key")
	if c.Gateway.DeviceKeyFile != "/tmp/device.key" {
		t.Errorf("gateway.device_key_file = %q, want /tmp/device.key", c.Gateway.DeviceKeyFile)
	}
}

// TestSetupSections_GatewayExposesNewFields asserts the Gateway
// section actually renders the newly added keys so the test above
// is not an orphan check — both the UI surface AND the apply-layer
// need to agree.
func TestSetupSections_GatewayExposesNewFields(t *testing.T) {
	p := NewSetupPanel(nil, &config.Config{}, nil)
	p.loadSections()

	var gateway *configSection
	for i := range p.sections {
		if p.sections[i].Name == "Gateway" {
			gateway = &p.sections[i]
			break
		}
	}
	if gateway == nil {
		t.Fatal("Gateway section missing")
		return
	}

	want := map[string]bool{
		"gateway.tls_skip_verify":    false,
		"gateway.approval_timeout_s": false,
		"gateway.device_key_file":    false,
	}
	for _, f := range gateway.Fields {
		if _, ok := want[f.Key]; ok {
			want[f.Key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("Gateway section missing field %q — loadSections() forgot to expose it", k)
		}
	}
}

// TestWizardHowTo_AllPopulated makes sure every wizard has a
// populated help block so the landing page doesn't render a blank
// spot for operators.
func TestWizardHowTo_AllPopulated(t *testing.T) {
	for i := 0; i < wizardCount; i++ {
		if strings.TrimSpace(wizardHowTo[i]) == "" {
			t.Errorf("wizardHowTo[%d] (%s) is empty — add a Runs/Needs/Tip block",
				i, wizardNames[i])
		}
		// Each block should mention the CLI command it runs so
		// operators know what will actually execute. A lightweight
		// smoke check, but catches copy-paste regressions.
		if !strings.Contains(wizardHowTo[i], "defenseclaw") {
			t.Errorf("wizardHowTo[%d] (%s) should mention the 'defenseclaw' CLI command that runs",
				i, wizardNames[i])
		}
	}
}
