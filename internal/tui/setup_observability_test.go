// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
)

// TestObservabilityWizardFields_PresetRebuildsForm asserts that
// selecting a new preset id yields the form layout for that preset —
// the TUI's single exit for the "pick preset, then fill prompts" flow.
//
// We assert on field labels rather than counts because the prompts
// churn with the Python preset registry; labels are the stable
// contract the TUI mirrors.
func TestObservabilityWizardFields_PresetRebuildsForm(t *testing.T) {
	cases := []struct {
		preset      string
		mustHave    []string // labels that MUST appear
		mustNotHave []string // labels that must NOT appear
	}{
		{
			preset:      "splunk-o11y",
			mustHave:    []string{"Realm", "Signals", "Access Token"},
			mustNotHave: []string{"HEC Token", "URL", "Dataset"},
		},
		{
			preset:      "datadog",
			mustHave:    []string{"Site", "API Key"},
			mustNotHave: []string{"Realm", "URL"},
		},
		{
			preset:   "webhook",
			mustHave: []string{"URL", "Method", "Verify TLS"},
			// Webhook has no "Signals" field because its target is
			// audit_sinks (log forwarder), not the OTel exporter.
			mustNotHave: []string{"Signals", "Realm", "Site"},
		},
		{
			preset:   "otlp",
			mustHave: []string{"Endpoint", "Protocol", "Target", "Signals"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.preset, func(t *testing.T) {
			fields := observabilityWizardFields(tc.preset)

			// Preset picker is always field 0 so the user can cycle
			// without losing their place.
			if fields[0].Kind != "preset" {
				t.Fatalf("field 0 kind=%q want preset", fields[0].Kind)
			}
			if fields[0].Value != tc.preset {
				t.Fatalf("field 0 Value=%q want %q", fields[0].Value, tc.preset)
			}

			labels := make(map[string]bool, len(fields))
			for _, f := range fields {
				labels[f.Label] = true
			}
			for _, want := range tc.mustHave {
				if !labels[want] {
					t.Errorf("preset %s: missing field %q (have %v)", tc.preset, want, labelList(fields))
				}
			}
			for _, notWant := range tc.mustNotHave {
				if labels[notWant] {
					t.Errorf("preset %s: unexpected field %q present", tc.preset, notWant)
				}
			}
		})
	}
}

// TestObservabilityWizardFields_TokenIsPasswordKind guards against a
// regression where the secret prompt leaked plaintext into the TUI
// output. The render layer masks *all* password-kind fields, so every
// preset that takes a token must declare Kind=="password".
func TestObservabilityWizardFields_TokenIsPasswordKind(t *testing.T) {
	presetsWithTokens := []string{
		"splunk-o11y", "splunk-hec", "datadog", "honeycomb",
		"newrelic", "grafana-cloud",
	}
	for _, id := range presetsWithTokens {
		t.Run(id, func(t *testing.T) {
			fields := observabilityWizardFields(id)
			var found *wizardFormField
			for i := range fields {
				if fields[i].Flag == "--token" {
					found = &fields[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("preset %s has no --token field", id)
			}
			if found.Kind != "password" {
				t.Errorf("preset %s: --token Kind=%q want password", id, found.Kind)
			}
		})
	}
}

// TestBuildWizardArgs_ObservabilityPresetIsPositional asserts the
// preset id is injected as a positional argument (not a --flag) so the
// CLI signature matches `defenseclaw setup observability add <preset>`.
func TestBuildWizardArgs_ObservabilityPresetIsPositional(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardObservability,
		wizFormFields: observabilityWizardFields("datadog"),
	}
	// Simulate the user filling out the "API Key" field.
	for i := range p.wizFormFields {
		if p.wizFormFields[i].Flag == "--token" {
			p.wizFormFields[i].Value = "dd-key-abc"
		}
	}

	args := p.buildWizardArgs(wizardObservability)

	// First 3 elements must be "setup observability add" — preset id
	// goes immediately after, before --non-interactive.
	want := []string{"setup", "observability", "add", "datadog", "--non-interactive"}
	for i, w := range want {
		if i >= len(args) || args[i] != w {
			t.Fatalf("args[%d]=%v want prefix %v", i, args[:min(len(args), len(want))], want)
		}
	}

	// --token must show up as a flag with its value.
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--token dd-key-abc") {
		t.Errorf("args missing --token: %v", args)
	}
}

// TestBuildWizardArgs_ObservabilityAlwaysPassesDefaults guards the
// rule that observability inputs feed the writer's `inputs` dict
// verbatim, so values matching the form default must still reach the
// CLI. Without this rule, a user who keeps `realm=us1` would build a
// CLI invocation missing --realm and the writer would raise a
// KeyError when rendering the `ingest.{realm}.observability...`
// template — failing only after the form was already submitted.
func TestBuildWizardArgs_ObservabilityAlwaysPassesDefaults(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardObservability,
		wizFormFields: observabilityWizardFields("splunk-o11y"),
	}
	// User accepts every default and submits without typing anything.
	args := p.buildWizardArgs(wizardObservability)
	joined := strings.Join(args, " ")

	mustContain := []string{
		"--realm us1",              // required template input
		"--signals traces,metrics", // optional but writer reads it
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("default-only submit missing %q\n  args: %v", want, args)
		}
	}
}

// TestBuildWizardArgs_NonObservabilityStillSkipsDefaults guards
// against accidentally making other wizards more verbose. The
// always-pass rule is scoped to wizardObservability — the splunk
// alias and others continue to skip values that match defaults.
func TestBuildWizardArgs_NonObservabilityStillSkipsDefaults(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx: wizardSplunk,
		wizFormFields: []wizardFormField{
			{Label: "App Name", Flag: "--app-name", Kind: "string", Default: "defenseclaw", Value: "defenseclaw"},
			{Label: "HEC Index", Flag: "--index", Kind: "string", Default: "x", Value: "y"},
		},
	}
	args := p.buildWizardArgs(wizardSplunk)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--app-name") {
		t.Errorf("splunk wizard should skip --app-name when value matches default; args=%v", args)
	}
	if !strings.Contains(joined, "--index y") {
		t.Errorf("splunk wizard should pass --index when value differs from default; args=%v", args)
	}
}

// TestSubmitWizardForm_BlocksOnMissingRequired asserts the form
// refuses to submit when a Required field is empty and surfaces the
// missing label in wizFormError. The non-interactive CLI cannot
// prompt the user, so this is the only chance to catch the gap.
func TestSubmitWizardForm_BlocksOnMissingRequired(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardObservability,
		wizFormActive: true,
		wizFormFields: observabilityWizardFields("webhook"),
	}
	// URL is the only Required field on the webhook preset and we
	// leave it empty.
	run, _, _, _ := p.submitWizardForm()
	if run {
		t.Fatal("submitWizardForm returned run=true with empty Required URL")
	}
	if p.wizFormError == "" {
		t.Fatal("wizFormError empty after blocked submit")
	}
	if !strings.Contains(p.wizFormError, "URL") {
		t.Errorf("wizFormError=%q does not name the missing field", p.wizFormError)
	}
	// Form must remain active so the user can fix the input
	// without losing the rest of their work.
	if !p.wizFormActive {
		t.Error("wizFormActive=false after blocked submit; user lost their form state")
	}
	if p.wizRunning {
		t.Error("wizRunning=true after blocked submit; should not have shelled out")
	}
}

// TestSubmitWizardForm_ProceedsWhenRequiredFilled asserts that filling
// the Required field unblocks submit and produces a CLI invocation
// with the value present.
func TestSubmitWizardForm_ProceedsWhenRequiredFilled(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardObservability,
		wizFormActive: true,
		wizFormFields: observabilityWizardFields("webhook"),
	}
	for i := range p.wizFormFields {
		if p.wizFormFields[i].Flag == "--url" {
			p.wizFormFields[i].Value = "https://example.com/hook"
		}
	}
	run, bin, args, _ := p.submitWizardForm()
	if !run {
		t.Fatalf("submitWizardForm returned run=false; wizFormError=%q", p.wizFormError)
	}
	if bin != "defenseclaw" {
		t.Errorf("bin=%q want defenseclaw", bin)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--url https://example.com/hook") {
		t.Errorf("args missing --url: %v", args)
	}
	if !strings.Contains(joined, "--non-interactive") {
		t.Errorf("args missing --non-interactive: %v", args)
	}
}

// TestObservabilityPresets_MatchPythonRegistry guards against the Go
// TUI and the Python preset registry drifting. The TUI shells out to
// the Python CLI for writes, so any preset id the TUI exposes that
// the CLI rejects would surface as "invalid choice" errors at the
// worst possible moment — after the operator has filled the form.
//
// We compare against a hard-coded snapshot of preset_choices() output;
// the Python test `test_tui_preset_list_matches_python` enforces the
// reverse direction.
func TestObservabilityPresets_MatchPythonRegistry(t *testing.T) {
	expected := map[string]bool{
		"splunk-o11y":   true,
		"splunk-hec":    true,
		"datadog":       true,
		"honeycomb":     true,
		"newrelic":      true,
		"grafana-cloud": true,
		"otlp":          true,
		"webhook":       true,
	}
	got := make(map[string]bool, len(observabilityPresets))
	for _, p := range observabilityPresets {
		got[p[0]] = true
	}
	for id := range expected {
		if !got[id] {
			t.Errorf("observabilityPresets missing %q (drift from presets.py)", id)
		}
	}
	for id := range got {
		if !expected[id] {
			t.Errorf("observabilityPresets has unexpected %q (drift from presets.py)", id)
		}
	}
}

func labelList(fields []wizardFormField) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Label
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
