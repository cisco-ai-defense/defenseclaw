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

// TestWebhookWizardFields_TypeRebuildsForm asserts that the per-type
// prompts (secret_env, room_id, …) appear / disappear when the user
// cycles the ``whtype`` picker. The CLI's required inputs differ by
// channel, so the TUI must expose the right set to avoid blocking
// submit on an unreachable field.
func TestWebhookWizardFields_TypeRebuildsForm(t *testing.T) {
	cases := []struct {
		channel     string
		mustHave    []string
		mustNotHave []string
	}{
		{
			channel:     "slack",
			mustHave:    []string{"Type", "URL", "Secret env (optional)"},
			mustNotHave: []string{"Room ID", "Routing key env", "Bot token env"},
		},
		{
			channel:     "pagerduty",
			mustHave:    []string{"Type", "URL", "Routing key env"},
			mustNotHave: []string{"Room ID"},
		},
		{
			channel:  "webex",
			mustHave: []string{"Type", "URL", "Bot token env", "Room ID"},
		},
		{
			channel:  "generic",
			mustHave: []string{"Type", "URL", "HMAC secret env (optional)"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.channel, func(t *testing.T) {
			fields := webhookWizardFields(tc.channel)
			if fields[0].Kind != "whtype" {
				t.Fatalf("field 0 kind=%q want whtype", fields[0].Kind)
			}
			if fields[0].Value != tc.channel {
				t.Fatalf("whtype Value=%q want %q", fields[0].Value, tc.channel)
			}

			labels := make(map[string]bool, len(fields))
			for _, f := range fields {
				labels[f.Label] = true
			}
			for _, want := range tc.mustHave {
				if !labels[want] {
					t.Errorf("channel %s: missing field %q (have %v)",
						tc.channel, want, labelList(fields))
				}
			}
			for _, notWant := range tc.mustNotHave {
				if labels[notWant] {
					t.Errorf("channel %s: unexpected field %q present",
						tc.channel, notWant)
				}
			}
		})
	}
}

// TestWebhookWizardFields_URLIsRequired asserts the URL field is
// marked Required so ``missingRequiredFields`` will block submit
// before shelling out to the Python CLI. A notifier webhook without
// a URL is guaranteed to fail at the writer layer; catching it in
// the form is the humane failure mode.
func TestWebhookWizardFields_URLIsRequired(t *testing.T) {
	for _, channel := range []string{"slack", "pagerduty", "webex", "generic"} {
		t.Run(channel, func(t *testing.T) {
			fields := webhookWizardFields(channel)
			var urlField *wizardFormField
			for i := range fields {
				if fields[i].Flag == "--url" {
					urlField = &fields[i]
					break
				}
			}
			if urlField == nil {
				t.Fatalf("channel %s: no --url field", channel)
			}
			if !urlField.Required {
				t.Errorf("channel %s: --url should be Required", channel)
			}
		})
	}
}

// TestBuildWizardArgs_WebhookTypeIsPositional asserts the channel
// type is injected positionally after ``add`` so the CLI signature
// matches ``defenseclaw setup webhook add <type>``. Mirroring
// TestBuildWizardArgs_ObservabilityPresetIsPositional.
func TestBuildWizardArgs_WebhookTypeIsPositional(t *testing.T) {
	cases := []struct {
		channel string
		wantURL string
	}{
		{"slack", "https://hooks.slack.com/services/A/B/C"},
		{"pagerduty", "https://events.pagerduty.com/v2/enqueue"},
		{"webex", "https://webexapis.com/v1/messages"},
		{"generic", "https://ops.example.com/hooks"},
	}

	for _, tc := range cases {
		t.Run(tc.channel, func(t *testing.T) {
			p := &SetupPanel{
				wizRunIdx:     wizardWebhook,
				wizFormFields: webhookWizardFields(tc.channel),
			}
			// Fill the required URL so we can build args; we don't
			// care about the submit path here (see the separate
			// TestSubmitWebhookForm_* tests below).
			for i := range p.wizFormFields {
				if p.wizFormFields[i].Flag == "--url" {
					p.wizFormFields[i].Value = tc.wantURL
				}
				// webex also requires a room id for submit, but
				// buildWizardArgs runs unconditionally.
				if p.wizFormFields[i].Flag == "--room-id" {
					p.wizFormFields[i].Value = "room-abc"
				}
			}

			args := p.buildWizardArgs(wizardWebhook)
			wantPrefix := []string{
				"setup", "webhook", "add", tc.channel, "--non-interactive",
			}
			for i, w := range wantPrefix {
				if i >= len(args) || args[i] != w {
					t.Fatalf("channel %s: args[%d]=%v want prefix %v",
						tc.channel, i, args[:min(len(args), len(wantPrefix))], wantPrefix)
				}
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--url "+tc.wantURL) {
				t.Errorf("channel %s: args missing --url %s\n  args: %v",
					tc.channel, tc.wantURL, args)
			}
		})
	}
}

// TestBuildWizardArgs_WebhookAlwaysPassesDefaults mirrors the
// observability always-pass rule. The Python writer needs defaults
// materialized on the command line (min-severity=HIGH, events=…,
// timeout=10) so the round-tripped YAML doesn't depend on Click
// default values that might drift between releases.
func TestBuildWizardArgs_WebhookAlwaysPassesDefaults(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardWebhook,
		wizFormFields: webhookWizardFields("slack"),
	}
	for i := range p.wizFormFields {
		if p.wizFormFields[i].Flag == "--url" {
			p.wizFormFields[i].Value = "https://hooks.slack.com/services/A/B/C"
		}
	}

	args := p.buildWizardArgs(wizardWebhook)
	joined := strings.Join(args, " ")

	mustContain := []string{
		"--min-severity HIGH",
		"--events block,scan,guardrail,drift,health",
		"--timeout-seconds 10",
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("webhook default-only submit missing %q\n  args: %v",
				want, args)
		}
	}
}

// TestSubmitWebhookForm_BlocksOnMissingURL asserts the required-field
// validator blocks submit when URL is empty — for every channel type.
func TestSubmitWebhookForm_BlocksOnMissingURL(t *testing.T) {
	for _, channel := range []string{"slack", "pagerduty", "webex", "generic"} {
		t.Run(channel, func(t *testing.T) {
			p := &SetupPanel{
				wizRunIdx:     wizardWebhook,
				wizFormActive: true,
				wizFormFields: webhookWizardFields(channel),
			}
			run, _, _, _ := p.submitWizardForm()
			if run {
				t.Fatalf("channel %s: submitWizardForm returned run=true with empty URL", channel)
			}
			if !strings.Contains(p.wizFormError, "URL") {
				t.Errorf("channel %s: wizFormError=%q does not name URL",
					channel, p.wizFormError)
			}
			if !p.wizFormActive {
				t.Errorf("channel %s: wizFormActive=false after blocked submit",
					channel)
			}
		})
	}
}

// TestSubmitWebhookForm_WebexRequiresRoomID asserts that webex is the
// only channel with a *second* required field (Room ID). Leaving it
// empty must block submit even when URL + secret_env are set.
func TestSubmitWebhookForm_WebexRequiresRoomID(t *testing.T) {
	p := &SetupPanel{
		wizRunIdx:     wizardWebhook,
		wizFormActive: true,
		wizFormFields: webhookWizardFields("webex"),
	}
	for i := range p.wizFormFields {
		if p.wizFormFields[i].Flag == "--url" {
			p.wizFormFields[i].Value = "https://webexapis.com/v1/messages"
		}
		// Bot token env has a Value default wired by webhookWizardFields,
		// so it's pre-satisfied.
	}

	run, _, _, _ := p.submitWizardForm()
	if run {
		t.Fatalf("webex submit without Room ID returned run=true")
	}
	if !strings.Contains(p.wizFormError, "Room ID") {
		t.Errorf("webex: wizFormError=%q does not mention Room ID",
			p.wizFormError)
	}
}

// TestWebhookWizardCommands_MatchCLISurface guards against the
// wizardCommands slice drifting from the actual CLI group. If the
// Python CLI ever moves ``setup webhook add`` the TUI must move too
// or every submit will fail with "unknown command" after the user
// has filled the form.
func TestWebhookWizardCommands_MatchCLISurface(t *testing.T) {
	want := []string{"setup", "webhook", "add"}
	got := wizardCommands[wizardWebhook]
	if len(got) != len(want) {
		t.Fatalf("wizardCommands[wizardWebhook]=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wizardCommands[wizardWebhook][%d]=%q want %q",
				i, got[i], want[i])
		}
	}
}
