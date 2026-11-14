// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap0651RoutingShapes are the routing shapes of
// TestInspectToolMessageRoutingValuesAreInspected: the message call with text,
// and the same destination as a send tool's arguments.
func gap0651RoutingShapes(value string) []struct{ withText, asSendTool string } {
	return []struct{ withText, asSendTool string }{
		{`{"to":"` + value + `","text":"hello"}`, `{"to":"` + value + `"}`},
		{`{"target":{"id":"` + value + `","text":"hello"}}`, `{"target.id":"` + value + `"}`},
		{`{"channel":"` + value + `","content":"hello"}`, `{"channel":"` + value + `"}`},
		{`{"targets":["+1","` + value + `"],"body":"hello"}`, `{"targets":"+1","targets#2":"` + value + `"}`},
	}
}

// The routing values of a message call that carries text are where the text
// is sent, so a credential in them gets what the destination of any send
// tool gets, in every tier (GAP-0651). Batch 11 broke this: secret-recall
// alerts on a credential a send tool hands on and finds a send tool by its
// name, and the OpenClaw tool is named message, a noun that decides nothing.
func TestGAP0651MessageRoutingIsASendDestinationInEveryTier(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 5 * time.Second
		for _, tc := range gap0651RoutingShapes(messageTestSecret) {
			_, want := postInspectForConnector(t, api, "openclaw", `{"tool":"send_email","args":`+tc.asSendTool+`}`)
			if !containsString(want.Findings, "SEC-ANTHROPIC:Anthropic API key") {
				t.Fatalf("%s %s: the send-tool call has no finding: %v", tier.name, tc.asSendTool, want.Findings)
			}
			if want.Action == "allow" {
				t.Fatalf("%s %s: a credential a send tool hands on is allowed; the comparison would prove nothing", tier.name, tc.asSendTool)
			}
			for _, content := range []string{``, `,"content":"hello"`} {
				_, got := postInspectForConnector(t, api, "openclaw",
					`{"tool":"message","args":`+tc.withText+content+`,"direction":"outbound"}`)
				if !containsString(got.Findings, "SEC-ANTHROPIC:Anthropic API key") {
					t.Errorf("%s %s%s: the routing secret was not found: %v", tier.name, tc.withText, content, got.Findings)
				}
				if got.Action != want.Action || got.RawAction != want.RawAction {
					t.Errorf("%s %s%s: action = %q/%q, want what a send tool's destination gets: %q/%q",
						tier.name, tc.withText, content, got.Action, got.RawAction, want.Action, want.RawAction)
				}
			}
		}
	}
}

// Benign twins a developer's agent really sends: ordinary recipients with
// text, and a call with no text (a reaction, a read of a channel). None of
// them blocks or alerts in any tier, before or after GAP-0651.
func TestGAP0651BenignMessageRoutingStaysClean(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	bodies := []string{
		`{"tool":"message","args":{"to":"+15551230000","channel":"sms","action":"send","text":"build is green"},"content":"build is green","direction":"outbound"}`,
		`{"tool":"message","args":{"target":{"id":"C024BE91L"},"channel":"slack","message":"deploy finished in 4m"},"direction":"outbound"}`,
		`{"tool":"message","args":{"targets":["#eng","@dana"],"body":"PR 1457 is ready for review"},"direction":"outbound"}`,
		`{"tool":"message","args":{"action":"react","channel":"discord","messageId":"1187654321","emoji":"thumbsup"}}`,
		`{"tool":"message","args":{"action":"read","channel":"telegram","to":"@release_notes","limit":20}}`,
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 5 * time.Second
		for _, body := range bodies {
			_, got := postInspectForConnector(t, api, "openclaw", body)
			if got.Action != "allow" || got.RawAction == "block" || got.RawAction == "alert" {
				t.Errorf("%s %s: action = %q raw = %q findings = %v, want a plain allow", tier.name, body, got.Action, got.RawAction, got.Findings)
			}
		}
	}
}

// A labelled passport number in a routing value is outbound personal data,
// as in the arguments of a send tool (outboundPIIFindings): the same send
// decision covers both lanes. The value is the outbound_pii_test fixture.
func TestGAP0651MessageRoutingPIIIsJudgedAsASendTool(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	const passport = "passport no. 561234789 attached"
	for _, tc := range gap0651RoutingShapes(passport)[:1] {
		_, want := postInspect(t, api, `{"tool":"send_email","args":`+tc.asSendTool+`}`)
		if !containsString(want.Findings, "PII-PASSPORT-LABELED:Labelled passport number in a message the tool sends") {
			t.Fatalf("send tool: findings = %v, want the passport finding", want.Findings)
		}
		_, got := postInspect(t, api, `{"tool":"message","args":`+tc.withText+`,"direction":"outbound"}`)
		if !containsString(got.Findings, "PII-PASSPORT-LABELED:Labelled passport number in a message the tool sends") ||
			got.Action != want.Action || got.RawAction != want.RawAction {
			t.Errorf("message routing: action = %q/%q findings = %v, want the send tool's %q/%q with the passport finding",
				got.Action, got.RawAction, got.Findings, want.Action, want.RawAction)
		}
	}
}

// The send decision: a send tool by name, or the routing values the message
// lane marks. The bare noun stays undecided, and a credential store keeps
// what it is handed.
func TestGAP0651SendDecision(t *testing.T) {
	for _, tc := range []struct {
		tool        string
		destination bool
		want        bool
	}{
		{"message", false, false},
		{"message", true, true},
		{"send_email", false, true},
		{"message_history", false, false},
		{"get_email", false, false},
	} {
		request := trustedActionRequest{Input: actionfacts.Input{Tool: tc.tool}, sendDestination: tc.destination}
		if got := trustedActionSendsMessage(request); got != tc.want {
			t.Errorf("trustedActionSendsMessage(%s, destination %t) = %t, want %t", tc.tool, tc.destination, got, tc.want)
		}
	}
	for _, tc := range []struct {
		tool        string
		destination bool
		want        bool
	}{
		{"message", false, false},
		{"message", true, true},
		{"save_password", true, false},
		{"send_email", false, true},
	} {
		if got := trustedActionPersistsCredentialLiteral(actionfacts.Facts{Tool: tc.tool}, tc.destination); got != tc.want {
			t.Errorf("trustedActionPersistsCredentialLiteral(%s, destination %t) = %t, want %t", tc.tool, tc.destination, got, tc.want)
		}
	}
}

// Only the message lane marks a send destination: the public inspect wire
// cannot.
func TestGAP0651SendDestinationIsNotOnTheWire(t *testing.T) {
	var req ToolInspectRequest
	body := `{"tool":"message","args":{"to":"x"},"sendDestination":true,"send_destination":true}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.sendDestination {
		t.Fatal("the wire set sendDestination")
	}
}
