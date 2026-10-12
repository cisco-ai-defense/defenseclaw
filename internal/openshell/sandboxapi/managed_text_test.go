// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"strings"
	"testing"
)

func TestExplainRequestSourcesRoundTrips(t *testing.T) {
	req := ExplainRequest{Sandbox: "box", Sources: true}
	if got := ParseExplainQuery(req.Query()); !got.Sources || got.Sandbox != "box" {
		t.Errorf("round trip = %+v", got)
	}
	if ParseExplainQuery(ExplainRequest{}.Query()).Sources {
		t.Error("sources set without being asked")
	}
}

func TestAccessContact(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"it-security@example.com", "Need an exception? Contact it-security@example.com"},
		{"", "Need an exception? Please contact your IT help desk."},
		{"  \x1b[31mhelp\x1b[0m\n", "Need an exception? Contact �[31mhelp�[0m"},
	} {
		if got := AccessContact(tc.in); got != tc.want {
			t.Errorf("AccessContact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := RequestAccessText(strings.Repeat("é", 400))
	if len(long) > MaxRequestAccessBytes || !strings.HasPrefix(long, "é") {
		t.Errorf("request-access text not bounded: %d bytes", len(long))
	}
}

// On a managed computer the off message never names another account, never
// sends the user to setup, and ends with the organization's contact.
func TestOffMessageManaged(t *testing.T) {
	busy := &Status{GatewayElsewhere: "127.0.0.1:17670, the gateway's port, is held by a process of another account",
		Managed: &ManagedStatus{RequestAccess: "it@example.com"}}
	got := busy.OffMessage()
	for _, want := range []string{AccountBusyMessage, "Contact it@example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("busy message %q lacks %q", got, want)
		}
	}
	for _, not := range []string{"setup", "hand", "doctor", "uid", "PID"} {
		if strings.Contains(got, not) {
			t.Errorf("busy message %q must not say %q", got, not)
		}
	}
	unavailable := (&Status{Managed: &ManagedStatus{Unavailable: "OpenShell is not installed"}}).OffMessage()
	if !strings.Contains(unavailable, "aren't available on this computer: OpenShell is not installed.") ||
		!strings.Contains(unavailable, "IT help desk") {
		t.Errorf("unavailable message = %q", unavailable)
	}
	if off := (&Status{Managed: &ManagedStatus{}}).OffMessage(); strings.Contains(off, "defenseclaw sandbox setup") {
		t.Errorf("off message sends a managed user to setup: %q", off)
	}
	// OSS is unchanged.
	if (&Status{}).OffMessage() != DisabledMessage {
		t.Error("the OSS off message changed")
	}
}
