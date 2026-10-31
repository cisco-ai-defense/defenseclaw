// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"strings"
	"testing"
)

// rel-1-0-6 GAP-0174: with the audit disk full, the managed gateway answered
// HTTP 503 "hook audit is unavailable" and the hook told the user that the
// gateway "returned an answer DefenseClaw could not use". The block now says
// that DefenseClaw could not write the call's audit record and where to look.
func TestManagedBlockSaysTheAuditRecordCouldNotBeWritten(t *testing.T) {
	text := managedStandaloneFailClosedText("PreToolUse", "response", managedAuditUnavailableReason)
	for _, want := range []string{"could not write the call's audit record", "disk", "status"} {
		if !strings.Contains(text, want) {
			t.Fatalf("block text %q does not say %q", text, want)
		}
	}
	if strings.Contains(text, "could not use") {
		t.Fatalf("block text still says the answer could not be used: %q", text)
	}
	if !gatewayAuditUnavailable(http.StatusServiceUnavailable, []byte(`{"error":"hook audit is unavailable"}`)) {
		t.Fatal("the gateway's audit-unavailable 503 is not recognised")
	}
	for _, other := range []struct {
		status int
		body   string
	}{{http.StatusServiceUnavailable, `{"error":"other"}`}, {http.StatusInternalServerError, `{"error":"hook audit is unavailable"}`}, {http.StatusServiceUnavailable, `not json`}} {
		if gatewayAuditUnavailable(other.status, []byte(other.body)) {
			t.Fatalf("%d %s read as the audit-unavailable answer", other.status, other.body)
		}
	}
}
