// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// A routing.admin denial and a routing.sensitive refusal are audited with
// their own routing.* actions, never the guardrail block action
// inspect-request-block, so block counts and dashboards that key on a
// "block" action do not count routing decisions as guardrail blocks
// (GAP-1126). The row keeps its target and its code and path details.
func TestRouteDenialsHaveTheirOwnRoutingAuditActions(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	auditRouteDeny(t.Context(), logger, "/v1/messages", &engine.DenyReason{Code: "routing_admin_denied", Message: "rule r1"})
	auditRouteDeny(t.Context(), logger, "/r/claudecode/v1/messages", &engine.DenyReason{Code: engine.DenyCodeSensitiveLocal, Message: "sensitive"})
	auditRouteDeny(t.Context(), logger, "/v1/responses", nil)

	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, event := range events {
		if strings.HasPrefix(event.Target, "routing.") {
			got[event.Target] = append(got[event.Target], event.Action)
			if !strings.Contains(event.Details, "routing refused the model request: ") || !strings.Contains(event.Details, " path=") {
				t.Fatalf("route deny details = %q", event.Details)
			}
		}
		if event.Action == "inspect-request-block" {
			t.Fatalf("a routing refusal was audited as the guardrail block action: %+v", event)
		}
	}
	if admin := got["routing.admin"]; len(admin) != 2 || admin[0] != "routing.admin_denied" || admin[1] != "routing.admin_denied" {
		t.Fatalf("routing.admin rows = %v, want two routing.admin_denied", admin)
	}
	if sensitive := got["routing.sensitive"]; len(sensitive) != 1 || sensitive[0] != "routing.sensitive_refused" {
		t.Fatalf("routing.sensitive rows = %v, want one routing.sensitive_refused", sensitive)
	}
	for _, action := range []string{"routing.admin_denied", "routing.sensitive_refused"} {
		// The webhook dispatcher and the TUI block filters key on "block".
		if strings.Contains(action, "block") {
			t.Fatalf("%s would count as a block", action)
		}
	}
}
