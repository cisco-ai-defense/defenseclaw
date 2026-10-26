// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// The activity counters carry the actor's kind only; the audit record
// keeps the whole actor (GAP-0377): bundle receipt actors and caller
// supplied /activity actors named accounts in the actor label.
func TestActivityMetricActorIsAKindAndTheAuditKeepsTheIdentity(t *testing.T) {
	for _, tc := range []struct{ actor, label string }{
		{"api:alice@example.com", "api"},
		{"os:uid:1001:alice", "os"},
		{"control-plane:acme/admin@example.com", "control-plane"},
		{"cli:alice", "cli"},
		{"alice@corp.example", "other"},
		{"alice", "other"},
		{"", "system"},
	} {
		t.Run(tc.label+"/"+tc.actor, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			if err := logger.LogActivity(ActivityInput{Actor: tc.actor, Action: ActionConfigUpdate, TargetType: "config", TargetID: "config.yaml"}); err != nil {
				t.Fatal(err)
			}
			_, records := runtime.snapshot()
			if len(records) != 1 {
				t.Fatalf("records=%d", len(records))
			}
			// The canonical record carries the actor when it matches the
			// principal pattern (optionalControlPlaneV8Actor); an
			// address-shaped actor is left out there on every OS.
			if tc.actor != "" && !strings.Contains(tc.actor, "@") {
				encoded, err := records[0].Bytes()
				if err != nil || !strings.Contains(string(encoded), tc.actor) {
					t.Fatalf("the audit record lost the actor %q: %s, %v", tc.actor, encoded, err)
				}
			}
			labelled := 0
			for _, metric := range runtime.metricSnapshot() {
				data, err := metric.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "alice") {
					t.Fatalf("metric names the account: %s", data)
				}
				if strings.Contains(string(data), `"defenseclaw.metric.actor":"`+tc.label+`"`) {
					labelled++
				}
			}
			if labelled != 2 {
				t.Fatalf("activity metrics with actor label %q = %d, want 2", tc.label, labelled)
			}
		})
	}
}
