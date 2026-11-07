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

//go:build linux || darwin

package gateway

import (
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0715: findings raised by a managed sandbox's manager must reach the
// verified account's durable audit and alert queue. Other sandbox records
// still use the same relay, and neither a peer nor a payload may change the
// registration's sandbox or person.
func TestGAP0715ManagedFindingsReachAuditAndAlerts(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	tel := newDaemonRelayTelemetry(fixtureEventsRelay{f: f, peer: sbxAlice},
		func(string) (string, bool) { return id, true }, t.Logf)
	tel.flushEvery = time.Hour
	ctx := t.Context()
	box := audit.SandboxIdentity{Name: "dc-claude-1", ID: "sbx-1"}
	now := time.Now().UTC()
	findings := []audit.SandboxFindingEvent{
		{Sandbox: box, Kind: audit.SandboxFindingHookSilence, FindingID: "silence-1", Severity: "HIGH",
			Title: "Hooks are silent", Evidence: "on_silence=alert", Timestamp: now, UserID: "42", UserName: "untrusted"},
		{Sandbox: box, Kind: audit.SandboxFindingHookTamper, FindingID: "tamper-1", Severity: "LOW",
			Title: "Hook integrity changed", Evidence: "on_tamper=stop", Timestamp: now.Add(time.Millisecond)},
		{Sandbox: box, Kind: audit.SandboxFindingShadowAI, FindingID: "shadow-1", Severity: "LOW",
			Title: "Unexpected provider", Timestamp: now.Add(2 * time.Millisecond)},
	}
	for _, finding := range findings {
		if err := tel.RecordSandboxFinding(ctx, finding); err != nil {
			t.Fatal(err)
		}
	}
	if err := tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{Sandbox: audit.SandboxIdentity{Name: box.Name,
		ID: box.ID, Phase: audit.SandboxPhaseReady}, Trigger: audit.SandboxTriggerCreate, Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if tel.flush(ctx) {
		t.Fatal("the managed relay kept a completed batch")
	}
	rows := auditEventsOf(t, store, audit.ActionSandboxFinding)
	if len(rows) != 3 {
		t.Fatalf("%d managed finding rows, want three", len(rows))
	}
	kinds := map[string]bool{}
	for _, row := range rows {
		fields := row.Structured
		if fields["defenseclaw.sandbox.name"] != box.Name || fields["defenseclaw.sandbox.id"] != box.ID ||
			fields["user.id"] != "94404076" || fields["defenseclaw.user.name"] != "ent-alice" {
			t.Fatalf("finding was not stamped from the registration: %+v", row)
		}
		category, _ := fields["defenseclaw.finding.category"].(string)
		if category == "sandbox.hook_silence" && (row.Severity != "HIGH" || fields["defenseclaw.finding.rule_id"] != "SANDBOX-HOOK-SILENCE") ||
			category == "sandbox.hook_tamper" && row.Severity != "HIGH" ||
			category == "sandbox.shadow_ai" && row.Severity != "LOW" {
			t.Fatalf("finding severity or rule ID changed: %+v", row)
		}
		kinds[category] = true
	}
	if !kinds["sandbox.hook_silence"] || !kinds["sandbox.hook_tamper"] || !kinds["sandbox.shadow_ai"] {
		t.Fatalf("managed finding categories = %v", kinds)
	}
	alerts, err := store.ListAlerts(100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range alerts {
		if row.Action == string(audit.ActionSandboxFinding) {
			seen[row.Structured["defenseclaw.finding.category"].(string)] = true
		}
	}
	if !seen["sandbox.hook_silence"] || !seen["sandbox.hook_tamper"] {
		t.Fatalf("managed finding alerts = %v", seen)
	}
	if got := len(auditEventsOf(t, store, audit.ActionSandboxLifecycle)); got != 1 {
		t.Fatalf("ordinary lifecycle rows = %d, want one", got)
	}
	if err := tel.RecordSandboxLifecycle(ctx, audit.SandboxLifecycleEvent{
		Sandbox: audit.SandboxIdentity{Name: box.Name, ID: box.ID, Phase: audit.SandboxPhaseStopped},
		Trigger: audit.SandboxTriggerStop, Condition: &audit.SandboxCondition{
			Type: "SecurityAlarm", Status: "True", Reason: "hook_silence"}, Timestamp: now.Add(3 * time.Millisecond),
	}); err != nil {
		t.Fatal(err)
	}
	tel.flush(ctx)
	lifecycle := auditEventsOf(t, store, audit.ActionSandboxLifecycle)
	if len(lifecycle) != 2 || lifecycle[0].Structured["defenseclaw.sandbox.condition.reason"] != "hook_silence" {
		t.Fatalf("managed stop cause was not recorded: %+v", lifecycle)
	}

	// A finding naming another sandbox is discarded, and another account
	// cannot post a finding under this registration.
	other := findings[0]
	other.Sandbox.Name = "other-box"
	if err := tel.RecordSandboxFinding(ctx, other); err != nil {
		t.Fatal(err)
	}
	tel.flush(ctx)
	if got := len(auditEventsOf(t, store, audit.ActionSandboxFinding)); got != 3 {
		t.Fatalf("foreign sandbox added a finding: %d rows", got)
	}
	payload := []byte(`{"sandbox":"dc-claude-1","kind":"hook_silence","severity":"HIGH"}`)
	response := f.do(sbxBob, http.MethodPost, sandboxrelay.PathEvents,
		sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: id,
			Events: []sandboxrelay.Event{{Kind: "sandbox_finding", Time: now, Payload: payload}}}, nil)
	if response.Code == http.StatusAccepted {
		t.Fatal("another account posted a finding")
	}
}

// A finding queued before the sandbox's deletion can arrive after its
// registration is revoked. It still belongs to the verified sandbox and
// remains visible without turning a tombstone into a new guest sighting.
func TestGAP0715FindingQueuedBeforeRevocationIsRecorded(t *testing.T) {
	f, store := managedTelemetryFixture(t)
	id := boundRegistration(t, f, sbxAlice, 1)
	tel := newDaemonRelayTelemetry(fixtureEventsRelay{f: f, peer: sbxAlice},
		func(string) (string, bool) { return id, true }, t.Logf)
	tel.flushEvery = time.Hour
	if err := tel.RecordSandboxFinding(t.Context(), audit.SandboxFindingEvent{
		Sandbox: audit.SandboxIdentity{Name: "dc-claude-1", ID: "sbx-1"},
		Kind:    audit.SandboxFindingHookSilence, Severity: "HIGH", Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	reportDeleted(t, f, sbxAlice, id)
	tel.flush(t.Context())
	if rows := auditEventsOf(t, store, audit.ActionSandboxFinding); len(rows) != 1 {
		t.Fatalf("%d findings survived registration deletion, want one", len(rows))
	}
}
