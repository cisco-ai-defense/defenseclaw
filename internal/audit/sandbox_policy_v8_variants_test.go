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

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// Every outcome branch of the managed families: the outcome, the mandatory
// flag and the audit action key the stored event carries. A failed policy
// resolution refuses the registration, so it is mandatory like the other
// enforced outcomes; an alert-only report is not.
func TestSandboxManagedOutcomeVariants(t *testing.T) {
	identity, subject := testManagedIdentity(), testManagedSubject()
	foreign := SandboxIdentity{Name: "raw-openshell-box", Connector: "claudecode", Managed: identity.Managed}
	cases := []struct {
		name      string
		event     any
		outcome   observability.Outcome
		mandatory bool
		action    Action
	}{
		{"resolved", SandboxPolicyResolvedEvent{Sandbox: identity, Subject: subject},
			observability.OutcomeCompleted, false, ActionSandboxPolicy},
		{"resolved failed", SandboxPolicyResolvedEvent{Sandbox: identity, Subject: subject, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxPolicy},
		{"rematched", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchGeneration},
			observability.OutcomeApplied, true, ActionSandboxPolicyRematched},
		{"rematched failed", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchFacts, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxPolicyRematched},
		{"foreign rule removed", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedRemove},
			observability.OutcomeApplied, true, ActionSandboxPolicyForeignRule},
		{"foreign rule stop", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedStop},
			observability.OutcomeApplied, true, ActionSandboxPolicyForeignRule},
		{"foreign rule stop failed", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedStop, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxPolicyForeignRule},
		{"foreign rule remove failed", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedRemove, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxPolicyForeignRule},
		{"foreign rule alert", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedAlert},
			observability.OutcomeSkipped, false, ActionSandboxPolicyForeignRule},
		{"foreign rule alert failed", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedAlert, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxPolicyForeignRule},
		{"foreign sandbox stop", SandboxForeignSandboxEvent{Sandbox: foreign, Subject: subject, Action: SandboxManagedStop},
			observability.OutcomeApplied, true, ActionSandboxManaged},
		{"foreign sandbox alert", SandboxForeignSandboxEvent{Sandbox: foreign, Subject: subject, Action: SandboxManagedAlert},
			observability.OutcomeSkipped, false, ActionSandboxManaged},
		{"foreign sandbox stop failed", SandboxForeignSandboxEvent{Sandbox: foreign, Subject: subject, Action: SandboxManagedStop, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxManaged},
		{"foreign sandbox alert failed", SandboxForeignSandboxEvent{Sandbox: foreign, Subject: subject, Action: SandboxManagedAlert, Failed: true},
			observability.OutcomeFailed, true, ActionSandboxManaged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			harness := newSandboxHarness(t)
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
				t.Fatal(err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if record.Outcome() != tc.outcome || record.Mandatory() != tc.mandatory {
				t.Fatalf("outcome %q mandatory %v, want %q %v", record.Outcome(), record.Mandatory(), tc.outcome, tc.mandatory)
			}
			rows, err := harness.logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 || rows[0].Action != string(tc.action) {
				t.Fatalf("event history rows=%d err=%v want one %s row: %#v", len(rows), err, tc.action, rows)
			}
		})
	}
}

// The mandatory floor follows the same flag: a failed resolution reaches it,
// a successful one is refused there.
func TestSandboxManagedFailedResolutionReachesFloor(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, router.AdmissionFloor)
	if err := recorder.RecordSandboxPolicyResolved(context.Background(), SandboxPolicyResolvedEvent{
		Sandbox: testManagedIdentity(), Subject: testManagedSubject(), Failed: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, record := onlySandboxRecord(t, runtime); !record.IsFloorOnly() || !record.Mandatory() {
		t.Fatalf("failed resolution floor=%v mandatory=%v", record.IsFloorOnly(), record.Mandatory())
	}
	if err := recorder.RecordSandboxPolicyResolved(context.Background(), SandboxPolicyResolvedEvent{
		Sandbox: testManagedIdentity(), Subject: testManagedSubject(),
	}); err == nil {
		t.Fatal("a successful resolution was admitted to the mandatory floor")
	}
}

// A malformed descriptive stamp never costs the existing families their
// records: the mandatory egress-denied, approval-resolved and policy-update
// records are emitted, without the stamps that did not fit.
func TestSandboxMalformedDescriptiveStampKeepsMandatoryRecords(t *testing.T) {
	harness := newSandboxHarness(t)
	for name, mutate := range map[string]func(*SandboxManaged){
		"v prefix version": func(m *SandboxManaged) { m.OpenShellVersion = "v0.1.3" },
		"underscore tag":   func(m *SandboxManaged) { m.OpenShellVersion = "0.1.3_rc" },
		"install mode":     func(m *SandboxManaged) { m.InstallMode = "bundled" },
		"profile match":    func(m *SandboxManaged) { m.ProfileMatch = "everyone" },
		"matched group":    func(m *SandboxManaged) { m.MatchedGroup = "bad\ngroup" },
	} {
		identity := testManagedIdentity()
		mutate(&identity.Managed)
		for label, event := range map[string]any{
			"egress denied": SandboxEgressEvent{Sandbox: identity, Source: SandboxEgressSourceProxy, Host: "example.com", Blocked: true},
			"approval resolved": SandboxApprovalEvent{
				Sandbox: identity, Stage: SandboxApprovalResolved, ApprovalID: "ask-1", Kind: SandboxApprovalHostPort,
				Result: SandboxApprovalDenied, Host: "x.example.com",
			},
			"policy update": SandboxPolicyEvent{Sandbox: identity, Operation: SandboxPolicyApply, Actor: "cli:alice", Origin: "cli", ChangeCount: 1},
		} {
			_, record := harness.recordOne(t, router.AdmissionOrdinary, event)
			if !record.Mandatory() {
				t.Fatalf("%s/%s: record is not mandatory", name, label)
			}
			body := sandboxBody(t, record)
			assertSandboxFields(t, body, map[string]any{
				"defenseclaw.sandbox.registration.id": identity.Managed.RegistrationID,
				"defenseclaw.guardrail.profile.name":  "contractors",
				"defenseclaw.subject.key":             identity.Managed.SubjectKey,
			})
			for _, key := range map[string][]string{
				"v prefix version": {"defenseclaw.openshell.version"}, "underscore tag": {"defenseclaw.openshell.version"},
				"install mode": {"defenseclaw.openshell.install_mode"}, "profile match": {"defenseclaw.guardrail.profile.match"},
				"matched group": {"defenseclaw.guardrail.profile.matched_group"},
			}[name] {
				if _, present := body[key]; present {
					t.Fatalf("%s/%s: malformed stamp was recorded as %s", name, label, key)
				}
			}
		}
	}
	// A stamp that identifies the registration still fails: it is not a
	// descriptive one.
	identity := testManagedIdentity()
	identity.Managed.SubjectKey = "alice"
	_, recorder := harness.bind(t, router.AdmissionOrdinary)
	if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
		Sandbox: identity, Source: SandboxEgressSourceProxy, Host: "example.com", Blocked: true,
	}); err == nil {
		t.Fatal("a malformed subject key was accepted")
	}
}
