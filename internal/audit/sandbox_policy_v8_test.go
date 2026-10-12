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
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func testManagedIdentity() SandboxIdentity {
	provisional := false
	identity := testSandboxIdentity()
	identity.Managed = SandboxManaged{
		RegistrationID:   "reg-q7x2mfd3k5b4oznwj6lhc2ypea",
		GuardrailProfile: "contractors", ProfileDigest: "sha256:" + strings.Repeat("cd", 32),
		ProfileMatch: SandboxProfileMatchGroup, MatchedGroup: `CORP\Contractors`,
		PolicyDigest: "sha256:" + strings.Repeat("ef", 32), PolicyGeneration: 4, Provisional: &provisional,
		SubjectKey:       "hmac-sha256:" + strings.Repeat("a1", 32),
		OpenShellVersion: "0.1.3", InstallMode: SandboxInstallPrerequisite,
	}
	return identity
}

func testManagedSubject() SandboxManagedSubject {
	return SandboxManagedSubject{UserID: "1001", UserName: "alice", UserPrincipal: "alice@CORP.EXAMPLE.COM"}
}

func recordManagedEvent(ctx context.Context, recorder *SandboxRecorder, event any) error {
	switch event := event.(type) {
	case SandboxPolicyResolvedEvent:
		return recorder.RecordSandboxPolicyResolved(ctx, event)
	case SandboxPolicyRematchedEvent:
		return recorder.RecordSandboxPolicyRematched(ctx, event)
	case SandboxPolicyForeignRuleEvent:
		return recorder.RecordSandboxPolicyForeignRule(ctx, event)
	case SandboxAskDecidedEvent:
		return recorder.RecordSandboxAskDecided(ctx, event)
	case SandboxHostRunRefusedEvent:
		return recorder.RecordSandboxHostRunRefused(ctx, event)
	case SandboxHostRunUnavailableEvent:
		return recorder.RecordSandboxHostRunUnavailable(ctx, event)
	case SandboxAccessRefusedEvent:
		return recorder.RecordSandboxAccessRefused(ctx, event)
	case SandboxForeignSandboxEvent:
		return recorder.RecordSandboxForeignSandbox(ctx, event)
	case SandboxForeignContainerEvent:
		return recorder.RecordSandboxForeignContainer(ctx, event)
	case SandboxSettingsDriftEvent:
		return recorder.RecordSandboxSettingsDrift(ctx, event)
	}
	panic(fmt.Sprintf("recordManagedEvent: unsupported event %T", event))
}

// Every managed family: identity, bucket, mandatory floor and its own fields.
func TestSandboxManagedFamilies(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	stored := true
	cases := []struct {
		name      string
		event     any
		eventName string
		bucket    observability.Bucket
		mandatory bool
		want      map[string]any
	}{
		{"resolved", SandboxPolicyResolvedEvent{Sandbox: identity, Subject: subject, Reason: "offline_floor"},
			observability.TelemetryEventSandboxPolicyResolved, observability.BucketComplianceActivity, false,
			map[string]any{"defenseclaw.sandbox.managed.reason": "offline_floor"}},
		{"rematched", SandboxPolicyRematchedEvent{
			Sandbox: identity, Subject: subject, Reason: SandboxRematchLookupResolved,
			PreviousProfile: "default-floor", PreviousDigest: "sha256:" + strings.Repeat("01", 32),
		}, observability.TelemetryEventSandboxPolicyRematched, observability.BucketComplianceActivity, true,
			map[string]any{
				"defenseclaw.sandbox.policy.rematch.reason":   "lookup_resolved",
				"defenseclaw.sandbox.policy.previous_profile": "default-floor",
				"defenseclaw.sandbox.policy.previous_digest":  "sha256:" + strings.Repeat("01", 32),
			}},
		{"foreign rule", SandboxPolicyForeignRuleEvent{
			Sandbox: identity, Subject: subject, Action: SandboxManagedRemove, Host: "evil.example.com", Port: 443, Rule: "user-added",
		}, observability.TelemetryEventSandboxPolicyForeignRule, observability.BucketEnforcementAction, true,
			map[string]any{
				"defenseclaw.sandbox.managed.action": "remove", "defenseclaw.sandbox.policy.rule": "user-added",
				"server.address": "evil.example.com", "server.port": int64(443),
			}},
		{"foreign rule alert only", SandboxPolicyForeignRuleEvent{
			Sandbox: identity, Subject: subject, Action: SandboxManagedAlert, Host: "evil.example.com",
		}, observability.TelemetryEventSandboxPolicyForeignRule, observability.BucketEnforcementAction, false,
			map[string]any{"defenseclaw.sandbox.managed.action": "alert", "server.port": nil}},
		{"ask decided", SandboxAskDecidedEvent{
			Sandbox: identity, Subject: subject, ApprovalID: "ask-42", Kind: SandboxApprovalHostPort,
			Result: SandboxApprovalApproved, Scope: SandboxApprovalScopeAlways, Host: "api.example.com", Port: 443, Stored: &stored,
		}, observability.TelemetryEventSandboxAskDecided, observability.BucketComplianceActivity, true,
			map[string]any{
				"defenseclaw.approval.id": "ask-42", "defenseclaw.approval.result": "approved",
				"defenseclaw.sandbox.approval.kind": "host_port", "defenseclaw.sandbox.approval.scope": "always",
				"defenseclaw.sandbox.decision.stored": true, "server.address": "api.example.com",
			}},
		{"host run refused", SandboxHostRunRefusedEvent{
			Sandbox: SandboxIdentity{Connector: "claudecode", Managed: identity.Managed}, Subject: subject,
			Reason: "required_group", Rule: "contractors",
		}, observability.TelemetryEventSandboxHostRunRefused, observability.BucketEnforcementAction, true,
			map[string]any{"defenseclaw.sandbox.managed.reason": "required_group", "defenseclaw.sandbox.policy.rule": "contractors"}},
		{"host run unavailable refused", SandboxHostRunUnavailableEvent{
			Sandbox: SandboxIdentity{Connector: "codex", Managed: identity.Managed}, Subject: subject, Reason: "os_unsupported",
		}, observability.TelemetryEventSandboxHostRunUnavailable, observability.BucketEnforcementAction, true,
			map[string]any{"defenseclaw.sandbox.managed.reason": "os_unsupported", "defenseclaw.sandbox.managed.action": "refuse"}},
		{"host run unavailable allowed", SandboxHostRunUnavailableEvent{
			Sandbox: SandboxIdentity{Connector: "codex", Managed: identity.Managed}, Subject: subject, Reason: "no_kvm", Allowed: true,
		}, observability.TelemetryEventSandboxHostRunUnavailable, observability.BucketEnforcementAction, false,
			map[string]any{"defenseclaw.sandbox.managed.reason": "no_kvm", "defenseclaw.sandbox.managed.action": "allow"}},
		{"access refused", SandboxAccessRefusedEvent{
			Sandbox: identity, Subject: subject, Host: "blocked.example.com", Port: 443, Rule: "org-deny", Reason: "floor_denied",
		}, observability.TelemetryEventSandboxAccessRefused, observability.BucketEnforcementAction, true,
			map[string]any{
				"server.address": "blocked.example.com", "defenseclaw.sandbox.policy.rule": "org-deny",
				"defenseclaw.sandbox.managed.reason": "floor_denied",
			}},
		{"foreign sandbox", SandboxForeignSandboxEvent{
			Sandbox: SandboxIdentity{Name: "raw-openshell-box", Connector: "claudecode", Managed: identity.Managed},
			Subject: subject, Action: SandboxManagedStop,
		}, observability.TelemetryEventSandboxForeignSandbox, observability.BucketEnforcementAction, true,
			map[string]any{"defenseclaw.sandbox.name": "raw-openshell-box", "defenseclaw.sandbox.managed.action": "stop"}},
		// The alert names the image the container runs (GAP-0677).
		{"foreign container", SandboxForeignContainerEvent{
			Sandbox: SandboxIdentity{Name: "claude-dev", Managed: identity.Managed}, Subject: subject,
			Image: "registry.example.com:5000/team/plain-nolabel:lab",
		}, observability.TelemetryEventSandboxForeignContainer, observability.BucketComplianceActivity, false,
			map[string]any{
				"defenseclaw.sandbox.name": "claude-dev", "defenseclaw.sandbox.managed.action": "alert",
				"defenseclaw.sandbox.container.image": "registry.example.com:5000/team/plain-nolabel:lab",
			}},
		{"settings drift", SandboxSettingsDriftEvent{
			Sandbox: SandboxIdentity{Managed: identity.Managed}, Subject: subject, Field: "compute_driver",
		}, observability.TelemetryEventSandboxSettingsDrift, observability.BucketEnforcementAction, true,
			map[string]any{"defenseclaw.openshell.settings.field": "compute_driver", "defenseclaw.sandbox.managed.action": "refuse"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
				t.Fatal(err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if record.EventName() != observability.EventName(tc.eventName) || record.Bucket() != tc.bucket ||
				record.Mandatory() != tc.mandatory {
				t.Fatalf("record %s bucket %s mandatory %v", record.EventName(), record.Bucket(), record.Mandatory())
			}
			body := sandboxBody(t, record)
			assertSandboxFields(t, body, map[string]any{
				"defenseclaw.sandbox.registration.id":    "reg-q7x2mfd3k5b4oznwj6lhc2ypea",
				"defenseclaw.guardrail.profile.name":     "contractors",
				"defenseclaw.guardrail.profile.match":    "group",
				"defenseclaw.sandbox.policy.digest":      identity.Managed.PolicyDigest,
				"defenseclaw.sandbox.policy.generation":  int64(4),
				"defenseclaw.sandbox.policy.provisional": false,
				"defenseclaw.subject.key":                identity.Managed.SubjectKey,
				"defenseclaw.openshell.version":          "0.1.3",
				"defenseclaw.openshell.install_mode":     "prerequisite",
				"user.id":                                "1001",
				"defenseclaw.user.name":                  "alice",
				"defenseclaw.user.principal":             "alice@CORP.EXAMPLE.COM",
			})
			assertSandboxFields(t, body, tc.want)
		})
	}
}

// A sandbox no managed gateway governs keeps its records as they were: none
// of the managed stamps appears, and a stamped lifecycle record carries them.
func TestSandboxManagedStampsOnExistingFamilies(t *testing.T) {
	harness := newSandboxHarness(t)
	stampKeys := []string{
		"defenseclaw.sandbox.registration.id", "defenseclaw.sandbox.policy.digest", "defenseclaw.sandbox.policy.provisional",
		"defenseclaw.guardrail.profile.name", "defenseclaw.subject.key", "defenseclaw.openshell.version",
	}
	_, plain := harness.recordOne(t, router.AdmissionOrdinary, SandboxLifecycleEvent{
		Sandbox: testSandboxIdentity(), Trigger: SandboxTriggerCreate,
	})
	for _, key := range stampKeys {
		if _, present := sandboxBody(t, plain)[key]; present {
			t.Fatalf("unmanaged lifecycle record carries %s", key)
		}
	}
	managed := testManagedIdentity()
	for name, event := range map[string]any{
		"lifecycle": SandboxLifecycleEvent{Sandbox: managed, Trigger: SandboxTriggerCreate},
		"approval": SandboxApprovalEvent{
			Sandbox: managed, Stage: SandboxApprovalResolved, ApprovalID: "ask-1", Kind: SandboxApprovalHostPort,
			Result: SandboxApprovalDenied, Host: "x.example.com",
		},
		"process tree": SandboxProcessEvent{Sandbox: managed, Event: SandboxProcessStart, PID: 7},
	} {
		_, record := harness.recordOne(t, router.AdmissionOrdinary, event)
		body := sandboxBody(t, record)
		assertSandboxFields(t, body, map[string]any{
			"defenseclaw.sandbox.registration.id": managed.Managed.RegistrationID,
			"defenseclaw.guardrail.profile.name":  "contractors",
			"defenseclaw.subject.key":             managed.Managed.SubjectKey,
		})
		if t.Failed() {
			t.Fatalf("%s record lacks the managed stamps", name)
		}
	}
}

// A mandatory managed record reaches the floor when a route's collection
// settings would drop it; an alert-only one does not.
func TestSandboxManagedMandatoryFloor(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, router.AdmissionFloor)
	if err := recorder.RecordSandboxHostRunRefused(context.Background(), SandboxHostRunRefusedEvent{
		Sandbox: SandboxIdentity{Connector: "claudecode"}, Subject: testManagedSubject(), Reason: "required_group",
	}); err != nil {
		t.Fatal(err)
	}
	if _, record := onlySandboxRecord(t, runtime); !record.IsFloorOnly() || !record.Mandatory() {
		t.Fatalf("refusal floor=%v mandatory=%v", record.IsFloorOnly(), record.Mandatory())
	}
	if err := recorder.RecordSandboxForeignContainer(context.Background(), SandboxForeignContainerEvent{
		Sandbox: SandboxIdentity{Name: "claude-dev"}, Subject: testManagedSubject(),
	}); err == nil {
		t.Fatal("an alert-only record was admitted to the mandatory floor")
	}
}

// DefenseClaw-owned values that do not fit the registry fail before anything
// is emitted; names the user or the operator chose never cost the record.
func TestSandboxManagedRejectsUnregisteredValues(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	withStamp := func(edit func(*SandboxManaged)) SandboxIdentity {
		stamped := identity
		edit(&stamped.Managed)
		return stamped
	}
	for name, bad := range map[string]any{
		"unknown rematch reason": SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: "guess"},
		"bad previous digest": SandboxPolicyRematchedEvent{
			Sandbox: identity, Subject: subject, Reason: SandboxRematchFacts, PreviousDigest: "sha256:zz",
		},
		"foreign rule action":   SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: "ignore"},
		"foreign rule no name":  SandboxPolicyForeignRuleEvent{Sandbox: SandboxIdentity{}, Subject: subject, Action: SandboxManagedRemove},
		"ask result":            SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, Result: "maybe"},
		"scope on a denial":     SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, Result: SandboxApprovalDenied, Scope: SandboxApprovalScopeAlways},
		"refusal needs reason":  SandboxHostRunRefusedEvent{Sandbox: identity, Subject: subject},
		"free-text reason":      SandboxHostRunUnavailableEvent{Sandbox: identity, Subject: subject, Reason: "No KVM here"},
		"foreign action":        SandboxForeignSandboxEvent{Sandbox: identity, Subject: subject, Action: "remove"},
		"drift field is a path": SandboxSettingsDriftEvent{Sandbox: identity, Subject: subject, Field: "/etc/openshell/gateway.toml"},
		"bad subject key":       SandboxPolicyResolvedEvent{Sandbox: withStamp(func(m *SandboxManaged) { m.SubjectKey = "alice" }), Subject: subject},
		"bad install mode":      SandboxPolicyResolvedEvent{Sandbox: withStamp(func(m *SandboxManaged) { m.InstallMode = "bundled" }), Subject: subject},
		"bad profile match":     SandboxPolicyResolvedEvent{Sandbox: withStamp(func(m *SandboxManaged) { m.ProfileMatch = "everyone" }), Subject: subject},
		"bad version":           SandboxPolicyResolvedEvent{Sandbox: withStamp(func(m *SandboxManaged) { m.OpenShellVersion = "latest" }), Subject: subject},
		"negative generation":   SandboxPolicyResolvedEvent{Sandbox: withStamp(func(m *SandboxManaged) { m.PolicyGeneration = -1 }), Subject: subject},
	} {
		runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
		if err := recordManagedEvent(context.Background(), recorder, bad); err == nil {
			t.Fatalf("%s: %+v accepted", name, bad)
		}
		if metadata, _ := runtime.snapshot(); len(metadata) != 0 {
			t.Fatalf("%s emitted before it was refused", name)
		}
	}

	// Chosen names never fail the record: a foreign sandbox with an odd name
	// is still reported, without the name; an unusable rule or host is omitted.
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxForeignSandboxEvent{
		Sandbox: SandboxIdentity{Name: "has spaces & symbols", Managed: identity.Managed}, Subject: subject,
		Action: SandboxManagedAlert,
	})
	if _, present := sandboxBody(t, record)["defenseclaw.sandbox.name"]; present {
		t.Fatal("an unbounded foreign sandbox name was recorded")
	}
	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxForeignContainerEvent{
		Sandbox: SandboxIdentity{Name: "dev", Managed: identity.Managed}, Subject: subject, Image: "not an image\n",
	})
	if _, present := sandboxBody(t, record)["defenseclaw.sandbox.container.image"]; present {
		t.Fatal("an image value that is not a reference was recorded")
	}
	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxAccessRefusedEvent{
		Sandbox: identity, Subject: subject, Host: strings.Repeat("a", 300), Rule: "has spaces",
	})
	body := sandboxBody(t, record)
	for _, key := range []string{"defenseclaw.sandbox.policy.rule", "server.address"} {
		if _, present := body[key]; present {
			t.Fatalf("unusable %s was recorded", key)
		}
	}
}

// The principal is recorded only when the caller supplies a usable one; the
// keyed subject pseudonym names the person otherwise.
func TestSandboxManagedPrincipalIsOptional(t *testing.T) {
	harness := newSandboxHarness(t)
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxPolicyResolvedEvent{
		Sandbox: testManagedIdentity(), Subject: SandboxManagedSubject{UserID: "1001", UserName: "alice"},
	})
	body := sandboxBody(t, record)
	if _, present := body["defenseclaw.user.principal"]; present {
		t.Fatal("a principal was recorded without one being supplied")
	}
	assertSandboxFields(t, body, map[string]any{
		"user.id": "1001", "defenseclaw.subject.key": testManagedIdentity().Managed.SubjectKey,
	})
	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxPolicyResolvedEvent{
		Sandbox: testManagedIdentity(), Subject: SandboxManagedSubject{UserID: "1001", UserPrincipal: "alice smith"},
	})
	if _, present := sandboxBody(t, record)["defenseclaw.user.principal"]; present {
		t.Fatal("a principal with whitespace was recorded")
	}
}
