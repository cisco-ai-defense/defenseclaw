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
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

var sandboxManagedInstruments = []string{
	observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
	observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
	observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
	observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
	observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
}

// Each managed sandbox record moves its fleet counter once, with the
// profile, driver and connector and one closed code as the only labels:
// never the person, the sandbox, the registration or the destination.
func TestSandboxManagedRecordsMoveTheirFleetCounter(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	provisional := true
	floor := identity
	floor.Managed.Provisional = &provisional
	base := map[string]any{
		"defenseclaw.guardrail.profile.name": "contractors",
		"defenseclaw.sandbox.driver":         "docker",
		"defenseclaw.connector.source":       "claudecode",
	}
	with := func(extra map[string]any, drop ...string) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		for _, k := range drop {
			delete(out, k)
		}
		return out
	}
	managedOnly := SandboxIdentity{Connector: "claudecode", Driver: SandboxDriverDocker, Managed: identity.Managed}
	cases := []struct {
		name       string
		event      any
		instrument string
		want       map[string]any
	}{
		{"host run refused", SandboxHostRunRefusedEvent{Sandbox: managedOnly, Subject: subject, Reason: "required_for", Rule: "contractors"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "required_for"})},
		{"sandbox unavailable refused", SandboxHostRunUnavailableEvent{Sandbox: managedOnly, Subject: subject, Reason: "no_kvm"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "no_kvm"})},
		{"sandbox unavailable allowed", SandboxHostRunUnavailableEvent{Sandbox: managedOnly, Subject: subject, Reason: "no_kvm", Allowed: true},
			"", nil},
		{"access refused", SandboxAccessRefusedEvent{Sandbox: identity, Subject: subject, Host: "blocked.example.com", Port: 443, Reason: "floor_denied"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals,
			with(map[string]any{"defenseclaw.sandbox.managed.reason": "floor_denied"})},
		{"ask approved", SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-1", Result: SandboxApprovalApproved,
			Scope: SandboxApprovalScopeSandbox, Host: "api.example.com", Port: 443},
			observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
			with(map[string]any{"defenseclaw.approval.result": "approved"})},
		{"ask denied by the floor", SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-2", Result: SandboxApprovalDenied,
			Reason: "floor_denied", Host: "api.example.com", Port: 443},
			observability.TelemetryInstrumentDefenseClawSandboxManagedAsks,
			with(map[string]any{"defenseclaw.approval.result": "denied", "defenseclaw.sandbox.managed.reason": "floor_denied"})},
		{"foreign rule", SandboxPolicyForeignRuleEvent{Sandbox: identity, Subject: subject, Action: SandboxManagedRemove, Host: "evil.example.com", Port: 443, Rule: "user-added"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "rule", "defenseclaw.sandbox.managed.action": "remove"})},
		{"foreign sandbox", SandboxForeignSandboxEvent{Sandbox: SandboxIdentity{Name: "raw-box", Connector: "claudecode", Driver: SandboxDriverDocker, Managed: identity.Managed},
			Subject: subject, Action: SandboxManagedStop},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "sandbox", "defenseclaw.sandbox.managed.action": "stop"})},
		{"foreign container", SandboxForeignContainerEvent{Sandbox: SandboxIdentity{Name: "claude-dev", Managed: identity.Managed}, Subject: subject},
			observability.TelemetryInstrumentDefenseClawSandboxManagedForeignItems,
			with(map[string]any{"defenseclaw.metric.kind": "container", "defenseclaw.sandbox.managed.action": "alert"},
				"defenseclaw.sandbox.driver", "defenseclaw.connector.source")},
		{"resolved on the offline floor", SandboxPolicyResolvedEvent{Sandbox: floor, Subject: subject, Reason: "offline_floor"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
			with(map[string]any{"defenseclaw.metric.result": "provisional"})},
		{"resolved, not provisional", SandboxPolicyResolvedEvent{Sandbox: identity, Subject: subject}, "", nil},
		{"provisional lookup resolved", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchLookupResolved},
			observability.TelemetryInstrumentDefenseClawSandboxManagedProvisional,
			with(map[string]any{"defenseclaw.metric.result": "resolved"})},
		{"generation re-match", SandboxPolicyRematchedEvent{Sandbox: identity, Subject: subject, Reason: SandboxRematchGeneration}, "", nil},
		{"settings drift", SandboxSettingsDriftEvent{Sandbox: managedOnly, Subject: subject, Field: "compute_driver"},
			observability.TelemetryInstrumentDefenseClawSandboxManagedDrift,
			with(map[string]any{"defenseclaw.openshell.settings.field": "compute_driver"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
				t.Fatal(err)
			}
			for _, instrument := range sandboxManagedInstruments {
				got := sandboxMetrics(t, runtime, instrument)
				if instrument != tc.instrument {
					if len(got) != 0 {
						t.Fatalf("%s moved %d times; want only %q", instrument, len(got), tc.instrument)
					}
					continue
				}
				if len(got) != 1 || sandboxMetricValue(t, got[0]) != 1 {
					t.Fatalf("%s points=%d, want one increment", instrument, len(got))
				}
				attributes := metricAttributes(t, got[0])
				if !reflect.DeepEqual(attributes, tc.want) {
					t.Fatalf("%s attributes=%#v want %#v", instrument, attributes, tc.want)
				}
				for key := range attributes {
					for _, private := range []string{"user", "subject", "principal", "registration", "sandbox.name", "sandbox.id", "server.", "host."} {
						if strings.Contains(key, private) {
							t.Fatalf("%s carries the per-person or per-sandbox label %q", instrument, key)
						}
					}
				}
			}
		})
	}
}

// A reason, a setting field or a connector the counters take from a record
// can come from the sandbox daemon, which runs as the managed user. A value
// outside the closed lists (here one shaped like a code but naming an
// account) is counted as other, or left out for a connector, and never
// becomes a label. Before, any value that matched the code pattern was the
// label.
func TestSandboxManagedCountersTakeOnlyClosedValues(t *testing.T) {
	harness := newSandboxHarness(t)
	identity, subject := testManagedIdentity(), testManagedSubject()
	unknownConnector := SandboxIdentity{Connector: "jdoe_agent", Driver: SandboxDriverDocker, Managed: identity.Managed}
	cases := []struct {
		name, instrument, key string
		event                 any
		want                  any
	}{
		{"access refusal reason", observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, "defenseclaw.sandbox.managed.reason",
			SandboxAccessRefusedEvent{Sandbox: identity, Subject: subject, Host: "blocked.example.com", Port: 443, Reason: "acct_jdoe_4021"},
			SandboxManagedMetricOther},
		{"ask reason", observability.TelemetryInstrumentDefenseClawSandboxManagedAsks, "defenseclaw.sandbox.managed.reason",
			SandboxAskDecidedEvent{Sandbox: identity, Subject: subject, ApprovalID: "ask-3", Result: SandboxApprovalDenied,
				Reason: "user_jdoe", Host: "api.example.com", Port: 443},
			SandboxManagedMetricOther},
		{"drift field", observability.TelemetryInstrumentDefenseClawSandboxManagedDrift, "defenseclaw.openshell.settings.field",
			SandboxSettingsDriftEvent{Sandbox: identity, Subject: subject, Field: "home.jdoe.token_path"},
			SandboxManagedMetricOther},
		{"connector", observability.TelemetryInstrumentDefenseClawSandboxManagedRefusals, "defenseclaw.connector.source",
			SandboxHostRunRefusedEvent{Sandbox: unknownConnector, Subject: subject, Reason: "required_for"},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recordManagedEvent(context.Background(), recorder, tc.event); err != nil {
				t.Fatal(err)
			}
			got := sandboxMetrics(t, runtime, tc.instrument)
			if len(got) != 1 {
				t.Fatalf("%s points=%d, want one increment", tc.instrument, len(got))
			}
			value, present := metricAttributes(t, got[0])[tc.key]
			if tc.want == nil {
				if present {
					t.Fatalf("%s carries %s=%v, want none", tc.instrument, tc.key, value)
				}
				return
			}
			if value != tc.want {
				t.Fatalf("%s %s=%v, want %v", tc.instrument, tc.key, value, tc.want)
			}
		})
	}
	for _, code := range []string{"required_for", "no_kvm", "floor_denied", "account_busy",
		// The access refusals of the openshell manager (accessRefused*).
		"egress_proxy", "egress_proposal", "approved_rule_removed"} {
		if got := SandboxManagedMetricReason(code); got != code {
			t.Fatalf("registered reason %q counted as %q", code, got)
		}
	}
}
