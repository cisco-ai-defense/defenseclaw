// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

func TestTraceOTLPContractCoversRegisteredGeneratedFamilies(t *testing.T) {
	for _, descriptor := range generatedFamilyIdentityDescriptors() {
		if descriptor.Identity.Signal != SignalTraces {
			continue
		}
		family := descriptor.Identity.Name
		contract, ok := traceOTLPContract(family)
		if !ok {
			t.Fatalf("registered trace family %q has no OTLP contract", family)
		}
		if contract.identity.Name != family || contract.identity.Signal != SignalTraces {
			t.Fatalf("family %q resolved mismatched identity %+v", family, contract.identity)
		}
		for _, descriptor := range contract.fields {
			if kind, present := TraceOTLPAttributeKind(family, descriptor.key); !present || kind == OTLPValueInvalid {
				t.Fatalf("family %q attribute %q has no OTLP value kind", family, descriptor.key)
			}
		}
		for _, event := range contract.allowedEvents {
			for _, descriptor := range event.fields {
				if kind, present := TraceOTLPEventAttributeKind(family, event.name, descriptor.key); !present || kind == OTLPValueInvalid {
					t.Fatalf("family %q event %q attribute %q has no OTLP value kind", family, event.name, descriptor.key)
				}
			}
		}
	}
	if _, ok := traceOTLPContract("span.unknown"); ok {
		t.Fatal("unknown family unexpectedly resolved")
	}
}

func TestTraceOTLPContractPreservesNumericAndStructuredArms(t *testing.T) {
	tests := []struct {
		family EventName
		key    string
		want   OTLPValueKind
	}{
		{EventName(TelemetryFamilyAgentTransition), "defenseclaw.agent.sequence", OTLPValueInt64},
		{EventName(TelemetryFamilyAgentTransition), "defenseclaw.agent.reported_cost.usd", OTLPValueDouble},
		{EventName(TelemetryFamilyModelChat), "defenseclaw.model.streaming", OTLPValueBoolean},
		{EventName(TelemetryFamilyModelChat), "gen_ai.output.messages", OTLPValueStructured},
		{EventName(TelemetryFamilyGuardrailApply), "defenseclaw.guardrail.rule_ids", OTLPValueStringArray},
	}
	for _, test := range tests {
		got, ok := TraceOTLPAttributeKind(test.family, test.key)
		if !ok || got != test.want {
			t.Fatalf("%s/%s kind=%d present=%t want=%d", test.family, test.key, got, ok, test.want)
		}
	}
}
