// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package localobservability

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestLegacyV7ProjectedTraceResourcePlaceholdersRemainOTLPCompatible(t *testing.T) {
	fixture := newLocalFixture(t, "legacy-v7", 12)
	for _, test := range []struct {
		name, canaryTarget string
	}{
		{name: "ordinary"},
		{name: "canary", canaryTarget: DestinationName},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := fixture.agentRecord(t, agentRecordInput{
				traceID: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", spanID: "e1e2e3e4e5e6e7e8",
				agentID: "agent-legacy-v7", rootID: "agent-legacy-v7", agentType: "diagnostic",
				lifecycle: "lifecycle-legacy-v7", execution: "execution-legacy-v7", phase: "session", phaseCode: 1,
				canaryTarget: test.canaryTarget,
			})
			outcome, err := fixture.pipeline.Process(record)
			if err != nil || len(outcome.OptionalWork()) != 1 || len(outcome.OptionalFailures()) != 0 {
				t.Fatalf("legacy-v7 projection err=%v work=%d failures=%d", err, len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
			}
			result := Project(outcome.OptionalWork()[0].Projection())
			encoded, ok := result.Bytes()
			if !ok {
				t.Fatalf("legacy-v7 compatibility projection=%s", result.Reason())
			}
			wire, ok := decodeWire(encoded, true)
			if !ok {
				t.Fatal("decode legacy-v7 compatibility projection")
			}
			for _, key := range []string{"service.instance.id", "defenseclaw.instance.id"} {
				value, valueOK := wire.Body.Resource.Attributes[key].(string)
				if !valueOK || !strings.HasPrefix(value, "<redacted len=") || !strings.Contains(value, " sha=") {
					t.Fatalf("legacy-v7 projected resource %s did not retain the bounded redaction placeholder", key)
				}
			}
			if _, ok := NewPayload(result, ""); !ok {
				t.Fatalf("legacy-v7 projected runtime trace was rejected before OTLP delivery: predicate=%s", projectedWireFailure(wire, fixture.destination.Name))
			}
		})
	}
}

func TestLegacyV7ProjectedModelCanaryRemainsOTLPCompatible(t *testing.T) {
	fixture := newLocalFixture(t, "legacy-v7", 12)
	record := fixture.modelRecord(t, modelRecordInput{
		traceID: "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", spanID: "f1f2f3f4f5f6f7f8",
		parentSpanID: "e1e2e3e4e5e6e7e8", agentID: "agent-legacy-v7", rootID: "agent-legacy-v7",
		agentType: "diagnostic", lifecycle: "lifecycle-legacy-v7", execution: "execution-legacy-v7",
		canaryTarget: DestinationName,
	})
	outcome, err := fixture.pipeline.Process(record)
	if err != nil || len(outcome.OptionalWork()) != 1 || len(outcome.OptionalFailures()) != 0 {
		t.Fatalf("legacy-v7 model projection err=%v work=%d failures=%d", err, len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}
	result := Project(outcome.OptionalWork()[0].Projection())
	encoded, ok := result.Bytes()
	if !ok {
		t.Fatalf("legacy-v7 model compatibility projection=%s", result.Reason())
	}
	wire, ok := decodeWire(encoded, true)
	if !ok {
		t.Fatal("decode legacy-v7 model compatibility projection")
	}
	if _, ok := NewPayload(result, ""); !ok {
		t.Fatalf("legacy-v7 projected model canary was rejected: predicate=%s parent_span_id=%q", projectedWireFailure(wire, fixture.destination.Name), wire.Body.ParentSpanID)
	}
}

func TestLegacyV7ProjectedTraceRejectsTamperedIdentityPlaceholders(t *testing.T) {
	fixture := newLocalFixture(t, "legacy-v7", 12)
	record := fixture.agentRecord(t, agentRecordInput{
		traceID: "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1", spanID: "a1a2a3a4a5a6a7a8",
		agentID: "agent-legacy-negative", rootID: "agent-legacy-negative", agentType: "diagnostic",
		lifecycle: "lifecycle-legacy-negative", execution: "execution-legacy-negative", phase: "session", phaseCode: 1,
		canaryTarget: DestinationName,
	})
	outcome, err := fixture.pipeline.Process(record)
	if err != nil || len(outcome.OptionalWork()) != 1 {
		t.Fatal("build legacy-v7 negative fixture")
	}
	projected := Project(outcome.OptionalWork()[0].Projection())
	encoded, ok := projected.Bytes()
	if !ok {
		t.Fatal("project legacy-v7 negative fixture")
	}
	base, ok := decodeWire(encoded, true)
	if !ok {
		t.Fatal("decode legacy-v7 negative fixture")
	}
	for _, test := range []struct {
		name   string
		mutate func(*projectedWire)
	}{
		{name: "wrong profile", mutate: func(wire *projectedWire) {
			wire.Projection.RedactionProfile = "strict"
		}},
		{name: "malformed source placeholder", mutate: func(wire *projectedWire) {
			wire.Body.Attributes["defenseclaw.source"] = "<redacted arbitrary>"
		}},
		{name: "malformed resource placeholder", mutate: func(wire *projectedWire) {
			wire.Body.Resource.Attributes["service.instance.id"] = "<redacted arbitrary>"
		}},
		{name: "raw valid resource identifier", mutate: func(wire *projectedWire) {
			wire.Body.Resource.Attributes["service.instance.id"] = "raw-valid-instance"
		}},
		{name: "malformed canary target", mutate: func(wire *projectedWire) {
			wire.Body.Attributes[canaryDestination] = "<redacted arbitrary>"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := base
			wire.Body.Attributes = cloneObject(base.Body.Attributes)
			wire.Body.Resource.Attributes = cloneObject(base.Body.Resource.Attributes)
			test.mutate(&wire)
			forged := encodedResult(t, wire)
			if _, accepted := NewPayload(forged, ""); accepted {
				t.Fatal("tampered legacy-v7 projection reached a delivery payload")
			}
		})
	}

	wrongTarget := base
	wrongTarget.Body.Attributes = cloneObject(base.Body.Attributes)
	wrongTarget.Body.Attributes[canaryDestination] = legacyredaction.LegacyV7Entity("wrong-destination")
	if _, _, _, _, _, accepted := wrongTarget.otlp(fixture.destination.Name); accepted {
		t.Fatal("request validation accepted a valid placeholder for the wrong raw destination")
	}
}

func encodedResult(t *testing.T, wire projectedWire) Result {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return Result{reason: ProjectionEligible, encoded: encoded}
}

func projectedWireFailure(wire projectedWire, destination string) string {
	if _, ok := decodeID(stringMap(wire.Correlation, "trace_id"), 16); !ok {
		return "trace_id"
	}
	if _, ok := decodeID(stringMap(wire.Correlation, "span_id"), 8); !ok {
		return "span_id"
	}
	if wire.Body.ParentSpanID != "" {
		if _, ok := decodeID(wire.Body.ParentSpanID, 8); !ok {
			return "parent_span_id"
		}
	}
	start, startOK := unsigned(wire.Body.StartTimeUnixNano, 64)
	end, endOK := unsigned(wire.Body.EndTimeUnixNano, 64)
	if !startOK || !endOK || start == 0 || end < start {
		return "timing"
	}
	if _, ok := spanKind(wire.Body.Kind); !ok {
		return "kind"
	}
	if !canonicalEndedIdentity(wire) {
		return "canonical_identity"
	}
	if present, valid := generatedCanary(wire, destination); present && !valid {
		return "canary"
	}
	family := observability.EventName(wire.Family)
	if _, ok := spanAttributes(family, wire.Body.Attributes); !ok {
		return "span_attributes"
	}
	if _, ok := requiredResourceAttributes(family, wire.Body.Resource.Attributes, wire.Projection.RedactionProfile); !ok {
		return "resource_attributes"
	}
	if _, ok := requiredScope(family, wire.Body.Scope); !ok {
		return "scope"
	}
	if _, ok := status(wire.Body.Status); !ok {
		return "status"
	}
	if _, ok := events(family, wire.Body.Events); !ok {
		return "events"
	}
	if _, ok := links(family, wire.Body.Links); !ok {
		return "links"
	}
	return "dropped_counts_or_payload"
}
