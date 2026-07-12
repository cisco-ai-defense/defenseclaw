// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestGeneratedProfileExactlyCoversImplementedShapes(t *testing.T) {
	t.Parallel()
	manifest, err := profilemanifest.Get(ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Shape{
		"span.agent.invoke":     ShapeAgent,
		"span.guardrail.judge":  ShapeLLM,
		"span.model.chat":       ShapeLLM,
		"span.retrieval.search": ShapeRetriever,
		"span.tool.execute":     ShapeTool,
		"span.workflow.run":     ShapeWorkflow,
	}
	if len(manifest.Families) != len(want) {
		t.Fatalf("generated Galileo family count = %d, want %d", len(manifest.Families), len(want))
	}
	for _, ineligible := range []string{"span.agent.transition", "span.approval.resolve"} {
		if profilemanifest.Eligible(ProfileID, observability.SignalTraces, observability.EventName(ineligible)) {
			t.Fatalf("generated Galileo profile admitted explicitly ineligible family %q", ineligible)
		}
	}
	for _, family := range manifest.Families {
		shape, ok := want[family.FamilyID]
		if !ok || family.Signal != observability.SignalTraces ||
			family.Projection.Shape != string(shape) || family.Projection.Mode != "galileo_shape_v2" {
			t.Fatalf("generated Galileo family = %+v", family)
		}
	}
}

func TestGeneratedFamilyStructuralDispositionsAreCompleteAndDetached(t *testing.T) {
	t.Parallel()
	manifest, err := profilemanifest.Get(ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range manifest.Families {
		family := family
		t.Run(family.FamilyID, func(t *testing.T) {
			t.Parallel()
			profileContract, ok := profilemanifest.FamilyTraceContract(
				ProfileID, family.Signal, family.EventName,
			)
			if !ok {
				t.Fatal("generated profile trace contract missing")
			}
			registered, ok := observability.RegisteredTraceProjectionContract(
				observability.EventIdentity{
					Bucket: family.Bucket, Signal: family.Signal, Name: family.EventName,
				},
			)
			if !ok || !reflect.DeepEqual(profileContract.AttributeKeys, registered.AttributeKeys) ||
				!reflect.DeepEqual(profileContract.EventNames, sortedMapKeys(registered.EventAttributeKeys)) ||
				!reflect.DeepEqual(profileContract.LinkRelations, registered.LinkRelations) {
				t.Fatalf("generated contract disagreement profile=%+v registered=%+v", profileContract, registered)
			}

			attributes := make(map[string]any, len(registered.AttributeKeys)+1)
			for _, key := range registered.AttributeKeys {
				attributes[key] = "registered-value"
			}
			attributes["operator.unregistered"] = "must-not-project"
			projected := projectAttributes(
				attributes, stringSet(registered.AttributeKeys), defaultAttributeValueBytes,
			)
			if len(projected) != len(registered.AttributeKeys) {
				t.Fatalf("attribute dispositions = %d, want %d", len(projected), len(registered.AttributeKeys))
			}
			if _, exists := projected["operator.unregistered"]; exists {
				t.Fatal("unregistered family attribute projected")
			}

			for eventName, keys := range registered.EventAttributeKeys {
				input := make(map[string]any, len(keys)+1)
				for _, key := range keys {
					input[key] = "registered-value"
				}
				input["operator.unregistered"] = "must-not-project"
				got := projectEventAttributes(
					input, stringSet(keys), defaultAttributesPerEvent, defaultAttributeValueBytes,
				)
				if len(got) != len(keys) {
					t.Fatalf("event %q dispositions = %d, want %d", eventName, len(got), len(keys))
				}
				if _, exists := got["operator.unregistered"]; exists {
					t.Fatalf("event %q projected unregistered field", eventName)
				}
			}

			linkInput := make(map[string]any, len(registered.LinkAttributeKeys)+1)
			for _, key := range registered.LinkAttributeKeys {
				linkInput[key] = "registered-value"
			}
			linkInput["operator.unregistered"] = "must-not-project"
			linkOutput := projectLinkAttributes(
				linkInput, stringSet(registered.LinkAttributeKeys),
				defaultAttributesPerEvent, defaultAttributeValueBytes,
			)
			if len(linkOutput) != len(registered.LinkAttributeKeys) {
				t.Fatalf("link dispositions = %d, want %d", len(linkOutput), len(registered.LinkAttributeKeys))
			}
		})
	}
}

func TestCompatibilityOnlyInputsAreExplicitAndClosed(t *testing.T) {
	t.Parallel()
	allowed := map[string]struct{}{"gen_ai.provider.name": {}}
	input := map[string]any{
		"gen_ai.provider.name": "openai", "openinference.span.kind": "LLM",
		"input.value": "prompt", "input.mime_type": "text/plain",
		"output.value": "answer", "output.mime_type": "text/plain",
		"openinference.secret": "must-not-project", "operator.unregistered": "must-not-project",
	}
	projected := projectAttributes(input, allowed, defaultAttributeValueBytes)
	for _, key := range []string{
		"gen_ai.provider.name", "openinference.span.kind", "input.value", "input.mime_type",
		"output.value", "output.mime_type",
	} {
		if _, present := projected[key]; !present {
			t.Errorf("explicit compatibility input %q missing", key)
		}
	}
	for _, key := range []string{"openinference.secret", "operator.unregistered"} {
		if _, present := projected[key]; present {
			t.Errorf("unregistered compatibility input %q projected", key)
		}
	}
}

func TestProjectAcceptsExactRichV2Shapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		bucket     observability.Bucket
		family     observability.EventName
		spanName   string
		kind       any
		attributes map[string]any
		wantShape  Shape
		wantOIKind string
	}{
		{
			name: "agent", bucket: observability.BucketAgentLifecycle, family: "span.agent.invoke",
			spanName: "invoke_agent reviewer", kind: "INTERNAL", wantShape: ShapeAgent, wantOIKind: "AGENT",
			attributes: map[string]any{
				"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai",
				"gen_ai.agent.name": "reviewer", "gen_ai.input.messages": messages("user", "inspect"),
				"gen_ai.output.messages": messages("assistant", "done"),
			},
		},
		{
			name: "chat", bucket: observability.BucketModelIO, family: "span.model.chat",
			spanName: "chat gpt-5", kind: 3, wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
				"gen_ai.request.model": "gpt-5", "gen_ai.input.messages": messages("user", "hello"),
				"gen_ai.output.messages": messages("assistant", "hello"),
			},
		},
		{
			name: "text completion", bucket: observability.BucketModelIO, family: "span.model.chat",
			spanName: "text_completion llama", kind: json.Number("3"), wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "text_completion", "gen_ai.provider.name": "local",
				"gen_ai.input.messages":  messages("user", "prefix"),
				"gen_ai.output.messages": messages("assistant", "suffix"),
			},
		},
		{
			name: "tool", bucket: observability.BucketToolActivity, family: "span.tool.execute",
			spanName: "execute_tool search", kind: "CLIENT", wantShape: ShapeTool, wantOIKind: "TOOL",
			attributes: map[string]any{
				"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "search",
				"gen_ai.tool.call.id": "call-9", "gen_ai.tool.call.arguments": map[string]any{"q": "otel"},
				"gen_ai.tool.call.result": map[string]any{"hits": 2},
			},
		},
		{
			name: "retriever", bucket: observability.BucketToolActivity, family: "span.retrieval.search",
			spanName: "retrieve vector-store", kind: "CLIENT", wantShape: ShapeRetriever, wantOIKind: "RETRIEVER",
			attributes: map[string]any{
				"db.operation.name": "search", "input.value": "redacted query",
				"gen_ai.output.messages": messages("assistant", "bounded document summary"),
			},
		},
		{
			name: "workflow", bucket: observability.BucketAgentLifecycle, family: "span.workflow.run",
			spanName: "workflow retrieval-turn", kind: "INTERNAL", wantShape: ShapeWorkflow, wantOIKind: "CHAIN",
			attributes: map[string]any{
				"defenseclaw.workflow.name": "retrieval-turn",
				"input.value":               "turn input", "output.value": "turn output",
			},
		},
		{
			name: "judge chat", bucket: observability.BucketGuardrailEvaluation, family: "span.guardrail.judge",
			spanName: "chat judge-model", kind: "CLIENT", wantShape: ShapeLLM, wantOIKind: "LLM",
			attributes: map[string]any{
				"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
				"gen_ai.request.model": "judge-model", "gen_ai.input.messages": messages("user", "[REDACTED]"),
				"gen_ai.output.messages": messages("assistant", "allow"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := projectRecord(t, test.bucket, test.family, test.spanName, map[string]any{
				"kind": test.kind, "attributes": test.attributes,
			}, redaction.ProfileNone)
			result := Project(projection, Limits{})
			if !result.Eligible() || result.Reason() != ReasonEligible || result.Shape() != test.wantShape {
				t.Fatalf("result = eligible:%v reason:%q shape:%q missing:%v", result.Eligible(), result.Reason(), result.Shape(), result.MissingFields())
			}
			wire := resultWire(t, result)
			if got := wire["compatibility_profile"]; got != ProfileID {
				t.Fatalf("profile = %v", got)
			}
			attrs := resultAttributes(t, result)
			if got := attrs["openinference.span.kind"]; got != test.wantOIKind {
				t.Fatalf("openinference kind = %v", got)
			}
			if _, ok := attrs["gen_ai.input.messages"]; !ok {
				t.Fatal("input messages missing")
			}
			if _, ok := attrs["gen_ai.output.messages"]; !ok {
				t.Fatal("output messages missing")
			}
			for _, direction := range []string{"input", "output"} {
				value, valueOK := attrs[direction+".value"].(string)
				if !valueOK || value == "" {
					t.Fatalf("Galileo UI-facing %s.value missing: %#v", direction, attrs)
				}
				wantMimeType := "text/plain"
				if test.family == "span.tool.execute" {
					wantMimeType = "application/json"
				}
				if got := attrs[direction+".mime_type"]; got != wantMimeType {
					t.Fatalf("Galileo UI-facing %s.mime_type = %#v", direction, got)
				}
			}
			if _, suppliedAsValue := test.attributes["input.value"]; suppliedAsValue {
				if attrs["defenseclaw.telemetry.input.reported"] != true || attrs["gen_ai.input.messages"] == "[]" {
					t.Fatalf("input.value was not projected as reported messages: %#v", attrs)
				}
			}
			if test.family == "span.guardrail.judge" && attrs["defenseclaw.guardrail.judge"] != true {
				t.Fatal("judge marker missing")
			}
			if test.family == "span.workflow.run" && attrs["defenseclaw.workflow.name"] != "retrieval-turn" {
				t.Fatalf("workflow name = %#v", attrs["defenseclaw.workflow.name"])
			}
			first, _ := result.Bytes()
			second, _ := Project(projection, Limits{}).Bytes()
			if !bytes.Equal(first, second) {
				t.Fatal("projection is not deterministic")
			}
		})
	}
}

func TestProjectMalformedAndUnicodeContentStates(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat unicode", map[string]any{
		"kind": "CLIENT",
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages":  `[{"role":"user","content":`,
			"gen_ai.output.messages": messages("assistant", "こんにちは 🦀"),
			"error.type":             "invalid_response",
		},
		"status": map[string]any{"code": 2, "description": "bounded redacted failure"},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q, missing %v", result.Reason(), result.MissingFields())
	}
	attributes := resultAttributes(t, result)
	if attributes["gen_ai.input.messages"] != "[]" || attributes["defenseclaw.telemetry.input.reported"] != true ||
		attributes["defenseclaw.telemetry.input.state"] != "failed_closed" {
		t.Fatalf("malformed input state = %#v", attributes)
	}
	if attributes["input.value"] != "[]" || attributes["input.mime_type"] != "application/json" {
		t.Fatalf("malformed UI-facing input = %#v", attributes)
	}
	if !strings.Contains(attributes["gen_ai.output.messages"].(string), "こんにちは") || attributes["error.type"] != "invalid_response" {
		t.Fatalf("unicode/error projection = %#v", attributes)
	}
	body := resultWire(t, result)["body"].(map[string]any)
	status := body["status"].(map[string]any)
	if status["code"] != json.Number("2") || status["description"] != "bounded redacted failure" {
		t.Fatalf("status = %#v", status)
	}
}

func TestProjectMissingContentUsesHonestPlaceholders(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat", map[string]any{
		"kind": "CLIENT",
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"defenseclaw.telemetry.input.reported": false,
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q, missing %v", result.Reason(), result.MissingFields())
	}
	attributes := resultAttributes(t, result)
	for _, direction := range []string{"input", "output"} {
		if got := attributes["gen_ai."+direction+".messages"]; got != "[]" {
			t.Errorf("%s placeholder = %#v", direction, got)
		}
		if got := attributes["defenseclaw.telemetry."+direction+".reported"]; got != false {
			t.Errorf("%s reported = %#v", direction, got)
		}
		if got := attributes["defenseclaw.telemetry."+direction+".state"]; got != "not_reported" {
			t.Errorf("%s state = %#v", direction, got)
		}
		if got := attributes[direction+".value"]; got != "" {
			t.Errorf("%s UI-facing placeholder = %#v", direction, got)
		}
		if got := attributes[direction+".mime_type"]; got != "text/plain" {
			t.Errorf("%s UI-facing MIME type = %#v", direction, got)
		}
	}
	if _, exists := attributes["gen_ai.request.model"]; exists {
		t.Fatal("unknown model was fabricated")
	}
}

func TestProjectToolAliasesHonorMessageSuppression(t *testing.T) {
	t.Parallel()
	const inputCanary = "TOOL-INPUT-MUST-NOT-RENDER"
	const outputCanary = "TOOL-OUTPUT-MUST-NOT-RENDER"
	projection := projectRecord(t, observability.BucketToolActivity, "span.tool.execute", "execute_tool lookup", map[string]any{
		"kind": "INTERNAL",
		"attributes": map[string]any{
			"gen_ai.operation.name":                 "execute_tool",
			"gen_ai.tool.name":                      "lookup",
			"gen_ai.tool.call.arguments":            map[string]any{"query": inputCanary},
			"gen_ai.tool.call.result":               map[string]any{"summary": outputCanary},
			"defenseclaw.telemetry.input.reported":  false,
			"defenseclaw.telemetry.output.reported": false,
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q, missing %v", result.Reason(), result.MissingFields())
	}
	attributes := resultAttributes(t, result)
	for _, direction := range []string{"input", "output"} {
		if got := attributes["gen_ai."+direction+".messages"]; got != "[]" {
			t.Errorf("%s messages = %#v", direction, got)
		}
		if got := attributes["defenseclaw.telemetry."+direction+".reported"]; got != false {
			t.Errorf("%s reported = %#v", direction, got)
		}
		if got := attributes[direction+".value"]; got != "" {
			t.Errorf("%s UI-facing alias bypassed suppression = %#v", direction, got)
		}
	}
}

func TestOpenInferenceMessageValueOnlyFlattensTextParts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		encoded  string
		want     string
		wantMIME string
	}{
		{
			name:     "multiple text messages include roles",
			encoded:  `[{"role":"user","parts":[{"type":"text","content":"first"}]},{"role":"assistant","parts":[{"type":"text","content":"second"}]}]`,
			want:     "user: first\nassistant: second",
			wantMIME: "text/plain",
		},
		{
			name:     "blob remains canonical JSON",
			encoded:  `[{"role":"user","parts":[{"type":"blob","content":"aW1hZ2U="}]}]`,
			want:     `[{"role":"user","parts":[{"type":"blob","content":"aW1hZ2U="}]}]`,
			wantMIME: "application/json",
		},
		{
			name:     "reasoning remains canonical JSON",
			encoded:  `[{"role":"assistant","parts":[{"type":"reasoning","content":"private reasoning"}]}]`,
			want:     `[{"role":"assistant","parts":[{"type":"reasoning","content":"private reasoning"}]}]`,
			wantMIME: "application/json",
		},
		{
			name:     "unknown part remains canonical JSON",
			encoded:  `[{"role":"user","parts":[{"content":"future shape"}]}]`,
			want:     `[{"role":"user","parts":[{"content":"future shape"}]}]`,
			wantMIME: "application/json",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, gotMIME := openInferenceMessageValue(test.encoded, true)
			if got != test.want || gotMIME != test.wantMIME {
				t.Fatalf("value = %q (%s), want %q (%s)", got, gotMIME, test.want, test.wantMIME)
			}
		})
	}
}

func TestProjectToolRemovedContentIsAnExplicitSchemaMiss(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketToolActivity, "span.tool.execute", "execute_tool shell", map[string]any{
		"kind": "INTERNAL",
		"attributes": map[string]any{
			"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "shell",
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	want := []string{"gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}
	if result.Eligible() || result.Reason() != ReasonSchemaMissingRequired || !reflect.DeepEqual(result.MissingFields(), want) {
		t.Fatalf("result = eligible:%v reason:%q missing:%v", result.Eligible(), result.Reason(), result.MissingFields())
	}
}

func TestProjectRejectsSchemaMissAndNativeNonGalileoShapes(t *testing.T) {
	t.Parallel()
	missingProvider := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat model", map[string]any{
		"kind": "CLIENT", "attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.input.messages": messages("user", "x"),
			"gen_ai.output.messages": messages("assistant", "y"),
		},
	}, redaction.ProfileNone)
	result := Project(missingProvider, Limits{})
	if result.Eligible() || result.Reason() != ReasonSchemaMissingRequired ||
		!reflect.DeepEqual(result.MissingFields(), []string{"gen_ai.provider.name"}) {
		t.Fatalf("schema miss = eligible:%v reason:%q missing:%v", result.Eligible(), result.Reason(), result.MissingFields())
	}
	if _, err := result.Bytes(); !IsProjectionError(err, ReasonSchemaMissingRequired) || strings.Contains(err.Error(), "model") {
		t.Fatalf("safe rejection error = %v", err)
	}

	nativeGuardrail := projectRecord(t, observability.BucketGuardrailEvaluation, "span.guardrail.apply", "apply_guardrail pii input", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages": messages("user", "x"), "gen_ai.output.messages": messages("assistant", "y"),
		},
	}, redaction.ProfileNone)
	if got := Project(nativeGuardrail, Limits{}); got.Reason() != ReasonUnsupportedShape {
		t.Fatalf("native guardrail reason = %q", got.Reason())
	}

	for _, test := range []struct {
		name     string
		bucket   observability.Bucket
		family   observability.EventName
		spanName string
	}{
		{name: "agent transition", bucket: observability.BucketAgentLifecycle, family: "span.agent.transition", spanName: "agent.transition approval"},
		{name: "approval resolution", bucket: observability.BucketEnforcementAction, family: "span.approval.resolve", spanName: "exec.approval"},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection := projectRecord(t, test.bucket, test.family, test.spanName, map[string]any{
				"kind": "INTERNAL", "attributes": map[string]any{
					"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai",
					"gen_ai.agent.name": "invented-shape", "gen_ai.input.messages": messages("user", "x"),
					"gen_ai.output.messages": messages("assistant", "y"),
				},
			}, redaction.ProfileNone)
			got := Project(projection, Limits{})
			if got.Eligible() || got.Reason() != ReasonUnsupportedShape {
				t.Fatalf("explicitly ineligible result = eligible:%v reason:%q", got.Eligible(), got.Reason())
			}
		})
	}

	wrongOperation := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent a", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{"gen_ai.operation.name": "execute_tool"},
	}, redaction.ProfileNone)
	if got := Project(wrongOperation, Limits{}); got.Reason() != ReasonUnsupportedShape {
		t.Fatalf("wrong operation reason = %q", got.Reason())
	}

	for _, test := range []struct {
		name       string
		spanName   string
		attributes map[string]any
		missing    []string
	}{
		{
			name: "missing workflow name", spanName: "workflow retrieval-turn",
			attributes: map[string]any{}, missing: []string{"defenseclaw.workflow.name"},
		},
		{
			name: "unbounded workflow name", spanName: "workflow " + strings.Repeat("a", 129),
			attributes: map[string]any{"defenseclaw.workflow.name": strings.Repeat("a", 129)},
			missing:    []string{"defenseclaw.workflow.name"},
		},
		{
			name: "invalid workflow token", spanName: "workflow Retrieval Turn",
			attributes: map[string]any{"defenseclaw.workflow.name": "Retrieval Turn"},
			missing:    []string{"defenseclaw.workflow.name"},
		},
		{
			name: "rendered workflow name mismatch", spanName: "workflow other-turn",
			attributes: map[string]any{"defenseclaw.workflow.name": "retrieval-turn"},
			missing:    []string{"span_name"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection := projectRecord(t, observability.BucketAgentLifecycle, "span.workflow.run", test.spanName, map[string]any{
				"kind": "INTERNAL", "attributes": test.attributes,
			}, redaction.ProfileNone)
			got := Project(projection, Limits{})
			if got.Eligible() || got.Reason() != ReasonSchemaMissingRequired || !reflect.DeepEqual(got.MissingFields(), test.missing) {
				t.Fatalf("workflow result = eligible:%v reason:%q missing:%v", got.Eligible(), got.Reason(), got.MissingFields())
			}
		})
	}
}

func TestProjectPreservesLifecycleCorrelationAndSafeSecurityEvents(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"kind":           "INTERNAL",
		"parent_span_id": "0011223344556677",
		"attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "anthropic", "gen_ai.agent.name": "reviewer",
			"gen_ai.agent.id": "child", "gen_ai.agent.type": "subagent", "gen_ai.conversation.id": "conversation",
			"gen_ai.input.messages": messages("user", "review"), "gen_ai.output.messages": messages("assistant", "done"),
			"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
			"defenseclaw.agent.lifecycle.id": "life", "defenseclaw.agent.execution.id": "exec",
			"defenseclaw.agent.lifecycle.event": "subagent_start", "defenseclaw.agent.lifecycle.state": "active",
			"defenseclaw.agent.phase": "model", "defenseclaw.agent.phase.previous": "planning",
			"defenseclaw.agent.phase.code": 3, "defenseclaw.agent.sequence": 7, "defenseclaw.agent.depth": 2,
			"defenseclaw.session.root.id": "root-session", "defenseclaw.session.parent.id": "parent-session",
			"defenseclaw.session.source": "claude-code", "defenseclaw.session.resumed": true,
			"defenseclaw.operation.id": "operation", "defenseclaw.turn.id": "turn",
			"defenseclaw.guardrail.decision": "block", "defenseclaw.guardrail.reason": "do not export this detail",
			"defenseclaw.llm.request.body": "not a safe overlay alias", "arbitrary.secret": "not allowed",
		},
		"events": []any{
			map[string]any{"name": "guardrail.decision", "attributes": map[string]any{
				"defenseclaw.evaluation.id": "eval", "defenseclaw.guardrail.decision": "block",
				"defenseclaw.security.severity": "HIGH", "reason": "unsafe detail",
			}},
			map[string]any{"name": "security.finding.observed", "attributes": map[string]any{
				"defenseclaw.finding.id": "finding", "defenseclaw.finding.rule_id": "rule",
				"defenseclaw.finding.category": "injection", "evidence": "unsafe evidence",
			}},
			map[string]any{"name": "custom.raw", "attributes": map[string]any{"content": "raw"}},
		},
		"links": []any{
			map[string]any{"trace_id": strings.Repeat("1", 32), "span_id": strings.Repeat("2", 16), "attributes": map[string]any{
				"defenseclaw.link.relation": "correlates_with", "defenseclaw.agent.root.id": "root", "reason": "drop",
			}},
		},
	}
	projection := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent reviewer", body, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("result = %q", result.Reason())
	}
	attributes := resultAttributes(t, result)
	for key, want := range map[string]any{
		"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
		"defenseclaw.agent.lifecycle.id": "life", "defenseclaw.agent.execution.id": "exec",
		"defenseclaw.agent.lifecycle.event": "subagent_start", "defenseclaw.agent.lifecycle.state": "active",
		"defenseclaw.session.root.id": "root-session", "defenseclaw.session.parent.id": "parent-session",
		"defenseclaw.operation.id": "operation", "defenseclaw.turn.id": "turn",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("%s = %#v, want %#v", key, got, want)
		}
	}
	for _, key := range []string{"defenseclaw.guardrail.reason", "defenseclaw.llm.request.body", "arbitrary.secret"} {
		if _, exists := attributes[key]; exists {
			t.Errorf("unsafe attribute %q retained", key)
		}
	}
	wire := resultWire(t, result)
	correlation := wire["correlation"].(map[string]any)
	for key, want := range map[string]any{
		"session_id": "session-1", "turn_id": "turn-1", "agent_id": "agent-1",
		"agent_instance_id": "instance-1", "tool_invocation_id": "tool-1",
	} {
		if got := correlation[key]; got != want {
			t.Errorf("correlation %s = %#v, want %#v", key, got, want)
		}
	}
	resultBody := wire["body"].(map[string]any)
	events := resultBody["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events = %d", len(events))
	}
	for _, eventValue := range events {
		event := eventValue.(map[string]any)
		eventAttributes := event["attributes"].(map[string]any)
		if _, unsafe := eventAttributes["reason"]; unsafe {
			t.Error("event reason retained")
		}
		if _, unsafe := eventAttributes["evidence"]; unsafe {
			t.Error("event evidence retained")
		}
	}
	links := resultBody["links"].([]any)
	linkAttributes := links[0].(map[string]any)["attributes"].(map[string]any)
	if linkAttributes["defenseclaw.link.relation"] != "correlates_with" {
		t.Fatalf("safe delegation link = %#v", linkAttributes)
	}
	for _, absent := range []string{"defenseclaw.agent.root.id", "reason"} {
		if _, exists := linkAttributes[absent]; exists {
			t.Fatalf("unregistered link attribute %q retained", absent)
		}
	}
}

func TestProjectNeverRecoversRawContentAndDestinationProjectionsRemainIndependent(t *testing.T) {
	t.Parallel()
	const canary = "GALILEO-RAW-CANARY-7c786fc9"
	body := map[string]any{
		"kind": "INTERNAL",
		"attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai", "gen_ai.agent.name": "defenseclaw",
			"gen_ai.input.messages": messages("user", canary), "gen_ai.output.messages": messages("assistant", canary),
			canaryMarkerKey: true, canaryOperationKey: canaryOperationValue, canaryDestinationKey: "galileo",
		},
		"events": []any{map[string]any{"name": "guardrail.decision", "attributes": map[string]any{"decision": "allow", "reason": canary}}},
		"status": map[string]any{"code": 1, "message": canary},
	}
	record := newTraceRecord(t, observability.BucketAgentLifecycle, observability.EventName(observability.TelemetryFamilyAgentInvoke), "invoke_agent diagnostic", body)
	rawRoute := redactRecord(t, record, redaction.ProfileNone)
	strictRoute := redactRecord(t, record, redaction.ProfileStrict)
	rawBefore, _ := rawRoute.Bytes()
	strictBefore, _ := strictRoute.Bytes()

	rawResult := Project(rawRoute, Limits{})
	strictResult := Project(strictRoute, Limits{})
	if !rawResult.Eligible() || !strictResult.Eligible() {
		t.Fatalf("raw=%q strict=%q missing=%v", rawResult.Reason(), strictResult.Reason(), strictResult.MissingFields())
	}
	rawBytes, _ := rawResult.Bytes()
	strictBytes, _ := strictResult.Bytes()
	if !bytes.Contains(rawBytes, []byte(canary)) {
		t.Fatal("none route unexpectedly lost operator-selected raw content")
	}
	if bytes.Contains(strictBytes, []byte(canary)) {
		t.Fatal("strict route recovered raw content")
	}
	strictAttributes := resultAttributes(t, strictResult)
	if strictAttributes["gen_ai.input.messages"] != "[]" || strictAttributes["defenseclaw.telemetry.input.reported"] != false {
		t.Fatalf("strict content state = %#v", strictAttributes)
	}
	if strictAttributes["input.value"] != "" || strictAttributes["output.value"] != "" {
		t.Fatalf("strict UI-facing aliases recovered content = %#v", strictAttributes)
	}
	rawAfter, _ := rawRoute.Bytes()
	strictAfter, _ := strictRoute.Bytes()
	if !bytes.Equal(rawBefore, rawAfter) || !bytes.Equal(strictBefore, strictAfter) {
		t.Fatal("compatibility projection mutated a destination projection")
	}
}

func TestProjectPreservesCanonicalResourceAttributesAndDroppedCount(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		aliases map[string]any
	}{
		{name: "aliases present", aliases: map[string]any{
			"deployment.environment": "test",
			"deployment.mode":        "gateway",
			"defenseclaw.device.id":  "device-fingerprint",
		}},
		{name: "aliases absent", aliases: map[string]any{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resourceAttributes := canonicalResourceAttributes()
			for key, value := range test.aliases {
				resourceAttributes[key] = value
			}
			body := map[string]any{
				"kind": "CLIENT",
				"attributes": map[string]any{
					"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
					"gen_ai.input.messages":  messages("user", "safe"),
					"gen_ai.output.messages": messages("assistant", "safe"),
				},
				"resource": map[string]any{
					"schema_url": "https://opentelemetry.io/schemas/1.42.0",
					"attributes": resourceAttributes, "dropped_attributes_count": uint32(7),
				},
			}
			record := newTraceRecord(t, observability.BucketModelIO, "span.model.chat", "chat fixture", body)
			rawProjection := redactRecord(t, record, redaction.ProfileNone)
			strictProjection := redactRecord(t, record, redaction.ProfileStrict)
			rawBefore, _ := rawProjection.Bytes()
			strictBefore, _ := strictProjection.Bytes()

			rawResult := Project(rawProjection, Limits{})
			strictResult := Project(strictProjection, Limits{})
			if !rawResult.Eligible() || !strictResult.Eligible() {
				t.Fatalf("raw=%q strict=%q", rawResult.Reason(), strictResult.Reason())
			}
			rawResource := resultWire(t, rawResult)["body"].(map[string]any)["resource"].(map[string]any)
			gotAttributes := rawResource["attributes"].(map[string]any)
			for key, want := range resourceAttributes {
				if got := gotAttributes[key]; got != want {
					t.Errorf("resource %q = %#v, want %#v", key, got, want)
				}
			}
			if got := rawResource["dropped_attributes_count"]; got != json.Number("7") {
				t.Fatalf("resource dropped_attributes_count = %#v", got)
			}
			for key := range map[string]struct{}{
				"deployment.environment": {}, "deployment.mode": {}, "defenseclaw.device.id": {},
			} {
				_, present := gotAttributes[key]
				_, wantPresent := test.aliases[key]
				if present != wantPresent {
					t.Errorf("alias %q presence = %v, want %v", key, present, wantPresent)
				}
			}
			rawAfter, _ := rawProjection.Bytes()
			strictAfter, _ := strictProjection.Bytes()
			if !bytes.Equal(rawBefore, rawAfter) || !bytes.Equal(strictBefore, strictAfter) {
				t.Fatal("resource projection mutated its source or sibling projection")
			}
		})
	}
}

func TestProjectRejectsForgedResourceAttributes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "secret key", mutate: func(attributes map[string]any) {
			attributes["resource.secret"] = "opaque"
		}},
		{name: "absolute path value", mutate: func(attributes map[string]any) {
			attributes["operator.location"] = "/private/location"
		}},
		{name: "reserved process key", mutate: func(attributes map[string]any) {
			attributes["discovery.source"] = "connector"
		}},
		{name: "non string value", mutate: func(attributes map[string]any) {
			attributes["operator.level"] = json.Number("7")
		}},
		{name: "sixty five custom attributes", mutate: func(attributes map[string]any) {
			for index := 0; index < 65; index++ {
				attributes[fmt.Sprintf("operator.extra.%02d", index)] = "x"
			}
		}},
		{name: "custom aggregate above limit", mutate: func(attributes map[string]any) {
			for index := 0; index < 17; index++ {
				attributes[fmt.Sprintf("operator.aggregate.%02d", index)] = strings.Repeat("x", 1000)
			}
		}},
		{name: "prometheus normalized collision", mutate: func(attributes map[string]any) {
			attributes["operator.profile-name"] = "one"
			attributes["operator.profile.name"] = "two"
		}},
		{name: "alias mismatch", mutate: func(attributes map[string]any) {
			attributes["deployment.environment"] = "production"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			attributes := canonicalResourceAttributes()
			test.mutate(attributes)
			projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat fixture", map[string]any{
				"kind": "CLIENT",
				"attributes": map[string]any{
					"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
					"gen_ai.input.messages":  messages("user", "safe"),
					"gen_ai.output.messages": messages("assistant", "safe"),
				},
				"resource": map[string]any{
					"schema_url": "https://opentelemetry.io/schemas/1.42.0", "attributes": attributes,
				},
			}, redaction.ProfileNone)
			before, _ := projection.Bytes()
			result := Project(projection, Limits{})
			if result.Eligible() || result.Reason() != ReasonInvalidProjection {
				t.Fatalf("result = eligible:%v reason:%q", result.Eligible(), result.Reason())
			}
			after, _ := projection.Bytes()
			if !bytes.Equal(before, after) {
				t.Fatal("rejected resource validation mutated its source projection")
			}
		})
	}
}

func TestProjectRejectsNonCanonicalResourceShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		resource map[string]any
	}{
		{name: "unknown resource member", resource: map[string]any{
			"attributes": canonicalResourceAttributes(), "future": "value",
		}},
		{name: "invalid dropped count", resource: map[string]any{
			"attributes": canonicalResourceAttributes(), "dropped_attributes_count": -1,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat fixture", map[string]any{
				"kind": "CLIENT",
				"attributes": map[string]any{
					"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
					"gen_ai.input.messages":  messages("user", "safe"),
					"gen_ai.output.messages": messages("assistant", "safe"),
				},
				"resource": test.resource,
			}, redaction.ProfileNone)
			result := Project(projection, Limits{})
			if result.Eligible() || result.Reason() != ReasonInvalidProjection {
				t.Fatalf("result = eligible:%v reason:%q", result.Eligible(), result.Reason())
			}
		})
	}
}

func TestProjectRejectsInvalidScopeDroppedCountAtCompatibilityBoundary(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat fixture", map[string]any{
		"kind": "CLIENT",
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages":  messages("user", "safe"),
			"gen_ai.output.messages": messages("assistant", "safe"),
		},
		"scope": map[string]any{
			"name": "defenseclaw.telemetry", "version": "v8-test",
			"schema_url": "https://defenseclaw.io/schemas/telemetry/v8",
			"attributes": map[string]any{
				"defenseclaw.trace.schema_version": "defenseclaw-trace-v1",
				"defenseclaw.semantic_profile":     "defenseclaw-genai-rich-v1",
			},
			"dropped_attributes_count": -1,
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if result.Eligible() || result.Reason() != ReasonInvalidProjection {
		t.Fatalf("invalid scope dropped count = eligible:%v reason:%q", result.Eligible(), result.Reason())
	}
}

func TestProjectCanarySurfaceIsExact(t *testing.T) {
	t.Parallel()
	base := func() map[string]any {
		return map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages": messages("user", "canary"), "gen_ai.output.messages": messages("assistant", "ok"),
			canaryMarkerKey: true, canaryOperationKey: canaryOperationValue, canaryDestinationKey: "galileo",
		}
	}
	valid := projectRecord(t, observability.BucketModelIO, observability.EventName(observability.TelemetryFamilyModelChat), "chat gpt-4o-mini", map[string]any{
		"kind": "CLIENT", "attributes": base(),
	}, redaction.ProfileNone)
	result := Project(valid, Limits{})
	if !result.Eligible() || result.Shape() != ShapeLLM {
		t.Fatalf("valid canary = %q/%q", result.Reason(), result.Shape())
	}
	wire := resultWire(t, result)
	if wire["bucket"] != string(observability.BucketModelIO) ||
		wire["event_name"] != observability.TelemetryFamilyModelChat {
		t.Fatalf("canonical canary identity was rewritten: %#v", wire)
	}
	for name, mutation := range map[string]func(map[string]any){
		"missing marker":      func(attributes map[string]any) { delete(attributes, canaryMarkerKey) },
		"false marker":        func(attributes map[string]any) { attributes[canaryMarkerKey] = false },
		"wrong operation tag": func(attributes map[string]any) { attributes[canaryOperationKey] = "probe" },
		"missing destination": func(attributes map[string]any) { delete(attributes, canaryDestinationKey) },
		"unstable destination": func(attributes map[string]any) {
			attributes[canaryDestinationKey] = " galileo "
		},
	} {
		t.Run(name, func(t *testing.T) {
			attributes := base()
			mutation(attributes)
			projection := projectRecord(t, observability.BucketModelIO, observability.EventName(observability.TelemetryFamilyModelChat), "chat gpt-4o-mini", map[string]any{
				"kind": "CLIENT", "attributes": attributes,
			}, redaction.ProfileNone)
			if result := Project(projection, Limits{}); result.Reason() != ReasonUnsupportedShape {
				t.Fatalf("invalid canary reason = %q", result.Reason())
			}
		})
	}
	diagnostic := projectRecord(t, observability.BucketDiagnostic, observability.EventName(observability.TelemetryFamilyDiagnosticCanary), "diagnostic canary", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{
			canaryMarkerKey: true, canaryOperationKey: canaryOperationValue, canaryDestinationKey: "galileo",
		},
	}, redaction.ProfileNone)
	if result := Project(diagnostic, Limits{}); result.Reason() != ReasonUnsupportedShape {
		t.Fatalf("ordinary diagnostic family was rewritten into release canary: %q", result.Reason())
	}
}

func TestProjectPreservesCanonicalTraceStateAndFullFlags(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketModelIO, observability.EventName(observability.TelemetryFamilyModelChat), "chat fixture", map[string]any{
		"kind": "CLIENT", "trace_state": "vendor=value", "flags": uint32(0x301),
		"attributes": map[string]any{
			"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
			"gen_ai.input.messages": messages("user", "safe"), "gen_ai.output.messages": messages("assistant", "safe"),
		},
	}, redaction.ProfileNone)
	result := Project(projection, Limits{})
	if !result.Eligible() {
		t.Fatalf("projection = %q", result.Reason())
	}
	body := resultWire(t, result)["body"].(map[string]any)
	if body["trace_state"] != "vendor=value" || body["flags"] != json.Number("769") {
		t.Fatalf("trace metadata = state:%#v flags:%#v", body["trace_state"], body["flags"])
	}

	for name, mutation := range map[string]func(map[string]any){
		"invalid trace state": func(body map[string]any) { body["trace_state"] = "Invalid=state" },
		"negative flags":      func(body map[string]any) { body["flags"] = -1 },
		"fractional flags":    func(body map[string]any) { body["flags"] = 1.5 },
	} {
		t.Run(name, func(t *testing.T) {
			body := map[string]any{
				"kind": "CLIENT", "trace_state": "vendor=value", "flags": uint32(0x101),
				"attributes": map[string]any{
					"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
					"gen_ai.input.messages": messages("user", "safe"), "gen_ai.output.messages": messages("assistant", "safe"),
				},
			}
			mutation(body)
			projection := projectRecord(t, observability.BucketModelIO, observability.EventName(observability.TelemetryFamilyModelChat), "chat fixture", body, redaction.ProfileNone)
			if result := Project(projection, Limits{}); result.Reason() != ReasonInvalidProjection {
				t.Fatalf("invalid trace metadata = %q", result.Reason())
			}
		})
	}
}

func TestProjectBoundsAreDeterministicAndFailClosed(t *testing.T) {
	t.Parallel()
	attributes := map[string]any{
		"gen_ai.operation.name": "chat", "gen_ai.provider.name": "openai",
		"gen_ai.input.messages": messagesMany(3), "gen_ai.output.messages": strings.Repeat("x", 400),
	}
	for index, key := range []string{
		"defenseclaw.agent.execution.id", "defenseclaw.agent.instance_id",
		"defenseclaw.agent.lifecycle.id", "defenseclaw.agent.parent.id",
		"defenseclaw.agent.root.id", "defenseclaw.connector.source",
		"defenseclaw.destination.app", "defenseclaw.model.request.id",
		"defenseclaw.model.response.id", "defenseclaw.operation.id",
		"defenseclaw.policy.id", "defenseclaw.policy.version",
		"defenseclaw.request.id", "defenseclaw.run.id",
		"defenseclaw.session.parent.id", "defenseclaw.session.root.id",
		"defenseclaw.turn.id", "defenseclaw.user.name", "gen_ai.agent.id",
		"gen_ai.agent.name", "gen_ai.conversation.id", "gen_ai.request.model",
		"gen_ai.response.id", "gen_ai.response.model", "user.id",
	} {
		attributes[key] = fmt.Sprintf("id-%02d-%s", index, strings.Repeat("x", 170))
	}
	for index := 0; index < 8; index++ {
		attributes[fmt.Sprintf("gen_ai.request.compatibility_extra_%02d", index)] = "must-be-dropped"
	}
	body := map[string]any{
		"kind": "CLIENT", "attributes": attributes,
		"events": []any{
			map[string]any{"name": "model.retry", "attributes": map[string]any{
				"defenseclaw.model.attempt": 1, "defenseclaw.model.retry_count": 2,
				"error.type": "timeout", "defenseclaw.evaluation.id": "e",
			}},
			map[string]any{"name": "guardrail.decision", "attributes": map[string]any{
				"defenseclaw.guardrail.decision": "allow",
			}},
		},
		"links": []any{
			map[string]any{
				"trace_id": strings.Repeat("1", 32), "span_id": strings.Repeat("3", 16),
				"attributes": map[string]any{"defenseclaw.link.relation": "correlates_with"},
			},
			map[string]any{
				"trace_id": strings.Repeat("2", 32), "span_id": strings.Repeat("4", 16),
				"attributes": map[string]any{"defenseclaw.link.relation": "derived_from"},
			},
		},
	}
	projection := projectRecord(t, observability.BucketModelIO, "span.model.chat", "chat model", body, redaction.ProfileNone)
	limits := Limits{
		MaxAttributesPerSpan: 32, MaxEventsPerSpan: 1, MaxLinksPerSpan: 1,
		MaxAttributesPerEvent: 4, MaxAttributeValueBytes: 256,
		MaxProjectedSpanBytes: 1024 * 1024, MaxMessageItems: 1,
	}
	result := Project(projection, limits)
	if !result.Eligible() {
		t.Fatalf("bounded result = %q", result.Reason())
	}
	resultBody := resultWire(t, result)["body"].(map[string]any)
	if got := len(resultBody["attributes"].(map[string]any)); got > limits.MaxAttributesPerSpan {
		t.Fatalf("attribute count = %d", got)
	}
	if got := len(resultBody["events"].([]any)); got != 1 {
		t.Fatalf("event count = %d", got)
	}
	if got := len(resultBody["links"].([]any)); got != 1 {
		t.Fatalf("link count = %d", got)
	}
	boundedAttributes := resultBody["attributes"].(map[string]any)
	if boundedAttributes["defenseclaw.telemetry.input.state"] != "truncated" {
		t.Fatalf("input state = %#v", boundedAttributes["defenseclaw.telemetry.input.state"])
	}
	if boundedAttributes["gen_ai.output.messages"] != "[]" || boundedAttributes["defenseclaw.telemetry.output.state"] != "failed_closed" {
		t.Fatalf("oversize output was not failed closed: %#v", boundedAttributes)
	}
	for _, required := range requiredAttributeKeys(shapeContract{shape: ShapeLLM}) {
		if _, ok := boundedAttributes[required]; !ok {
			t.Errorf("required attribute %q dropped", required)
		}
	}

	tooSmall := limits
	tooSmall.MaxProjectedSpanBytes = minProjectedSpanBytes
	if got := Project(projection, tooSmall); got.Reason() != ReasonProjectionTooLarge {
		t.Fatalf("oversize reason = %q", got.Reason())
	}
	invalid := limits
	invalid.MaxMessageItems = maxMessageItems + 1
	if got := Project(projection, invalid); got.Reason() != ReasonInvalidLimits {
		t.Fatalf("invalid-limit reason = %q", got.Reason())
	}
}

func TestProjectIsConcurrentDeterministicAndImmutable(t *testing.T) {
	t.Parallel()
	projection := projectRecord(t, observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent child", map[string]any{
		"kind": "INTERNAL", "attributes": map[string]any{
			"gen_ai.operation.name": "invoke_agent", "gen_ai.provider.name": "openai", "gen_ai.agent.name": "child",
			"gen_ai.input.messages": messages("user", "input"), "gen_ai.output.messages": messages("assistant", "output"),
			"defenseclaw.agent.root.id": "root", "defenseclaw.agent.parent.id": "parent",
		},
	}, redaction.ProfileNone)
	before, _ := projection.Bytes()
	want, err := Project(projection, Limits{}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, projectErr := Project(projection, Limits{}).Bytes()
			if projectErr != nil {
				errorsOut <- projectErr
				return
			}
			if !bytes.Equal(got, want) {
				errorsOut <- errors.New("non-deterministic projection")
			}
		}()
	}
	group.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Error(err)
	}
	after, _ := projection.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("source projection mutated")
	}
	copyOut, _ := Project(projection, Limits{}).Bytes()
	copyOut[0] ^= 0xff
	again, _ := Project(projection, Limits{}).Bytes()
	if !bytes.Equal(again, want) {
		t.Fatal("returned bytes alias internal state")
	}
}

func TestProjectRejectsZeroProjectionWithoutRawFallback(t *testing.T) {
	t.Parallel()
	result := Project(redaction.Projection{}, Limits{})
	if result.Reason() != ReasonInvalidProjection || result.Eligible() {
		t.Fatalf("zero projection = %q eligible=%v", result.Reason(), result.Eligible())
	}
	if result.Shape() != "" || len(result.MissingFields()) != 0 {
		t.Fatalf("zero projection retained details: shape=%q missing=%v", result.Shape(), result.MissingFields())
	}
}

func messages(role, content string) string {
	encoded, _ := json.Marshal([]map[string]string{{"role": role, "content": content}})
	return string(encoded)
}

func canonicalResourceAttributes() map[string]any {
	return map[string]any{
		"service.name":                              "defenseclaw",
		"service.version":                           "v8-test",
		"service.namespace":                         "cisco.ai-defense",
		"service.instance.id":                       "instance-1",
		"deployment.environment.name":               "test",
		"defenseclaw.instance.id":                   "instance-1",
		"defenseclaw.deployment.mode":               "gateway",
		"defenseclaw.device.public_key_fingerprint": "device-fingerprint",
		"team.owner":                                "runtime-security",
		"region.site":                               "east-lab",
	}
}

func messagesMany(count int) string {
	messages := make([]map[string]string, count)
	for index := range messages {
		messages[index] = map[string]string{"role": "user", "content": strconv.Itoa(index)}
	}
	encoded, _ := json.Marshal(messages)
	return string(encoded)
}

func projectRecord(
	t *testing.T,
	bucket observability.Bucket,
	family observability.EventName,
	spanName string,
	body map[string]any,
	profileName redaction.ProfileName,
) redaction.Projection {
	t.Helper()
	return redactRecord(t, newTraceRecord(t, bucket, family, spanName, body), profileName)
}

func newTraceRecord(
	t *testing.T,
	bucket observability.Bucket,
	family observability.EventName,
	spanName string,
	body map[string]any,
) observability.Record {
	t.Helper()
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		RecordID:  "galileo-" + strings.ReplaceAll(string(family), ".", "-"),
		Identity: observability.EventIdentity{
			Bucket: bucket, Signal: observability.SignalTraces, Name: family,
		},
		SpanName: spanName, Source: observability.SourceGateway,
		Correlation: observability.Correlation{
			RunID: "run-1", SessionID: "session-1", TurnID: "turn-1",
			TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16),
			AgentID: "agent-1", AgentInstanceID: "instance-1", ToolInvocationID: "tool-1",
		},
		Provenance: observability.Provenance{
			Producer: "gateway.trace", BinaryVersion: "v8-test",
			RegistrySchemaVersion: 1, ConfigGeneration: 7,
		},
		Body: body, FieldClasses: fieldClasses(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func redactRecord(t *testing.T, record observability.Record, profileName redaction.ProfileName) redaction.Projection {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := redaction.BuiltInProfile(profileName)
	if !ok {
		t.Fatalf("profile %q not found", profileName)
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func fieldClasses(body map[string]any) map[string]observability.FieldClass {
	classes := make(map[string]observability.FieldClass)
	var visit func(any, string, string)
	visit = func(value any, pointer, key string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				classes[pointer] = classForKey(key)
				return
			}
			keys := make([]string, 0, len(typed))
			for childKey := range typed {
				keys = append(keys, childKey)
			}
			sort.Strings(keys)
			for _, childKey := range keys {
				visit(typed[childKey], pointer+"/"+pointerToken(childKey), childKey)
			}
		case []any:
			if len(typed) == 0 {
				classes[pointer] = classForKey(key)
				return
			}
			for index, child := range typed {
				visit(child, pointer+"/"+strconv.Itoa(index), key)
			}
		default:
			classes[pointer] = classForKey(key)
		}
	}
	visit(body, "", "")
	return classes
}

func classForKey(key string) observability.FieldClass {
	lower := strings.ToLower(key)
	switch {
	case strings.Contains(lower, "message"), strings.Contains(lower, "content"),
		strings.Contains(lower, "argument"), strings.Contains(lower, "result"),
		lower == "input.value", lower == "output.value", lower == "body":
		return observability.FieldClassContent
	case strings.Contains(lower, "reason"):
		return observability.FieldClassReason
	case strings.Contains(lower, "evidence"):
		return observability.FieldClassEvidence
	case strings.Contains(lower, "secret"):
		return observability.FieldClassCredential
	default:
		return observability.FieldClassMetadata
	}
}

func pointerToken(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "~", "~0"), "/", "~1")
}

func resultWire(t *testing.T, result Result) map[string]any {
	t.Helper()
	encoded, err := result.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func resultAttributes(t *testing.T, result Result) map[string]any {
	t.Helper()
	body, ok := resultWire(t, result)["body"].(map[string]any)
	if !ok {
		t.Fatal("projected body missing")
	}
	attributes, ok := body["attributes"].(map[string]any)
	if !ok {
		t.Fatal("projected attributes missing")
	}
	return attributes
}
