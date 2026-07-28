// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"encoding/hex"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

func TestProjectCanonicalLogFieldsPromotesCorrelationWithoutChangingTopology(t *testing.T) {
	record := &logspb.LogRecord{Attributes: []*commonpb.KeyValue{stringAttribute("defenseclaw.record.id", "record-1")}}
	projected := []byte(`{
		"timestamp":"2026-07-14T12:00:00Z",
		"log_level":"INFO",
		"correlation":{
			"semantic_event_id":"semantic-1",
			"logical_event_id":"logical-1",
			"connector_instance_id":"connector-instance-1",
			"request_id":"transport-request-1",
			"turn_id":"turn-1",
			"model_request_id":"model-request-1",
			"model_response_id":"model-response-1",
			"tool_invocation_id":"tool-1",
			"trace_id":"0123456789abcdef0123456789abcdef",
			"span_id":"0123456789abcdef"
		}
	}`)
	if !projectCanonicalLogFields(record, projected) {
		t.Fatal("canonical log correlation projection rejected")
	}
	if got := hex.EncodeToString(record.TraceId); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("trace id=%s", got)
	}
	if got := hex.EncodeToString(record.SpanId); got != "0123456789abcdef" {
		t.Fatalf("span id=%s", got)
	}
	attributes := keyValuesByName(record.Attributes)
	for key, want := range map[string]string{
		"defenseclaw.semantic_event.id":     "semantic-1",
		"defenseclaw.logical_event.id":      "logical-1",
		"defenseclaw.connector.instance.id": "connector-instance-1",
	} {
		if got := attributes[key].GetStringValue(); got != want {
			t.Fatalf("attribute %s=%q, want %q", key, got, want)
		}
	}
	// The common destination overlay is deliberately occurrence-scoped. Raw
	// provider/session/work IDs remain inside the already-redacted canonical
	// body (or their registered family attributes); they must not be promoted
	// into a second, ungoverned OTLP attribute namespace here.
	for _, key := range []string{
		"defenseclaw.request.id",
		"defenseclaw.turn.id",
		"defenseclaw.model.request.id",
		"gen_ai.response.id",
		"gen_ai.tool.call.id",
	} {
		if _, present := attributes[key]; present {
			t.Fatalf("provider business identity %q was promoted by the common overlay", key)
		}
	}
}

func TestCanonicalCorrelationProjectionRejectsConflictingBodyAttribute(t *testing.T) {
	_, ok := withCanonicalCorrelationAttributes(
		map[string]any{"defenseclaw.semantic_event.id": "body-semantic"},
		map[string]any{"semantic_event_id": "envelope-semantic"},
	)
	if ok {
		t.Fatal("conflicting body and envelope correlation was accepted")
	}
}
