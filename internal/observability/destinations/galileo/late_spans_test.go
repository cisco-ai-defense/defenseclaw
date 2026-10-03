// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func lateTestSpan(traceID, spanID, parentID byte) *tracepb.Span {
	span := &tracepb.Span{TraceId: bytes.Repeat([]byte{traceID}, 16), SpanId: bytes.Repeat([]byte{spanID}, 8)}
	if parentID != 0 {
		span.ParentSpanId = bytes.Repeat([]byte{parentID}, 8)
	}
	span.Attributes = []*commonpb.KeyValue{{Key: "metadata", Value: &commonpb.AnyValue{
		Value: &commonpb.AnyValue_StringValue{StringValue: `{"defenseclaw.user.name":"alice"}`}}}}
	return span
}

// GAP-2045: Galileo drops spans that arrive after the request carrying their
// trace root, so a tool span that ends after its OpenClaw turn's root was
// sent becomes the root of its own Galileo trace naming the original one.
func TestGalileoLateSpanOfAClosedTraceBecomesItsOwnTrace(t *testing.T) {
	roots := newGalileoRootedTraces()
	agent, chat, quickTool := lateTestSpan(1, 1, 0), lateTestSpan(1, 2, 1), lateTestSpan(1, 3, 2)
	pending := lateTestSpan(2, 7, 0) // another turn: its child arrives first
	pendingChild := lateTestSpan(2, 8, 7)
	roots.reRootLateSpans([]*tracepb.Span{pendingChild}, nil)
	roots.reRootLateSpans([]*tracepb.Span{agent, chat, quickTool}, nil)
	roots.reRootLateSpans([]*tracepb.Span{pending}, nil)
	turn, other := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	for _, span := range []*tracepb.Span{agent, chat, quickTool} {
		if !bytes.Equal(span.TraceId, turn) {
			t.Fatalf("a span sent with its trace root changed trace: %x", span.TraceId)
		}
	}
	if !bytes.Equal(pending.TraceId, other) || !bytes.Equal(pendingChild.TraceId, other) {
		t.Fatal("a span sent before its trace root changed trace")
	}
	if !bytes.Equal(quickTool.ParentSpanId, chat.SpanId) || !bytes.Equal(pendingChild.ParentSpanId, pending.SpanId) {
		t.Fatal("a span sent with or before its trace root lost its parent")
	}

	slowTool, toolChild := lateTestSpan(1, 4, 2), lateTestSpan(1, 5, 4)
	roots.reRootLateSpans([]*tracepb.Span{slowTool, toolChild}, nil)
	if bytes.Equal(slowTool.TraceId, agent.TraceId) || len(slowTool.ParentSpanId) != 0 {
		t.Fatalf("late span still joins the closed trace: trace=%x parent=%x", slowTool.TraceId, slowTool.ParentSpanId)
	}
	if !bytes.Equal(toolChild.TraceId, slowTool.TraceId) || !bytes.Equal(toolChild.ParentSpanId, slowTool.SpanId) {
		t.Fatal("a late span's own child left its subtree")
	}
	var metadata map[string]string
	if err := json.Unmarshal([]byte(slowTool.Attributes[0].GetValue().GetStringValue()), &metadata); err != nil ||
		metadata[galileoLateSpanTraceMetadataKey] != hex.EncodeToString(agent.TraceId) || metadata["defenseclaw.user.name"] != "alice" {
		t.Fatalf("late span metadata=%v err=%v", metadata, err)
	}
	again := lateTestSpan(1, 4, 2)
	roots.reRootLateSpans([]*tracepb.Span{again}, map[string]bool{})
	if !bytes.Equal(again.TraceId, slowTool.TraceId) {
		t.Fatal("a retried late span got a different trace ID")
	}
	// A retry of the root's own request keeps the whole trace.
	retried := []*tracepb.Span{lateTestSpan(1, 1, 0), lateTestSpan(1, 2, 1), lateTestSpan(1, 3, 2)}
	roots.reRootLateSpans(retried, nil)
	for _, span := range retried {
		if !bytes.Equal(span.TraceId, turn) {
			t.Fatal("a retried root request was rewritten")
		}
	}
	canary := lateTestSpan(1, 6, 2)
	roots.reRootLateSpans([]*tracepb.Span{canary}, map[string]bool{hex.EncodeToString(canary.TraceId): true})
	if !bytes.Equal(canary.TraceId, turn) {
		t.Fatal("a canary span was rewritten")
	}
}
