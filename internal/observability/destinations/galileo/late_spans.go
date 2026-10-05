// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// Galileo's OTLP ingest closes a trace when the request that carries its root
// span is ingested. A later request with more spans of that trace is answered
// with success, but those spans are dropped (a root span is refused as a
// duplicate). An OpenClaw turn's zero-duration invoke_agent root is sent as
// soon as the model message arrives, so a tool call that runs for a few
// seconds ends after its trace was closed and never reached Galileo, while
// Tempo had it (GAP-2045).
//
// The workaround: a span whose trace root went out in an earlier request, and
// whose parent is not in this request, is sent as the root of its own Galileo
// trace. Its trace ID is derived from the original trace and span IDs (stable
// across retries), and its metadata names the original trace
// (defenseclaw.trace.id) so the turn can still be found. Other destinations
// are unchanged.

const (
	galileoLateSpanTraceMetadataKey = "defenseclaw.trace.id"
	galileoRootedTraceMemory        = 4096
)

// galileoRootedTraces remembers, bounded and oldest first out, the traces
// whose root span this destination already sent.
type galileoRootedTraces struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
}

func newGalileoRootedTraces() *galileoRootedTraces {
	return &galileoRootedTraces{seen: make(map[string]struct{})}
}

func (roots *galileoRootedTraces) rememberLocked(traceID string) {
	if _, ok := roots.seen[traceID]; ok {
		return
	}
	if len(roots.order) >= galileoRootedTraceMemory {
		delete(roots.seen, roots.order[0])
		roots.order = roots.order[1:]
	}
	roots.seen[traceID] = struct{}{}
	roots.order = append(roots.order, traceID)
}

// reRootLateSpans rewrites, in place, the spans of one request that would
// join a trace Galileo has already closed. skip names traces that must not
// change (telemetry canaries).
func (roots *galileoRootedTraces) reRootLateSpans(spans []*tracepb.Span, skip map[string]bool) {
	if roots == nil || len(spans) == 0 {
		return
	}
	type spanKey struct{ trace, span string }
	inRequest := make(map[spanKey]*tracepb.Span, len(spans))
	for _, span := range spans {
		inRequest[spanKey{hex.EncodeToString(span.TraceId), hex.EncodeToString(span.SpanId)}] = span
	}
	type plan struct {
		span    *tracepb.Span
		top     bool
		traceID []byte
		origin  string
	}
	roots.mu.Lock()
	defer roots.mu.Unlock()
	plans := make([]plan, 0)
	rootedNow := make([]string, 0)
	for _, span := range spans {
		traceID := hex.EncodeToString(span.TraceId)
		if len(span.ParentSpanId) == 0 {
			rootedNow = append(rootedNow, traceID)
			continue
		}
		if skip[traceID] {
			continue
		}
		if _, closed := roots.seen[traceID]; !closed {
			continue
		}
		// Walk up to the highest ancestor in this request. If it is the
		// trace root (a retry of the root's own request), nothing changes.
		top := span
		for steps := 0; steps < len(spans) && len(top.ParentSpanId) > 0; steps++ {
			parent, ok := inRequest[spanKey{traceID, hex.EncodeToString(top.ParentSpanId)}]
			if !ok {
				break
			}
			top = parent
		}
		if len(top.ParentSpanId) == 0 {
			continue
		}
		plans = append(plans, plan{
			span: span, top: top == span, origin: traceID,
			traceID: galileoLateSpanTraceID(span.TraceId, top.SpanId),
		})
	}
	for _, change := range plans {
		change.span.TraceId = change.traceID
		if change.top {
			change.span.ParentSpanId = nil
			setGalileoLateSpanOrigin(change.span, change.origin)
		}
	}
	for _, traceID := range rootedNow {
		roots.rememberLocked(traceID)
	}
}

func galileoLateSpanTraceID(traceID, spanID []byte) []byte {
	digest := sha256.New()
	digest.Write([]byte("defenseclaw-galileo-late-span\x00"))
	digest.Write(traceID)
	digest.Write(spanID)
	derived := digest.Sum(nil)[:16]
	derived[0] |= 0x01 // never the invalid all-zero trace ID
	return derived
}

// setGalileoLateSpanOrigin adds the original trace ID to the OpenInference
// metadata attribute, which Galileo shows as the span's metadata.
func setGalileoLateSpanOrigin(span *tracepb.Span, origin string) {
	for _, attribute := range span.Attributes {
		if attribute.GetKey() != "metadata" {
			continue
		}
		metadata := map[string]any{}
		if text := attribute.GetValue().GetStringValue(); text != "" {
			if json.Unmarshal([]byte(text), &metadata) != nil {
				return
			}
		}
		metadata[galileoLateSpanTraceMetadataKey] = origin
		if encoded, err := json.Marshal(metadata); err == nil {
			attribute.Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(encoded)}}
		}
		return
	}
	encoded, err := json.Marshal(map[string]string{galileoLateSpanTraceMetadataKey: origin})
	if err != nil {
		return
	}
	span.Attributes = append(span.Attributes, &commonpb.KeyValue{
		Key: "metadata", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(encoded)}},
	})
}
