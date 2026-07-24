// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// otlpGeneratedTraceRuntime is deliberately separate from the log and metric
// capabilities. Minimal emitters remain valid test/control-plane bindings, but
// production receive/normalize spans are created only by the generation-owned
// runtime that can hold one lease across the complete hierarchy.
type otlpGeneratedTraceRuntime interface {
	StartTelemetryReceiveTrace(
		context.Context,
		observability.SpanTelemetryReceiveInput,
	) (context.Context, *observabilityruntime.TelemetryReceiveTrace, error)
}

type otlpIngestTraceV8 struct {
	receive      *observabilityruntime.TelemetryReceiveTrace
	normalize    *observabilityruntime.TelemetryNormalizeTrace
	receiveInput observability.SpanTelemetryReceiveInput
	normalInput  observability.SpanTelemetryNormalizeInput
	receiveStart time.Time
	normalStart  time.Time
}

type otlpIngestTraceResult struct {
	outcome         observability.Outcome
	statusCode      int64
	payloadFormat   string
	reasonClass     string
	errorType       string
	records         int64
	resources       int64
	wireBytes       int64
	normalizedBytes int64
	hasWireBytes    bool
	hasNormalized   bool
	hasSummary      bool
	technical       bool
}

func (a *APIServer) startOTLPIngestTraceV8(
	ctx context.Context,
	r *http.Request,
	signal otelIngestSignal,
	connector string,
	started time.Time,
) (context.Context, *otlpIngestTraceV8) {
	runtime, ok := a.observabilityV8RuntimeEmitter().(otlpGeneratedTraceRuntime)
	if !ok || runtime == nil || ctx == nil || r == nil {
		return ctx, nil
	}
	input := observability.SpanTelemetryReceiveInput{
		Envelope: otlpIngestTraceEnvelope(ctx, signal, connector, "receive"),
		Outcome:  observability.OutcomeAttempted, Kind: "SERVER",
		StartTimeUnixNano:          uint64(started.UnixNano()),
		Status:                     observability.NewTraceStatusUnset(),
		HTTPRequestMethod:          r.Method,
		DefenseClawTelemetrySignal: observability.Present(string(signal)),
		NetworkProtocolName:        observability.Present("http"),
		ConditionConnectorKnown:    connector != "" && connector != "unknown",
	}
	if r.ProtoMajor > 0 {
		input.NetworkProtocolVersion = observability.Present(fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor))
	}
	if input.ConditionConnectorKnown {
		input.DefenseClawConnectorSource = observability.Present(connector)
	}
	if runID := gatewaylog.ProcessRunID(); runID != "" {
		input.DefenseClawRunID = observability.Present(runID)
	}
	startedContext, receive, err := runtime.StartTelemetryReceiveTrace(ctx, input)
	if err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical receive trace unavailable")
		return ctx, nil
	}
	if receive == nil {
		return startedContext, nil
	}
	return startedContext, &otlpIngestTraceV8{
		receive: receive, receiveInput: input, receiveStart: started,
	}
}

func (trace *otlpIngestTraceV8) startNormalize(
	ctx context.Context,
	signal otelIngestSignal,
	connector string,
	started time.Time,
) {
	if trace == nil || trace.receive == nil || trace.normalize != nil {
		return
	}
	input := observability.SpanTelemetryNormalizeInput{
		Envelope: otlpIngestTraceEnvelope(ctx, signal, connector, "normalization"),
		Outcome:  observability.OutcomeAttempted, Kind: "INTERNAL",
		StartTimeUnixNano:          uint64(started.UnixNano()),
		Status:                     observability.NewTraceStatusUnset(),
		DefenseClawTelemetrySignal: string(signal),
		ConditionConnectorKnown:    connector != "" && connector != "unknown",
	}
	if input.ConditionConnectorKnown {
		input.DefenseClawConnectorSource = observability.Present(connector)
	}
	if runID := gatewaylog.ProcessRunID(); runID != "" {
		input.DefenseClawRunID = observability.Present(runID)
	}
	normalize, err := trace.receive.StartNormalize(input)
	if err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical normalize trace unavailable")
		trace.receive.Abort()
		trace.receive = nil
		return
	}
	trace.normalize = normalize
	trace.normalInput = input
	trace.normalStart = started
}

func (trace *otlpIngestTraceV8) refreshCorrelation(ctx context.Context, connector string) {
	if trace == nil || ctx == nil {
		return
	}
	correlation := otlpIngestCorrelation(ctx, connector)
	trace.receiveInput.Envelope.Correlation = correlation
	trace.normalInput.Envelope.Correlation = correlation
}

func otlpIngestTraceEnvelope(
	ctx context.Context,
	signal otelIngestSignal,
	connector string,
	phase string,
) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceOTelReceiver, Connector: connector,
		Action: string(otlpIngestProducerKey(signal)), Phase: phase,
		Correlation: otlpIngestCorrelation(ctx, connector),
		Provenance:  observability.FamilyProvenanceInput{Producer: "defenseclaw"},
	}
}

func (trace *otlpIngestTraceV8) finishNormalize(result otlpIngestTraceResult) {
	if trace == nil || trace.normalize == nil {
		return
	}
	input := trace.normalInput
	input.Outcome = result.outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = otlpIngestTraceStatus(result)
	input.ConditionOperationTerminal = true
	input.ConditionTechnicalFailure = result.technical
	applyOTLPNormalizeTraceFacts(&input, result, time.Since(trace.normalStart))
	if err := trace.normalize.End(input); err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical normalize trace completion failed")
		trace.receive = nil // a failed generated child aborts the complete session
	}
	trace.normalize = nil
}

func (trace *otlpIngestTraceV8) finishReceive(result otlpIngestTraceResult) {
	if trace == nil || trace.receive == nil {
		return
	}
	if trace.normalize != nil {
		trace.abort()
		return
	}
	input := trace.receiveInput
	input.Outcome = result.outcome
	input.EndTimeUnixNano = uint64(time.Now().UTC().UnixNano())
	input.Status = otlpIngestTraceStatus(result)
	input.HTTPResponseStatusCode = observability.Present(result.statusCode)
	input.ConditionOperationTerminal = true
	input.ConditionTechnicalFailure = result.technical
	applyOTLPReceiveTraceFacts(&input, result, time.Since(trace.receiveStart))
	if err := trace.receive.End(input); err != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical receive trace completion failed")
	}
	trace.receive = nil
}

func (trace *otlpIngestTraceV8) abort() {
	if trace == nil {
		return
	}
	if trace.receive != nil {
		trace.receive.Abort()
	} else if trace.normalize != nil {
		trace.normalize.Abort()
	}
	trace.receive = nil
	trace.normalize = nil
}

func otlpIngestTraceStatus(result otlpIngestTraceResult) observability.TraceStatusInput {
	if result.outcome == observability.OutcomeCompleted && !result.technical {
		return observability.NewTraceStatusOK()
	}
	return observability.NewTraceStatusError(observability.Absent[string]())
}

func applyOTLPReceiveTraceFacts(
	input *observability.SpanTelemetryReceiveInput,
	result otlpIngestTraceResult,
	latency time.Duration,
) {
	if input == nil {
		return
	}
	input.DefenseClawTelemetryLatencyMs = observability.Present(nonnegativeMilliseconds(latency))
	if result.payloadFormat != "" {
		input.DefenseClawTelemetryPayloadFormat = observability.Present(result.payloadFormat)
	}
	if result.reasonClass != "" {
		input.DefenseClawTelemetryRejectionReasonClass = observability.Present(result.reasonClass)
	}
	if result.errorType != "" {
		input.ErrorType = observability.Present(result.errorType)
	}
	if result.hasWireBytes {
		input.DefenseClawTelemetryWireBytes = observability.Present(result.wireBytes)
		input.DefenseClawTelemetryByteCount = observability.Present(result.wireBytes)
	}
	if result.hasNormalized {
		input.DefenseClawTelemetryNormalizedBytes = observability.Present(result.normalizedBytes)
	}
	if result.hasSummary {
		input.DefenseClawTelemetryRecordCount = observability.Present(result.records)
		input.DefenseClawTelemetryResourceCount = observability.Present(result.resources)
	}
}

func applyOTLPNormalizeTraceFacts(
	input *observability.SpanTelemetryNormalizeInput,
	result otlpIngestTraceResult,
	latency time.Duration,
) {
	if input == nil {
		return
	}
	input.DefenseClawTelemetryLatencyMs = observability.Present(nonnegativeMilliseconds(latency))
	if result.payloadFormat != "" {
		input.DefenseClawTelemetryPayloadFormat = observability.Present(result.payloadFormat)
	}
	if result.reasonClass != "" {
		input.DefenseClawTelemetryRejectionReasonClass = observability.Present(result.reasonClass)
	}
	if result.errorType != "" {
		input.ErrorType = observability.Present(result.errorType)
	}
	if result.hasWireBytes {
		input.DefenseClawTelemetryWireBytes = observability.Present(result.wireBytes)
		input.DefenseClawTelemetryByteCount = observability.Present(result.wireBytes)
	}
	if result.hasNormalized {
		input.DefenseClawTelemetryNormalizedBytes = observability.Present(result.normalizedBytes)
	}
	if result.hasSummary {
		input.DefenseClawTelemetryRecordCount = observability.Present(result.records)
		input.DefenseClawTelemetryResourceCount = observability.Present(result.resources)
	}
}

func nonnegativeMilliseconds(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	return duration.Milliseconds()
}

var (
	_ otlpGeneratedTraceRuntime = (*observabilityruntime.Runtime)(nil)
	_ otlpGeneratedTraceRuntime = (*sidecarOwnedObservabilityV8Runtime)(nil)
)
