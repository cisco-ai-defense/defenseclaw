// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	tracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	tracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

// NewSpanExporter returns a single generation-owned exporter with guarded
// dialing. It applies no bucket/vendor filter; the complete routed general OTLP
// span graph reaches this exporter unchanged.
func (factory *Factory) NewSpanExporter(ctx context.Context) (*SpanExporter, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalTraces)
	if err != nil {
		return nil, err
	}
	if config.protocol == ProtocolHTTP {
		initialRetry, maximumRetry := retryBounds(config.timeout)
		client, transport := newHTTPClient(config)
		exporter, buildErr := tracehttp.New(ctx,
			tracehttp.WithEndpointURL(signalURL(config)),
			tracehttp.WithURLPath(config.path),
			tracehttp.WithHeaders(cloneHeaders(config.headers)),
			tracehttp.WithTimeout(config.timeout),
			tracehttp.WithCompression(tracehttp.NoCompression),
			tracehttp.WithRetry(tracehttp.RetryConfig{
				Enabled: true, InitialInterval: initialRetry,
				MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
			}),
			tracehttp.WithHTTPClient(client),
		)
		if buildErr != nil {
			closeHTTPTransport(transport)
			return nil, newError(ErrorInitialization, buildErr)
		}
		return &SpanExporter{
			inner: exporter, httpTransport: transport, maxBytes: factory.config.Batch.MaxExportBatchBytes,
			config: config, destination: factory.config.Destination,
		}, nil
	}
	connection, err := newGRPCConnection(config)
	if err != nil {
		return nil, err
	}
	initialRetry, maximumRetry := retryBounds(config.timeout)
	exporter, buildErr := tracegrpc.New(ctx,
		tracegrpc.WithGRPCConn(connection),
		tracegrpc.WithHeaders(cloneHeaders(config.headers)),
		tracegrpc.WithTimeout(config.timeout),
		tracegrpc.WithRetry(tracegrpc.RetryConfig{
			Enabled: true, InitialInterval: initialRetry,
			MaxInterval: maximumRetry, MaxElapsedTime: config.timeout,
		}),
	)
	if buildErr != nil {
		_ = connection.Close()
		return nil, newError(ErrorInitialization, buildErr)
	}
	return &SpanExporter{
		inner: exporter, connection: connection, maxBytes: factory.config.Batch.MaxExportBatchBytes,
		config: config, destination: factory.config.Destination,
	}, nil
}

// NewBatchSpanProcessor is the uncoupled telemetry-provider integration seam.
// Calling it is the explicit point at which the SDK batch worker is started.
func (factory *Factory) NewBatchSpanProcessor(ctx context.Context) (sdktrace.SpanProcessor, error) {
	exporter, err := factory.NewSpanExporter(ctx)
	if err != nil {
		return nil, err
	}
	batch := factory.config.Batch
	if batch.MaxQueueSize <= 0 || batch.MaxExportBatchSize <= 0 ||
		batch.MaxExportBatchSize > batch.MaxQueueSize || batch.ScheduledDelay <= 0 {
		cleanup, cancel := cleanupContext(ctx, factory.config.Timeout)
		_ = exporter.Shutdown(cleanup)
		cancel()
		return nil, newError(ErrorInvalidConfig, nil)
	}
	return newBoundedSpanProcessor(exporter, batch), nil
}

// SpanFilter is evaluated against an immutable ended span before it enters a
// destination queue. False and panics fail closed without retaining the span.
type SpanFilter func(sdktrace.ReadOnlySpan) bool

// NewFilteredBatchSpanProcessor creates one destination-owned processor whose
// route predicate runs before queue count/byte charging.
func (factory *Factory) NewFilteredBatchSpanProcessor(ctx context.Context, filter SpanFilter) (sdktrace.SpanProcessor, error) {
	if filter == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	processor, err := factory.NewBatchSpanProcessor(ctx)
	if err != nil {
		return nil, err
	}
	return &filteredSpanProcessor{inner: processor, filter: filter}, nil
}

type filteredSpanProcessor struct {
	inner  sdktrace.SpanProcessor
	filter SpanFilter
}

func (processor *filteredSpanProcessor) OnStart(ctx context.Context, span sdktrace.ReadWriteSpan) {
	// The bounded processor currently owns no start-time state, but delegate to
	// preserve the SpanProcessor contract if that implementation evolves.
	processor.inner.OnStart(ctx, span)
}

func (processor *filteredSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	allowed := false
	func() {
		defer func() { _ = recover() }()
		allowed = processor.filter(span)
	}()
	if allowed {
		processor.inner.OnEnd(span)
	}
}

func (processor *filteredSpanProcessor) ForceFlush(ctx context.Context) error {
	return processor.inner.ForceFlush(ctx)
}

func (processor *filteredSpanProcessor) Shutdown(ctx context.Context) error {
	return processor.inner.Shutdown(ctx)
}

func (processor *filteredSpanProcessor) TerminalDone() <-chan struct{} {
	if terminal, ok := processor.inner.(interface{ TerminalDone() <-chan struct{} }); ok {
		return terminal.TerminalDone()
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

type SpanExporter struct {
	inner         sdktrace.SpanExporter
	connection    *grpc.ClientConn
	httpTransport *http.Transport
	config        signalConfig
	destination   string
	maxBytes      int
	counters      mutableCounters
	mu            sync.RWMutex
	closed        bool
}

func (exporter *SpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if exporter == nil || ctx == nil {
		return newError(ErrorExport, nil)
	}
	exporter.mu.RLock()
	closed := exporter.closed
	defer exporter.mu.RUnlock()
	if closed {
		return newError(ErrorExport, nil)
	}
	spans = canarySpansForOTLPDestination(spans, exporter.destination)
	regular, canaries := partitionOTLPCanarySpans(spans)
	var exportErrors []error
	if len(regular) > 0 {
		if err := exporter.exportBatch(ctx, regular, ""); err != nil {
			exportErrors = append(exportErrors, err)
		}
	}
	for _, canary := range canaries {
		traceID := completeOTLPCanaryTrace(canary, exporter.destination)
		if err := exporter.exportBatch(ctx, canary, traceID); err != nil {
			exportErrors = append(exportErrors, err)
		}
	}
	return errors.Join(exportErrors...)
}

func completeOTLPCanaryTrace(spans []sdktrace.ReadOnlySpan, destination string) string {
	if len(spans) != 2 {
		return ""
	}
	if !observability.IsStableToken(destination) {
		return ""
	}
	traceID := spans[0].SpanContext().TraceID()
	if !traceID.IsValid() || spans[1].SpanContext().TraceID() != traceID {
		return ""
	}
	var root, child sdktrace.ReadOnlySpan
	var rootContract, childContract otlpCanaryContract
	for _, span := range spans {
		contract, valid := otlpGeneratedCanaryContract(span, destination)
		if !valid {
			return ""
		}
		switch contract.family {
		case observability.TelemetryFamilyAgentInvoke:
			if root != nil {
				return ""
			}
			root = span
			rootContract = contract
		case observability.TelemetryFamilyModelChat:
			if child != nil {
				return ""
			}
			child = span
			childContract = contract
		default:
			return ""
		}
	}
	if root == nil || child == nil || rootContract.generation != childContract.generation ||
		root.Name() != "invoke_agent diagnostic" ||
		child.Name() != "chat gpt-4o-mini" || root.SpanKind() != trace.SpanKindInternal ||
		child.SpanKind() != trace.SpanKindClient || root.Status().Code != codes.Ok ||
		child.Status().Code != codes.Ok || root.Parent().IsValid() ||
		root.SpanContext().SpanID() == child.SpanContext().SpanID() {
		return ""
	}
	rootContext, childContext, parent := root.SpanContext(), child.SpanContext(), child.Parent()
	if rootContext.IsRemote() || childContext.IsRemote() || !rootContext.IsSampled() ||
		!childContext.IsSampled() || rootContext.TraceFlags() != trace.FlagsSampled ||
		childContext.TraceFlags() != trace.FlagsSampled ||
		rootContext.TraceState().String() != childContext.TraceState().String() ||
		!parent.IsValid() || parent.IsRemote() || parent.TraceID() != traceID ||
		parent.SpanID() != rootContext.SpanID() ||
		parent.TraceFlags() != rootContext.TraceFlags() ||
		parent.TraceState().String() != rootContext.TraceState().String() {
		return ""
	}
	rootResource, rootSchema, valid := otlpCanonicalResource(root)
	if !valid {
		return ""
	}
	childResource, childSchema, valid := otlpCanonicalResource(child)
	if !valid || rootSchema != childSchema || !reflect.DeepEqual(rootResource, childResource) ||
		!otlpCanonicalScopeEqual(root, child) {
		return ""
	}
	return traceID.String()
}

type otlpCanaryContract struct {
	family     string
	generation int64
}

func otlpGeneratedCanaryContract(span sdktrace.ReadOnlySpan, destination string) (otlpCanaryContract, bool) {
	if span == nil {
		return otlpCanaryContract{}, false
	}
	values := make(map[string]attribute.Value, 10)
	for _, item := range span.Attributes() {
		key := string(item.Key)
		switch key {
		case "defenseclaw.bucket", "defenseclaw.span.family", "defenseclaw.span.family_schema_version",
			"defenseclaw.config.generation", "defenseclaw.source", "defenseclaw.outcome",
			"defenseclaw.telemetry.canary", "defenseclaw.telemetry.canary.operation",
			"defenseclaw.telemetry.canary.destination", "gen_ai.operation.name":
			if _, duplicate := values[key]; duplicate {
				return otlpCanaryContract{}, false
			}
			values[key] = item.Value
		}
	}
	family, ok := otlpStringAttribute(values, "defenseclaw.span.family")
	if !ok {
		return otlpCanaryContract{}, false
	}
	expectedBucket, expectedOperation := "", ""
	switch family {
	case observability.TelemetryFamilyAgentInvoke:
		expectedBucket, expectedOperation = string(observability.BucketAgentLifecycle), "invoke_agent"
	case observability.TelemetryFamilyModelChat:
		expectedBucket, expectedOperation = string(observability.BucketModelIO), "chat"
	default:
		return otlpCanaryContract{}, false
	}
	bucket, bucketOK := otlpStringAttribute(values, "defenseclaw.bucket")
	operation, operationOK := otlpStringAttribute(values, "gen_ai.operation.name")
	canaryOperation, canaryOperationOK := otlpStringAttribute(values, "defenseclaw.telemetry.canary.operation")
	target, targetOK := otlpStringAttribute(values, "defenseclaw.telemetry.canary.destination")
	source, sourceOK := otlpStringAttribute(values, "defenseclaw.source")
	outcome, outcomeOK := otlpStringAttribute(values, "defenseclaw.outcome")
	marker, markerOK := values["defenseclaw.telemetry.canary"]
	familyVersion, familyVersionOK := values["defenseclaw.span.family_schema_version"]
	generation, generationOK := values["defenseclaw.config.generation"]
	if !bucketOK || bucket != expectedBucket || !operationOK || operation != expectedOperation ||
		!canaryOperationOK || canaryOperation != "runtime-pipeline-test" ||
		!targetOK || target != destination || !observability.IsStableToken(target) ||
		!sourceOK || !observability.IsStableToken(source) || !outcomeOK || outcome != string(observability.OutcomeCompleted) ||
		!markerOK || marker.Type() != attribute.BOOL || !marker.AsBool() ||
		!familyVersionOK || familyVersion.Type() != attribute.INT64 || familyVersion.AsInt64() <= 0 ||
		!generationOK || generation.Type() != attribute.INT64 || generation.AsInt64() < 0 {
		return otlpCanaryContract{}, false
	}
	return otlpCanaryContract{family: family, generation: generation.AsInt64()}, true
}

func otlpStringAttribute(values map[string]attribute.Value, key string) (string, bool) {
	value, ok := values[key]
	if !ok || value.Type() != attribute.STRING {
		return "", false
	}
	return value.AsString(), true
}

func otlpCanonicalResource(span sdktrace.ReadOnlySpan) (map[string]string, string, bool) {
	resource := span.Resource()
	if resource == nil || strings.TrimSpace(resource.SchemaURL()) == "" {
		return nil, "", false
	}
	values := make(map[string]string)
	validation := make(map[string]any)
	for _, item := range resource.Attributes() {
		key := string(item.Key)
		if key == "" || item.Value.Type() != attribute.STRING {
			return nil, "", false
		}
		if _, duplicate := values[key]; duplicate {
			return nil, "", false
		}
		values[key] = item.Value.AsString()
		validation[key] = item.Value.AsString()
	}
	if observability.ValidateTelemetryResourceAttributes(validation) != nil {
		return nil, "", false
	}
	return values, resource.SchemaURL(), true
}

func otlpCanonicalScopeEqual(root, child sdktrace.ReadOnlySpan) bool {
	rootScope, childScope := root.InstrumentationScope(), child.InstrumentationScope()
	if rootScope.Name != "defenseclaw.telemetry" || rootScope.Version == "" || rootScope.SchemaURL == "" ||
		rootScope.Name != childScope.Name || rootScope.Version != childScope.Version || rootScope.SchemaURL != childScope.SchemaURL ||
		!rootScope.Attributes.Equals(&childScope.Attributes) {
		return false
	}
	values := make(map[string]attribute.Value)
	for _, item := range rootScope.Attributes.ToSlice() {
		values[string(item.Key)] = item.Value
	}
	traceSchema, traceOK := otlpStringAttribute(values, "defenseclaw.trace.schema_version")
	semanticProfile, semanticOK := otlpStringAttribute(values, "defenseclaw.semantic_profile")
	return len(values) == 2 && traceOK && traceSchema == observability.RuntimeTraceSchemaVersion &&
		semanticOK && semanticProfile == observability.RuntimeSemanticProfileID
}

func (exporter *SpanExporter) exportBatch(ctx context.Context, spans []sdktrace.ReadOnlySpan, canaryTraceID string) error {
	total := 0
	for _, span := range spans {
		bound, ok := conservativeSpanBytes(span)
		if !ok || bound > exporter.maxBytes-total {
			exporter.counters.rejectedOversize.Add(uint64(len(spans)))
			observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeRejectedOversize, Count: uint64(len(spans))})
			return newError(ErrorExport, nil)
		}
		total += bound
	}
	exporter.counters.accepted.Add(uint64(len(spans)))
	dialSequence := exporter.config.tracker.snapshot()
	attemptContext, attempts := withAttemptCounter(ctx)
	err := exporter.inner.ExportSpans(attemptContext, spans)
	recordRetryAttempts(&exporter.counters, exporter.config.observer, observability.SignalTraces, uint64(len(spans)), attempts.Load())
	if err != nil {
		exporter.counters.failed.Add(uint64(len(spans)))
		observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeExportFailed, Count: uint64(len(spans))})
		if exporter.config.tracker.unsafeSince(dialSequence) {
			return newError(ErrorUnsafeEndpoint, err)
		}
		return newError(ErrorExport, err)
	}
	exporter.counters.exported.Add(uint64(len(spans)))
	observe(exporter.config.observer, SignalEvent{Signal: observability.SignalTraces, Outcome: SignalOutcomeExported, Count: uint64(len(spans))})
	if canaryTraceID != "" {
		observeCanaryAcknowledgement(exporter.config.canary, CanaryAcknowledgement{
			Destination: exporter.destination, TraceID: canaryTraceID,
		})
	}
	return nil
}

func canarySpansForOTLPDestination(spans []sdktrace.ReadOnlySpan, destination string) []sdktrace.ReadOnlySpan {
	filtered := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		target := otlpCanaryDestination(span)
		if span != nil && (target == "" || target == destination) {
			filtered = append(filtered, span)
		}
	}
	return filtered
}

func partitionOTLPCanarySpans(spans []sdktrace.ReadOnlySpan) ([]sdktrace.ReadOnlySpan, [][]sdktrace.ReadOnlySpan) {
	regular := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	byTrace := make(map[string][]sdktrace.ReadOnlySpan)
	order := make([]string, 0)
	for _, span := range spans {
		if !isOTLPCanarySpan(span) {
			regular = append(regular, span)
			continue
		}
		traceID := span.SpanContext().TraceID().String()
		if _, exists := byTrace[traceID]; !exists {
			order = append(order, traceID)
		}
		byTrace[traceID] = append(byTrace[traceID], span)
	}
	canaries := make([][]sdktrace.ReadOnlySpan, 0, len(order))
	for _, traceID := range order {
		canaries = append(canaries, byTrace[traceID])
	}
	return regular, canaries
}

func isOTLPCanarySpan(span sdktrace.ReadOnlySpan) bool {
	if span == nil {
		return false
	}
	for _, item := range span.Attributes() {
		if string(item.Key) == "defenseclaw.telemetry.canary" && item.Value.Type() == attribute.BOOL {
			return item.Value.AsBool()
		}
	}
	return false
}

func otlpCanaryDestination(span sdktrace.ReadOnlySpan) string {
	if !isOTLPCanarySpan(span) {
		return ""
	}
	for _, item := range span.Attributes() {
		if string(item.Key) == "defenseclaw.telemetry.canary.destination" && item.Value.Type() == attribute.STRING {
			return strings.TrimSpace(item.Value.AsString())
		}
	}
	return ""
}

func observeCanaryAcknowledgement(observer CanaryAcknowledgementObserver, event CanaryAcknowledgement) {
	if observer == nil || event.Destination == "" || event.TraceID == "" {
		return
	}
	defer func() { _ = recover() }()
	observer.ObserveOTLPCanaryAcknowledgement(event)
}

func (exporter *SpanExporter) Shutdown(ctx context.Context) error {
	if exporter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	exporter.mu.Lock()
	if exporter.closed {
		exporter.mu.Unlock()
		return nil
	}
	exporter.closed = true
	exporter.mu.Unlock()
	err := exporter.inner.Shutdown(ctx)
	closeHTTPTransport(exporter.httpTransport)
	if exporter.connection != nil {
		if closeErr := exporter.connection.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return newError(ErrorShutdown, err)
	}
	return nil
}

func (exporter *SpanExporter) Counters() ExportCounters {
	if exporter == nil {
		return ExportCounters{}
	}
	return exporter.counters.snapshot()
}
