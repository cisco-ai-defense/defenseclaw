// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	v8DefaultCanonicalSpanHandoffCapacity        = 2_048
	v8DefaultCanonicalSpanHandoffBytes           = 64 * 1_024 * 1_024
	v8MaxDestinationNameBytes                    = 128
	v8RuntimeOTLPFlagsMask                uint32 = 0x3ff
)

// V8CanonicalEndedSpan is the generation-owned, copy-safe handoff form of a
// generated canonical trace record. It intentionally exposes no
// sdktrace.ReadOnlySpan: SDK snapshots are valid only for the synchronous
// SpanProcessor callback, while canonical consumers enqueue work that may
// outlive that callback. Record returns a fresh immutable clone.
type V8CanonicalEndedSpan struct {
	record                         observability.Record
	traceID                        trace.TraceID
	spanID                         trace.SpanID
	parentSpanID                   trace.SpanID
	hasParentSpanID                bool
	name                           string
	start                          time.Time
	end                            time.Time
	kind                           trace.SpanKind
	statusCode                     codes.Code
	statusDescription              string
	encodedBytes                   int
	bucket                         string
	configGeneration               int64
	family                         string
	familyVersion                  int64
	traceSchema                    string
	semanticProfile                string
	scopeName                      string
	scopeVersion                   string
	scopeSchemaURL                 string
	resourceSchemaURL              string
	resourceAttributes             map[string]string
	resourceDroppedAttributesCount uint32
	traceState                     string
	traceFlags                     byte
	otlpFlags                      uint32
}

func (span V8CanonicalEndedSpan) Record() observability.Record { return span.record.Clone() }
func (span V8CanonicalEndedSpan) TraceID() trace.TraceID       { return span.traceID }
func (span V8CanonicalEndedSpan) SpanID() trace.SpanID         { return span.spanID }
func (span V8CanonicalEndedSpan) Name() string                 { return strings.Clone(span.name) }
func (span V8CanonicalEndedSpan) StartTime() time.Time         { return span.start }
func (span V8CanonicalEndedSpan) EndTime() time.Time           { return span.end }
func (span V8CanonicalEndedSpan) Kind() trace.SpanKind         { return span.kind }
func (span V8CanonicalEndedSpan) StatusCode() codes.Code       { return span.statusCode }
func (span V8CanonicalEndedSpan) StatusDescription() string {
	return strings.Clone(span.statusDescription)
}
func (span V8CanonicalEndedSpan) TraceState() string { return strings.Clone(span.traceState) }
func (span V8CanonicalEndedSpan) TraceFlags() byte   { return span.traceFlags }
func (span V8CanonicalEndedSpan) OTLPFlags() uint32  { return span.otlpFlags }
func (span V8CanonicalEndedSpan) ResourceDroppedAttributesCount() uint32 {
	return span.resourceDroppedAttributesCount
}
func (span V8CanonicalEndedSpan) ParentSpanID() (trace.SpanID, bool) {
	return span.parentSpanID, span.hasParentSpanID
}

// V8CanonicalSpanEnqueueResult is a closed, content-free acknowledgement from
// a nonblocking canonical destination enqueue boundary.
type V8CanonicalSpanEnqueueResult string

const (
	V8CanonicalSpanEnqueueAccepted V8CanonicalSpanEnqueueResult = "accepted"
	V8CanonicalSpanEnqueueDropped  V8CanonicalSpanEnqueueResult = "dropped"
	V8CanonicalSpanEnqueueClosed   V8CanonicalSpanEnqueueResult = "closed"
	V8CanonicalSpanEnqueueFailed   V8CanonicalSpanEnqueueResult = "failed"
)

// V8CanonicalSpanConsumer owns one destination queue in exactly one runtime
// generation. TryEnqueue MUST be nonblocking and MUST snapshot anything it
// retains. ForceFlush and Shutdown are invoked by the generation's sole
// composite SDK processor and must not be shared with another generation.
type V8CanonicalSpanConsumer interface {
	TryEnqueue(V8CanonicalEndedSpan) V8CanonicalSpanEnqueueResult
	ForceFlush(context.Context) error
	Shutdown(context.Context) error
}

// V8GenerationSpanPipeline selects one generated-record consumer for a named
// destination. Raw SDK processor ownership is intentionally unavailable in
// the released v8 runtime.
type V8GenerationSpanPipeline struct {
	Destination string
	Canonical   V8CanonicalSpanConsumer
}

// V8CanonicalSpanRegistrationCode is the closed result of handing a generated
// record to the active provider immediately before the producer ends its span.
type V8CanonicalSpanRegistrationCode string

const (
	V8CanonicalSpanRegistered          V8CanonicalSpanRegistrationCode = "registered"
	V8CanonicalSpanProviderUnavailable V8CanonicalSpanRegistrationCode = "provider_unavailable"
	V8CanonicalSpanGenerationInactive  V8CanonicalSpanRegistrationCode = "generation_inactive"
	V8CanonicalSpanNotRecording        V8CanonicalSpanRegistrationCode = "not_recording"
	V8CanonicalSpanNotSampled          V8CanonicalSpanRegistrationCode = "not_sampled"
	V8CanonicalSpanCollectionDisabled  V8CanonicalSpanRegistrationCode = "collection_disabled"
	V8CanonicalSpanInvalidRecord       V8CanonicalSpanRegistrationCode = "invalid_record"
	V8CanonicalSpanIdentityMismatch    V8CanonicalSpanRegistrationCode = "identity_mismatch"
	V8CanonicalSpanGenerationMismatch  V8CanonicalSpanRegistrationCode = "generation_mismatch"
	V8CanonicalSpanPlanMismatch        V8CanonicalSpanRegistrationCode = "plan_mismatch"
	V8CanonicalSpanDuplicate           V8CanonicalSpanRegistrationCode = "duplicate"
	V8CanonicalSpanCapacityExceeded    V8CanonicalSpanRegistrationCode = "capacity_exceeded"
	V8CanonicalSpanHandoffNotConsumed  V8CanonicalSpanRegistrationCode = "handoff_not_consumed"
)

// V8ImportedSpanResult contains only bounded destination accounting for one
// already-ended imported canonical span. Imported spans never enter the local
// SDK processor or SQLite log pipeline.
type V8ImportedSpanResult struct {
	Matched    int
	Delivered  int
	Dropped    int
	Failed     int
	Suppressed int
}

// V8ImportedExportPolicy is private routing state for already-normalized
// inbound signals. The zero value performs ordinary fan-out. It is never
// copied into canonical records, span attributes, metric labels, or resource
// identity.
type V8ImportedExportPolicy struct {
	originDestination string
	suppressAll       bool
}

// NewV8ImportedExportPolicy validates an optional exact local destination.
// Empty selects ordinary fan-out and is valid for wrapper APIs.
func NewV8ImportedExportPolicy(originDestination string) (V8ImportedExportPolicy, error) {
	if originDestination != "" && !observability.IsStableToken(originDestination) {
		return V8ImportedExportPolicy{}, errors.New("telemetry: invalid imported export policy")
	}
	return V8ImportedExportPolicy{originDestination: originDestination}, nil
}

// SuppressAllV8ImportedExport returns the terminal-hop routing state without
// inventing a destination identity.
func SuppressAllV8ImportedExport() V8ImportedExportPolicy {
	return V8ImportedExportPolicy{suppressAll: true}
}

func (policy V8ImportedExportPolicy) valid() bool {
	return (!policy.suppressAll || policy.originDestination == "") &&
		(policy.originDestination == "" || observability.IsStableToken(policy.originDestination))
}

type v8SpanHandoffKey struct {
	traceID trace.TraceID
	spanID  trace.SpanID
}

type v8SpanHandoff struct {
	generation   uint64
	capacity     int
	byteLimit    int
	pendingBytes int
	active       atomic.Bool
	closed       atomic.Bool
	nextID       atomic.Uint64
	mu           sync.Mutex
	pending      map[v8SpanHandoffKey]v8PendingCanonicalSpan
}

type v8PendingCanonicalSpan struct {
	id    uint64
	span  V8CanonicalEndedSpan
	state *atomic.Uint32
}

type v8SpanHandoffRegistration struct {
	handoff *v8SpanHandoff
	key     v8SpanHandoffKey
	id      uint64
	end     time.Time
	state   *atomic.Uint32
}

const (
	v8HandoffStatePending uint32 = iota
	v8HandoffStateConsumed
	v8HandoffStateCancelled
	v8HandoffStateRetired
	v8HandoffStateParityRejected
)

func newV8SpanHandoff(generation uint64, capacity, byteLimit int) *v8SpanHandoff {
	if capacity <= 0 {
		capacity = v8DefaultCanonicalSpanHandoffCapacity
	}
	if byteLimit <= 0 {
		byteLimit = v8DefaultCanonicalSpanHandoffBytes
	}
	return &v8SpanHandoff{
		generation: generation,
		capacity:   capacity,
		byteLimit:  byteLimit,
		pending:    make(map[v8SpanHandoffKey]v8PendingCanonicalSpan, capacity),
	}
}

func (handoff *v8SpanHandoff) setActive(active bool) {
	if handoff == nil || handoff.closed.Load() {
		return
	}
	handoff.active.Store(active)
}

func (handoff *v8SpanHandoff) register(
	span trace.Span,
	canonical V8CanonicalEndedSpan,
) (v8SpanHandoffRegistration, V8CanonicalSpanRegistrationCode) {
	if handoff == nil || nilV8TraceSpan(span) {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanProviderUnavailable
	}
	if handoff.closed.Load() || !handoff.active.Load() {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanGenerationInactive
	}
	if !span.IsRecording() {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanNotRecording
	}
	spanContext := span.SpanContext()
	if !spanContext.IsValid() || !spanContext.IsSampled() {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanNotSampled
	}
	if canonical.traceID != spanContext.TraceID() || canonical.spanID != spanContext.SpanID() {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanIdentityMismatch
	}
	if handoff.generation > uint64(math.MaxInt64) ||
		canonical.record.Provenance().ConfigGeneration != int64(handoff.generation) {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanGenerationMismatch
	}

	key := v8SpanHandoffKey{traceID: canonical.traceID, spanID: canonical.spanID}
	id := handoff.nextID.Add(1)
	state := &atomic.Uint32{}
	state.Store(v8HandoffStatePending)
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed.Load() || !handoff.active.Load() {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanGenerationInactive
	}
	if _, exists := handoff.pending[key]; exists {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanDuplicate
	}
	if len(handoff.pending) >= handoff.capacity {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanCapacityExceeded
	}
	if canonical.encodedBytes > handoff.byteLimit-handoff.pendingBytes {
		return v8SpanHandoffRegistration{}, V8CanonicalSpanCapacityExceeded
	}
	handoff.pending[key] = v8PendingCanonicalSpan{id: id, span: canonical, state: state}
	handoff.pendingBytes += canonical.encodedBytes
	return v8SpanHandoffRegistration{handoff: handoff, key: key, id: id, end: canonical.end, state: state}, V8CanonicalSpanRegistered
}

func (handoff *v8SpanHandoff) consume(span sdktrace.ReadOnlySpan) (V8CanonicalEndedSpan, bool) {
	if handoff == nil || span == nil {
		return V8CanonicalEndedSpan{}, false
	}
	context := span.SpanContext()
	key := v8SpanHandoffKey{traceID: context.TraceID(), spanID: context.SpanID()}
	handoff.mu.Lock()
	pending, exists := handoff.pending[key]
	if exists {
		delete(handoff.pending, key)
		handoff.pendingBytes -= pending.span.encodedBytes
	}
	handoff.mu.Unlock()
	if !exists {
		return V8CanonicalEndedSpan{}, false
	}
	if !v8CanonicalPhysicalParity(pending.span, span) {
		pending.state.CompareAndSwap(v8HandoffStatePending, v8HandoffStateParityRejected)
		return V8CanonicalEndedSpan{}, false
	}
	pending.state.CompareAndSwap(v8HandoffStatePending, v8HandoffStateConsumed)
	return pending.span, true
}

func (registration v8SpanHandoffRegistration) cancel() {
	if registration.handoff == nil || registration.id == 0 {
		return
	}
	registration.handoff.mu.Lock()
	pending, exists := registration.handoff.pending[registration.key]
	if exists && pending.id == registration.id {
		delete(registration.handoff.pending, registration.key)
		registration.handoff.pendingBytes -= pending.span.encodedBytes
		pending.state.CompareAndSwap(v8HandoffStatePending, v8HandoffStateCancelled)
	}
	registration.handoff.mu.Unlock()
}

func (handoff *v8SpanHandoff) retire() {
	if handoff == nil || !handoff.closed.CompareAndSwap(false, true) {
		return
	}
	handoff.active.Store(false)
	handoff.mu.Lock()
	for _, pending := range handoff.pending {
		pending.state.CompareAndSwap(v8HandoffStatePending, v8HandoffStateRetired)
	}
	clear(handoff.pending)
	handoff.pendingBytes = 0
	handoff.mu.Unlock()
}

// EndV8CanonicalSpan atomically coordinates a generated canonical trace record
// with the SDK span's synchronous End callback. Successful registration ends
// at the canonical timestamp; every rejection still performs an ordinary End.
// It removes an unconsumed registration after End, which makes concurrent/
// double End and abnormal processor behavior leak-free.
// Registration is bounded and accepts only an active generation's recording,
// sampled, collected span; routes cannot resurrect an unsampled span.
// Producers MUST hold the runtimegraph generation lease from span Start through
// generated record construction and this End call.
func (p *Provider) EndV8CanonicalSpan(span trace.Span, record observability.Record) V8CanonicalSpanRegistrationCode {
	canonical, canonicalOK := newV8CanonicalEndedSpan(record)
	endPhysical := func(exact bool) {
		if nilV8TraceSpan(span) {
			return
		}
		if exact {
			span.End(trace.WithTimestamp(canonical.end))
			return
		}
		span.End()
	}
	if p == nil || p.v8 == nil || p.v8.handoff == nil {
		endPhysical(false)
		return V8CanonicalSpanProviderUnavailable
	}
	if !p.v8.active.Load() || p.shutdown.Load() {
		endPhysical(false)
		return V8CanonicalSpanGenerationInactive
	}
	if !canonicalOK {
		endPhysical(false)
		return V8CanonicalSpanInvalidRecord
	}
	if canonical.resourceDroppedAttributesCount != 0 {
		// sdk/resource has no dropped-attribute-count representation. Reject the
		// local SDK handoff before registration while leaving the canonical record
		// valid for inbound/projection-only consumers.
		endPhysical(false)
		return V8CanonicalSpanInvalidRecord
	}
	if !p.TraceBucketEnabled(canonical.record.Bucket()) {
		endPhysical(false)
		return V8CanonicalSpanCollectionDisabled
	}
	if digest := canonical.record.Provenance().ConfigDigest; digest == "" || digest != p.v8.planDigest {
		endPhysical(false)
		return V8CanonicalSpanPlanMismatch
	}
	registration, result := p.v8.handoff.register(span, canonical)
	if result != V8CanonicalSpanRegistered {
		endPhysical(false)
		return result
	}
	defer registration.cancel()
	span.End(trace.WithTimestamp(registration.end))
	state := registration.state.Load()
	switch state {
	case v8HandoffStateConsumed:
		return V8CanonicalSpanRegistered
	case v8HandoffStateRetired:
		return V8CanonicalSpanGenerationInactive
	default:
		return V8CanonicalSpanHandoffNotConsumed
	}
}

// ImportV8CanonicalSpan validates and directly fans out one already-ended
// imported span. The caller must hold the exact runtime-generation lease from
// collection admission through this call. There is deliberately no legacy SDK
// fallback because an SDK processor cannot preserve sender-owned trace/span IDs.
func (p *Provider) ImportV8CanonicalSpan(record observability.Record) (V8ImportedSpanResult, error) {
	return p.ImportV8CanonicalSpanWithPolicy(record, V8ImportedExportPolicy{})
}

// ImportV8CanonicalSpanWithPolicy is the imported-only fan-out path. Exact
// origin and terminal suppression happen before a destination consumer sees
// the span and do not mutate its canonical representation.
func (p *Provider) ImportV8CanonicalSpanWithPolicy(
	record observability.Record,
	policy V8ImportedExportPolicy,
) (V8ImportedSpanResult, error) {
	if !policy.valid() {
		return V8ImportedSpanResult{}, errors.New("telemetry: invalid imported export policy")
	}
	if p == nil || p.v8 == nil || p.v8.spanProcessor == nil ||
		!p.v8.active.Load() || p.shutdown.Load() {
		return V8ImportedSpanResult{}, errors.New("telemetry: imported canonical span provider is unavailable")
	}
	canonical, ok := newV8CanonicalEndedSpanForImport(record)
	if !ok {
		return V8ImportedSpanResult{}, errors.New("telemetry: imported canonical span record is invalid")
	}
	if !p.TraceBucketEnabled(record.Bucket()) {
		return V8ImportedSpanResult{}, errors.New("telemetry: imported canonical span is not collected")
	}
	if digest := record.Provenance().ConfigDigest; digest == "" || digest != p.v8.planDigest ||
		record.Provenance().ConfigGeneration < 0 ||
		uint64(record.Provenance().ConfigGeneration) != p.v8.generation {
		return V8ImportedSpanResult{}, errors.New("telemetry: imported canonical span generation mismatch")
	}
	return p.v8.spanProcessor.importCanonical(canonical, policy), nil
}

func nilV8TraceSpan(span trace.Span) bool {
	if span == nil {
		return true
	}
	value := reflect.ValueOf(span)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

type v8CompositeSpanProcessor struct {
	pipelines    []V8GenerationSpanPipeline
	handoff      *v8SpanHandoff
	gateMu       sync.Mutex
	closing      bool
	inflight     int
	drained      chan struct{}
	shutdownDone chan struct{}
	shutdownErr  error
}

func newV8CompositeSpanProcessor(
	generation uint64,
	capacity int,
	pipelines []V8GenerationSpanPipeline,
) (*v8CompositeSpanProcessor, error) {
	if len(pipelines) == 0 {
		return nil, errors.New("telemetry: empty v8 span pipelines")
	}
	cloned := append([]V8GenerationSpanPipeline(nil), pipelines...)
	if !validV8SpanPipelines(cloned) {
		return nil, errors.New("telemetry: invalid v8 span pipelines")
	}
	return &v8CompositeSpanProcessor{
		pipelines: cloned,
		handoff:   newV8SpanHandoff(generation, capacity, v8DefaultCanonicalSpanHandoffBytes),
		drained:   make(chan struct{}),
	}, nil
}

func cleanupV8SpanPipelines(pipelines []V8GenerationSpanPipeline, timeout time.Duration) {
	if len(pipelines) == 0 {
		return
	}
	v8BoundedPrepareCleanup(timeout, func(ctx context.Context) {
		seen := make(map[v8InterfaceIdentity]struct{}, len(pipelines)*2)
		for index := len(pipelines) - 1; index >= 0; index-- {
			pipeline := pipelines[index]
			if cleanupV8PipelineChild(pipeline.Canonical, seen) {
				_ = v8CallConsumerContext(pipeline.Canonical.Shutdown, ctx)
			}
		}
	})
}

func cleanupV8PipelineChild(value any, seen map[v8InterfaceIdentity]struct{}) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer && reflected.IsNil() {
		return false
	}
	identity, identifiable := identityOfV8PipelineChild(value)
	if !identifiable {
		return true
	}
	if _, duplicate := seen[identity]; duplicate {
		return false
	}
	seen[identity] = struct{}{}
	return true
}

func (processor *v8CompositeSpanProcessor) OnStart(_ context.Context, _ sdktrace.ReadWriteSpan) {
	if !processor.beginCallback() {
		return
	}
	defer processor.endCallback()
}

func (processor *v8CompositeSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if span == nil || !processor.beginCallback() {
		return
	}
	defer processor.endCallback()
	canonical, hasCanonical := processor.handoff.consume(span)
	for index := range processor.pipelines {
		pipeline := processor.pipelines[index]
		if pipeline.Canonical != nil && hasCanonical {
			v8CallCanonicalEnqueue(pipeline.Canonical, canonical)
		}
	}
}

func (processor *v8CompositeSpanProcessor) importCanonical(
	span V8CanonicalEndedSpan,
	policy V8ImportedExportPolicy,
) V8ImportedSpanResult {
	if !processor.beginCallback() {
		return V8ImportedSpanResult{Failed: 1}
	}
	defer processor.endCallback()
	result := V8ImportedSpanResult{}
	for index := range processor.pipelines {
		pipeline := processor.pipelines[index]
		consumer := pipeline.Canonical
		if consumer == nil {
			continue
		}
		if policy.suppressAll || pipeline.Destination == policy.originDestination {
			result.Suppressed++
			continue
		}
		result.Matched++
		switch v8TryCanonicalEnqueue(consumer, span) {
		case V8CanonicalSpanEnqueueAccepted:
			result.Delivered++
		case V8CanonicalSpanEnqueueDropped:
			result.Dropped++
		case V8CanonicalSpanEnqueueClosed, V8CanonicalSpanEnqueueFailed:
			result.Failed++
		default:
			result.Failed++
		}
	}
	return result
}

func (processor *v8CompositeSpanProcessor) ForceFlush(ctx context.Context) error {
	if !processor.beginCallback() {
		return nil
	}
	defer processor.endCallback()
	failed := false
	for index := range processor.pipelines {
		pipeline := processor.pipelines[index]
		err := v8CallConsumerContext(pipeline.Canonical.ForceFlush, ctx)
		failed = failed || err != nil
	}
	if failed {
		return errors.New("telemetry: v8 span pipeline flush failed")
	}
	return nil
}

func (processor *v8CompositeSpanProcessor) Shutdown(ctx context.Context) error {
	if processor == nil {
		return nil
	}
	processor.gateMu.Lock()
	if !processor.closing {
		processor.closing = true
		processor.shutdownDone = make(chan struct{})
		if processor.inflight == 0 {
			close(processor.drained)
		}
		go processor.runShutdown()
	}
	done := processor.shutdownDone
	processor.gateMu.Unlock()
	select {
	case <-done:
		processor.gateMu.Lock()
		err := processor.shutdownErr
		processor.gateMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (processor *v8CompositeSpanProcessor) beginCallback() bool {
	if processor == nil {
		return false
	}
	processor.gateMu.Lock()
	defer processor.gateMu.Unlock()
	if processor.closing {
		return false
	}
	processor.inflight++
	return true
}

func (processor *v8CompositeSpanProcessor) endCallback() {
	processor.gateMu.Lock()
	processor.inflight--
	if processor.closing && processor.inflight == 0 {
		close(processor.drained)
	}
	processor.gateMu.Unlock()
}

func (processor *v8CompositeSpanProcessor) runShutdown() {
	<-processor.drained
	processor.handoff.retire()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	failed := false
	for index := len(processor.pipelines) - 1; index >= 0; index-- {
		pipeline := processor.pipelines[index]
		err := v8CallConsumerContext(pipeline.Canonical.Shutdown, ctx)
		failed = failed || err != nil
	}
	if failed {
		processor.shutdownErr = errors.New("telemetry: v8 span pipeline shutdown failed")
	}
	processor.gateMu.Lock()
	close(processor.shutdownDone)
	processor.gateMu.Unlock()
}

func validV8SpanPipelines(pipelines []V8GenerationSpanPipeline) bool {
	destinations := make(map[string]struct{}, len(pipelines))
	children := make(map[v8InterfaceIdentity]struct{}, len(pipelines))
	for _, pipeline := range pipelines {
		if !observability.IsStableToken(pipeline.Destination) || len(pipeline.Destination) > v8MaxDestinationNameBytes ||
			pipeline.Canonical == nil {
			return false
		}
		if _, exists := destinations[pipeline.Destination]; exists {
			return false
		}
		destinations[pipeline.Destination] = struct{}{}
		identity, ok := identityOfV8PipelineChild(pipeline.Canonical)
		if !ok {
			return false
		}
		if _, exists := children[identity]; exists {
			return false
		}
		children[identity] = struct{}{}
	}
	return true
}

type v8InterfaceIdentity struct {
	typeName string
	pointer  uintptr
}

func identityOfV8PipelineChild(value any) (v8InterfaceIdentity, bool) {
	if value == nil {
		return v8InterfaceIdentity{}, false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Pointer || reflected.IsNil() {
		return v8InterfaceIdentity{}, false
	}
	return v8InterfaceIdentity{typeName: reflected.Type().String(), pointer: reflected.Pointer()}, true
}

func v8CallCanonicalEnqueue(consumer V8CanonicalSpanConsumer, span V8CanonicalEndedSpan) {
	defer func() { _ = recover() }()
	result := consumer.TryEnqueue(span)
	switch result {
	case V8CanonicalSpanEnqueueAccepted, V8CanonicalSpanEnqueueDropped,
		V8CanonicalSpanEnqueueClosed, V8CanonicalSpanEnqueueFailed:
	default:
		// Unknown acknowledgements fail closed for this destination only.
	}
}

func v8TryCanonicalEnqueue(
	consumer V8CanonicalSpanConsumer,
	span V8CanonicalEndedSpan,
) (result V8CanonicalSpanEnqueueResult) {
	defer func() {
		if recover() != nil {
			result = V8CanonicalSpanEnqueueFailed
		}
	}()
	return consumer.TryEnqueue(span)
}

func v8CallConsumerContext(call func(context.Context) error, ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("telemetry: canonical span consumer failed")
		}
	}()
	return call(ctx)
}

func newV8CanonicalEndedSpan(record observability.Record) (V8CanonicalEndedSpan, bool) {
	return newV8CanonicalEndedSpanWithFlags(record, false)
}

func newV8CanonicalEndedSpanForImport(record observability.Record) (V8CanonicalEndedSpan, bool) {
	return newV8CanonicalEndedSpanWithFlags(record, true)
}

func newV8CanonicalEndedSpanWithFlags(
	record observability.Record,
	allowReservedOTLPFlags bool,
) (V8CanonicalEndedSpan, bool) {
	if record.Signal() != observability.SignalTraces || !record.SchemaDerivedFieldClasses() {
		return V8CanonicalEndedSpan{}, false
	}
	encoded, err := record.Bytes()
	if err != nil || len(encoded) == 0 {
		return V8CanonicalEndedSpan{}, false
	}
	correlation := record.Correlation()
	traceID, err := trace.TraceIDFromHex(correlation.TraceID)
	if err != nil || !traceID.IsValid() {
		return V8CanonicalEndedSpan{}, false
	}
	spanID, err := trace.SpanIDFromHex(correlation.SpanID)
	if err != nil || !spanID.IsValid() {
		return V8CanonicalEndedSpan{}, false
	}
	body, present := record.Body()
	if !present {
		return V8CanonicalEndedSpan{}, false
	}
	object, err := body.Object()
	if err != nil {
		return V8CanonicalEndedSpan{}, false
	}
	kind, ok := v8CanonicalSpanKind(object["kind"])
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	startNanos, ok := v8CanonicalUnixNanos(object["start_time_unix_nano"])
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	endNanos, ok := v8CanonicalUnixNanos(object["end_time_unix_nano"])
	if !ok || endNanos < startNanos {
		return V8CanonicalEndedSpan{}, false
	}
	statusCode, statusDescription, ok := v8CanonicalSpanStatus(object["status"])
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	parent, hasParent, ok := v8CanonicalParentSpanID(object["parent_span_id"])
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	traceState, ok := v8CanonicalTraceState(object["trace_state"])
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	otlpFlags, ok := v8CanonicalUint32(object["flags"])
	// This handoff is constructed from an SDK runtime span rather than an
	// equivalent OTLP message. OTLP reserves bits 10-31 for future use and
	// requires runtime-sourced producers to clear them. Keep the registry's
	// general uint32 contract lossless while rejecting impossible runtime
	// parity before registration.
	if !ok || !allowReservedOTLPFlags && otlpFlags&^v8RuntimeOTLPFlagsMask != 0 {
		return V8CanonicalEndedSpan{}, false
	}
	controls, ok := v8CanonicalControlAttributes(record, object)
	if !ok {
		return V8CanonicalEndedSpan{}, false
	}
	return V8CanonicalEndedSpan{
		record: record, traceID: traceID, spanID: spanID,
		parentSpanID: parent, hasParentSpanID: hasParent,
		name: record.SpanName(), start: time.Unix(0, startNanos).UTC(), end: time.Unix(0, endNanos).UTC(),
		kind: kind, statusCode: statusCode, statusDescription: strings.Clone(statusDescription),
		encodedBytes: len(encoded), bucket: controls.bucket,
		configGeneration: controls.configGeneration, family: controls.family,
		familyVersion: controls.familyVersion, traceSchema: controls.traceSchema,
		semanticProfile: controls.semanticProfile,
		scopeName:       controls.scopeName, scopeVersion: controls.scopeVersion,
		scopeSchemaURL:                 controls.scopeSchemaURL,
		resourceSchemaURL:              controls.resourceSchemaURL,
		resourceAttributes:             controls.resourceAttributes,
		resourceDroppedAttributesCount: controls.resourceDroppedAttributesCount,
		traceState:                     traceState,
		traceFlags:                     byte(otlpFlags),
		otlpFlags:                      otlpFlags,
	}, true
}

type v8CanonicalControls struct {
	bucket                         string
	configGeneration               int64
	family                         string
	familyVersion                  int64
	traceSchema                    string
	semanticProfile                string
	scopeName                      string
	scopeVersion                   string
	scopeSchemaURL                 string
	resourceSchemaURL              string
	resourceAttributes             map[string]string
	resourceDroppedAttributesCount uint32
}

func v8CanonicalControlAttributes(record observability.Record, body map[string]any) (v8CanonicalControls, bool) {
	attributes, ok := body["attributes"].(map[string]any)
	if !ok {
		return v8CanonicalControls{}, false
	}
	bucket, bucketOK := attributes["defenseclaw.bucket"].(string)
	family, familyOK := attributes["defenseclaw.span.family"].(string)
	generation, generationOK := v8CanonicalInt64(attributes["defenseclaw.config.generation"])
	familyVersion, familyVersionOK := v8CanonicalInt64(attributes["defenseclaw.span.family_schema_version"])
	scope, scopeOK := body["scope"].(map[string]any)
	scopeAttributes, scopeAttributesOK := scope["attributes"].(map[string]any)
	scopeName, scopeNameOK := scope["name"].(string)
	scopeVersion, scopeVersionOK := scope["version"].(string)
	scopeSchemaURL, scopeSchemaURLOK := scope["schema_url"].(string)
	traceSchema, traceSchemaOK := scopeAttributes["defenseclaw.trace.schema_version"].(string)
	semanticProfile, semanticProfileOK := scopeAttributes["defenseclaw.semantic_profile"].(string)
	resourceObject, resourceOK := body["resource"].(map[string]any)
	resourceSchemaURL, resourceSchemaURLOK := resourceObject["schema_url"].(string)
	resourceRawAttributes, resourceAttributesOK := resourceObject["attributes"].(map[string]any)
	resourceDroppedAttributesCount := uint32(0)
	resourceDroppedAttributesOK := true
	if raw, present := resourceObject["dropped_attributes_count"]; present {
		resourceDroppedAttributesCount, resourceDroppedAttributesOK = v8CanonicalUint32(raw)
	}
	resourceAttributes := make(map[string]string, len(resourceRawAttributes))
	for key, raw := range resourceRawAttributes {
		value, stringOK := raw.(string)
		if !stringOK {
			return v8CanonicalControls{}, false
		}
		resourceAttributes[key] = value
	}
	if !bucketOK || !familyOK || !generationOK || !familyVersionOK || !scopeOK || !scopeAttributesOK ||
		!scopeNameOK || !scopeVersionOK || !scopeSchemaURLOK || !traceSchemaOK || !semanticProfileOK ||
		!resourceOK || !resourceSchemaURLOK || !resourceAttributesOK || !resourceDroppedAttributesOK ||
		bucket != string(record.Bucket()) ||
		family != string(record.EventName()) || generation != record.Provenance().ConfigGeneration ||
		familyVersion <= 0 || traceSchema == "" || semanticProfile == "" ||
		scopeName == "" || scopeVersion != record.Provenance().BinaryVersion || scopeSchemaURL == "" ||
		resourceSchemaURL == "" || len(resourceAttributes) == 0 {
		return v8CanonicalControls{}, false
	}
	return v8CanonicalControls{
		bucket: bucket, configGeneration: generation, family: family,
		familyVersion: familyVersion, traceSchema: traceSchema, semanticProfile: semanticProfile,
		scopeName: scopeName, scopeVersion: scopeVersion, scopeSchemaURL: scopeSchemaURL,
		resourceSchemaURL: resourceSchemaURL, resourceAttributes: resourceAttributes,
		resourceDroppedAttributesCount: resourceDroppedAttributesCount,
	}, true
}

func v8CanonicalInt64(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(number.String())
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, false
	}
	return rational.Num().Int64(), true
}

func v8CanonicalSpanKind(value any) (trace.SpanKind, bool) {
	text, ok := value.(string)
	if !ok {
		return trace.SpanKindUnspecified, false
	}
	switch text {
	case "INTERNAL":
		return trace.SpanKindInternal, true
	case "SERVER":
		return trace.SpanKindServer, true
	case "CLIENT":
		return trace.SpanKindClient, true
	case "PRODUCER":
		return trace.SpanKindProducer, true
	case "CONSUMER":
		return trace.SpanKindConsumer, true
	default:
		return trace.SpanKindUnspecified, false
	}
}

func v8CanonicalUnixNanos(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(number.String())
	if !ok || !rational.IsInt() || rational.Sign() <= 0 || !rational.Num().IsInt64() {
		return 0, false
	}
	nanos := rational.Num().Int64()
	return nanos, nanos > 0
}

func v8CanonicalParentSpanID(value any) (trace.SpanID, bool, bool) {
	if value == nil {
		return trace.SpanID{}, false, true
	}
	text, ok := value.(string)
	if !ok {
		return trace.SpanID{}, false, false
	}
	parent, err := trace.SpanIDFromHex(text)
	if err != nil || !parent.IsValid() {
		return trace.SpanID{}, false, false
	}
	return parent, true, true
}

func v8CanonicalTraceState(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	if !ok || len(text) > 512 {
		return "", false
	}
	parsed, err := trace.ParseTraceState(text)
	return strings.Clone(text), err == nil && parsed.String() == text
}

func v8CanonicalUint32(value any) (uint32, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(number.String())
	if !ok || !rational.IsInt() || rational.Sign() < 0 || !rational.Num().IsUint64() {
		return 0, false
	}
	unsigned := rational.Num().Uint64()
	return uint32(unsigned), unsigned <= math.MaxUint32
}

func v8CanonicalSpanStatus(value any) (codes.Code, string, bool) {
	status, ok := value.(map[string]any)
	if !ok {
		return codes.Unset, "", false
	}
	codeText, ok := status["code"].(string)
	if !ok {
		return codes.Unset, "", false
	}
	description := ""
	if raw, present := status["description"]; present {
		description, ok = raw.(string)
		if !ok {
			return codes.Unset, "", false
		}
	}
	switch codeText {
	case "UNSET":
		return codes.Unset, description, true
	case "OK":
		return codes.Ok, description, true
	case "ERROR":
		return codes.Error, description, true
	default:
		return codes.Unset, "", false
	}
}

func v8CanonicalPhysicalParity(canonical V8CanonicalEndedSpan, physical sdktrace.ReadOnlySpan) bool {
	if canonical.resourceDroppedAttributesCount != 0 || physical == nil || !physical.SpanContext().IsSampled() ||
		canonical.traceID != physical.SpanContext().TraceID() ||
		canonical.spanID != physical.SpanContext().SpanID() ||
		canonical.name != physical.Name() ||
		!canonical.start.Equal(physical.StartTime()) ||
		!canonical.end.Equal(physical.EndTime()) ||
		canonical.kind != physical.SpanKind() ||
		canonical.traceState != physical.SpanContext().TraceState().String() ||
		canonical.traceFlags != byte(physical.SpanContext().TraceFlags()) ||
		canonical.otlpFlags != v8PhysicalOTLPFlags(physical) {
		return false
	}
	physicalParent := physical.Parent()
	if canonical.hasParentSpanID != physicalParent.IsValid() ||
		canonical.hasParentSpanID && canonical.parentSpanID != physicalParent.SpanID() {
		return false
	}
	status := physical.Status()
	return canonical.statusCode == status.Code && canonical.statusDescription == status.Description &&
		v8PhysicalControlAttributesMatch(canonical, physical.Attributes()) &&
		v8PhysicalScopeMatches(canonical, physical) && v8PhysicalResourceMatches(canonical, physical)
}

func v8PhysicalOTLPFlags(span sdktrace.ReadOnlySpan) uint32 {
	flags := uint32(span.SpanContext().TraceFlags()) | 0x100
	if span.Parent().IsValid() && span.Parent().IsRemote() {
		flags |= 0x200
	}
	return flags
}

func v8PhysicalControlAttributesMatch(
	canonical V8CanonicalEndedSpan,
	attributes []attribute.KeyValue,
) bool {
	values := make(map[string]attribute.Value, 4)
	for _, item := range attributes {
		switch string(item.Key) {
		case "defenseclaw.bucket", "defenseclaw.config.generation", "defenseclaw.span.family",
			"defenseclaw.span.family_schema_version":
			values[string(item.Key)] = item.Value
		}
	}
	return v8AttributeStringEquals(values, "defenseclaw.bucket", canonical.bucket) &&
		v8AttributeInt64Equals(values, "defenseclaw.config.generation", canonical.configGeneration) &&
		v8AttributeStringEquals(values, "defenseclaw.span.family", canonical.family) &&
		v8AttributeInt64Equals(values, "defenseclaw.span.family_schema_version", canonical.familyVersion)
}

func v8PhysicalScopeMatches(canonical V8CanonicalEndedSpan, physical sdktrace.ReadOnlySpan) bool {
	scope := physical.InstrumentationScope()
	if scope.Name != canonical.scopeName || scope.Version != canonical.scopeVersion ||
		scope.SchemaURL != canonical.scopeSchemaURL {
		return false
	}
	attributes := scope.Attributes.ToSlice()
	if len(attributes) != 2 {
		return false
	}
	values := make(map[string]attribute.Value, 2)
	for _, item := range attributes {
		values[string(item.Key)] = item.Value
	}
	return v8AttributeStringEquals(values, "defenseclaw.trace.schema_version", canonical.traceSchema) &&
		v8AttributeStringEquals(values, "defenseclaw.semantic_profile", canonical.semanticProfile)
}

func v8PhysicalResourceMatches(canonical V8CanonicalEndedSpan, physical sdktrace.ReadOnlySpan) bool {
	resource := physical.Resource()
	if resource == nil || resource.SchemaURL() != canonical.resourceSchemaURL {
		return false
	}
	attributes := resource.Attributes()
	if len(attributes) != len(canonical.resourceAttributes) {
		return false
	}
	physicalAttributes := make(map[string]attribute.Value, len(attributes))
	for _, item := range attributes {
		physicalAttributes[string(item.Key)] = item.Value
	}
	for key, expected := range canonical.resourceAttributes {
		if !v8AttributeStringEquals(physicalAttributes, key, expected) {
			return false
		}
	}
	return true
}

func v8AttributeStringEquals(values map[string]attribute.Value, key, expected string) bool {
	value, ok := values[key]
	return ok && value.Type() == attribute.STRING && value.AsString() == expected
}

func v8AttributeInt64Equals(values map[string]attribute.Value, key string, expected int64) bool {
	value, ok := values[key]
	return ok && value.Type() == attribute.INT64 && value.AsInt64() == expected
}
