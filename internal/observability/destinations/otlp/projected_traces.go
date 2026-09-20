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
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	projectedTraceRequestBaseBytes = 128
	projectedTraceItemWrapperBytes = 65_536
	maxTraceResponseBodyBytes      = 64 * 1024
)

// ProjectedTraceRequest is a complete OTLP request derived only from immutable,
// destination-projected batch items. CanaryTraceIDs may contain only complete
// two-span canaries present in Request; acknowledgement is emitted only after a
// response accepts the complete request without partial rejection.
type ProjectedTraceRequest struct {
	Request        *collectortracepb.ExportTraceServiceRequest
	CanaryTraceIDs []string
}

// ProjectedTraceRequestBuilder is the explicit boundary between central
// projection/redaction and OTLP transport. Implementations must reject raw
// canonical records and mixed compatibility profiles. The transport validates
// the resulting span count and protobuf size before attempting delivery.
type ProjectedTraceRequestBuilder interface {
	BuildProjectedTraceRequest(destination string, batch delivery.Batch) (ProjectedTraceRequest, bool)
}

// ProjectedTraceAdapter transports already-projected trace records. It never
// receives an SDK ReadOnlySpan or canonical producer record, so it cannot reach
// back around destination routing/redaction. The common delivery dispatcher owns
// queueing, batching, and retry.
type ProjectedTraceAdapter struct {
	config        signalConfig
	destination   string
	builder       ProjectedTraceRequestBuilder
	httpClient    *http.Client
	httpTransport *http.Transport
	connection    *grpc.ClientConn
	grpcClient    collectortracepb.TraceServiceClient
	maxBytes      int
	counters      mutableCounters
	gate          chan struct{}
	closed        bool
}

// NewProjectedTraceAdapter claims one protobuf trace transport. The caller
// supplies the only accepted projected builder; canonical records and SDK spans
// never cross this boundary.
func (factory *Factory) NewProjectedTraceAdapter(
	ctx context.Context,
	builder ProjectedTraceRequestBuilder,
) (*ProjectedTraceAdapter, error) {
	if ctx == nil || builder == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalTraces)
	if err != nil {
		return nil, err
	}
	adapter := &ProjectedTraceAdapter{
		config: config, destination: factory.config.Destination,
		builder:  builder,
		maxBytes: factory.config.Batch.MaxExportBatchBytes, gate: make(chan struct{}, 1),
	}
	if config.protocol == ProtocolHTTP {
		adapter.httpClient, adapter.httpTransport = newHTTPClient(config)
	} else {
		connection, connectionErr := newGRPCConnection(config)
		if connectionErr != nil {
			return nil, connectionErr
		}
		adapter.connection = connection
		adapter.grpcClient = collectortracepb.NewTraceServiceClient(connection)
	}
	adapter.gate <- struct{}{}
	return adapter, nil
}

// NewCanonicalTraceAdapter claims the general OTLP direct-span transport for
// destination-routed and redacted canonical trace projections.
func (factory *Factory) NewCanonicalTraceAdapter(ctx context.Context) (*ProjectedTraceAdapter, error) {
	return factory.NewProjectedTraceAdapter(ctx, canonicalTraceProjectedBuilder{})
}

// EncodedSize conservatively accounts for the complete protobuf request. The
// fixed per-item allowance is the same reviewed projection-wrapper ceiling used
// by OTLP logs; Deliver verifies the exact marshaled request remains below it.
func (*ProjectedTraceAdapter) EncodedSize(projectedSizes []int) (int, bool) {
	total := projectedTraceRequestBaseBytes
	for _, size := range projectedSizes {
		if size < 0 || size > maxInt-projectedTraceItemWrapperBytes ||
			total > maxInt-size-projectedTraceItemWrapperBytes {
			return 0, false
		}
		total += size + projectedTraceItemWrapperBytes
	}
	return total, true
}

func (adapter *ProjectedTraceAdapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil || adapter.builder == nil || batch.Len() <= 0 {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	estimate, ok := adapter.EncodedSize(batchSizes(batch))
	if !ok || estimate != batch.EncodedSize() || estimate > adapter.maxBytes {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	projected, ok := buildProjectedTraceRequestSafely(adapter.builder, adapter.destination, batch)
	if !ok || projected.Request == nil || countTraceSpans(projected.Request) != batch.Len() ||
		proto.Size(projected.Request) > estimate {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if !adapter.lock(ctx) {
		return deliveryResult(delivery.OutcomeTransient)
	}
	defer adapter.unlock()
	if adapter.closed {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	adapter.counters.accepted.Add(uint64(batch.Len()))
	attemptContext, cancel := context.WithTimeout(ctx, adapter.config.timeout)
	defer cancel()
	if adapter.config.protocol == ProtocolHTTP {
		return adapter.deliverHTTP(attemptContext, projected, batch.Len())
	}
	return adapter.deliverGRPC(attemptContext, projected, batch.Len())
}

func buildProjectedTraceRequestSafely(
	builder ProjectedTraceRequestBuilder,
	destination string,
	batch delivery.Batch,
) (result ProjectedTraceRequest, ok bool) {
	defer func() {
		if recover() != nil {
			result, ok = ProjectedTraceRequest{}, false
		}
	}()
	return builder.BuildProjectedTraceRequest(destination, batch)
}

func (adapter *ProjectedTraceAdapter) deliverHTTP(
	ctx context.Context,
	projected ProjectedTraceRequest,
	spanCount int,
) delivery.DeliveryResult {
	encoded, err := proto.Marshal(projected.Request)
	if err != nil {
		adapter.recordTraceFailure(spanCount)
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, signalURL(adapter.config), bytes.NewReader(encoded),
	)
	if err != nil {
		adapter.recordTraceFailure(spanCount)
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	request.Header.Set("Content-Type", "application/x-protobuf")
	for key, value := range adapter.config.headers {
		request.Header.Set(key, value)
	}
	var wroteRequest atomic.Bool
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}))
	dialSequence := adapter.config.tracker.snapshot()
	response, err := adapter.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		switch {
		case adapter.config.tracker.unsafeSince(dialSequence),
			errors.Is(err, netguard.ErrV8AddressProhibited),
			errors.Is(err, netguard.ErrV8EndpointInvalid),
			errors.Is(err, netguard.ErrV8RedirectBlocked):
			return deliveryResult(delivery.OutcomeUnsafeEndpoint)
		case wroteRequest.Load():
			return deliveryResult(delivery.OutcomeAmbiguous)
		default:
			return deliveryResult(delivery.OutcomeTransient)
		}
	}
	if response == nil {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return deliveryResult(delivery.OutcomeAuthentication)
	}
	if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooEarly ||
		response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return deliveryResult(delivery.OutcomeTransient)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxTraceResponseBodyBytes+1))
	if readErr != nil || len(body) > maxTraceResponseBodyBytes {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	result, ok := decodeProjectedTraceHTTPResponse(response.Header.Get("Content-Type"), body)
	if !ok {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	return adapter.classifyTraceResponse(result, spanCount, projected.CanaryTraceIDs)
}

// decodeProjectedTraceHTTPResponse accepts the two OTLP/HTTP response
// encodings selected by Content-Type. An empty 2xx body is the zero response
// only when Content-Type is absent or selects one of those encodings. A
// non-empty response without Content-Type retains the historical protobuf
// interpretation, while malformed or unsupported media types fail closed.
func decodeProjectedTraceHTTPResponse(
	contentType string,
	body []byte,
) (*collectortracepb.ExportTraceServiceResponse, bool) {
	result := &collectortracepb.ExportTraceServiceResponse{}
	mediaType := "application/x-protobuf"
	if raw := strings.TrimSpace(contentType); raw != "" {
		parsed, _, err := mime.ParseMediaType(raw)
		if err != nil {
			return nil, false
		}
		mediaType = strings.ToLower(parsed)
	}
	if mediaType != "application/x-protobuf" && mediaType != "application/json" {
		return nil, false
	}
	if len(body) == 0 {
		return result, true
	}
	switch mediaType {
	case "application/x-protobuf":
		if err := proto.Unmarshal(body, result); err != nil {
			return nil, false
		}
	case "application/json":
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, result); err != nil {
			return nil, false
		}
	}
	return result, true
}

func (adapter *ProjectedTraceAdapter) deliverGRPC(
	ctx context.Context,
	projected ProjectedTraceRequest,
	spanCount int,
) delivery.DeliveryResult {
	if adapter.grpcClient == nil {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if len(adapter.config.headers) > 0 {
		pairs := make([]string, 0, len(adapter.config.headers)*2)
		for key, value := range adapter.config.headers {
			pairs = append(pairs, key, value)
		}
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(pairs...))
	}
	dialSequence := adapter.config.tracker.snapshot()
	response, err := adapter.grpcClient.Export(ctx, projected.Request, grpc.WaitForReady(false))
	if err != nil {
		if adapter.config.tracker.unsafeSince(dialSequence) ||
			errors.Is(err, netguard.ErrV8AddressProhibited) || errors.Is(err, netguard.ErrV8EndpointInvalid) {
			return deliveryResult(delivery.OutcomeUnsafeEndpoint)
		}
		switch grpcstatus.Code(err) {
		case codes.Unauthenticated, codes.PermissionDenied:
			return deliveryResult(delivery.OutcomeAuthentication)
		case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.FailedPrecondition,
			codes.OutOfRange, codes.Unimplemented:
			adapter.recordTraceFailure(spanCount)
			return deliveryResult(delivery.OutcomePermanentPayload)
		case codes.Canceled, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted, codes.Unavailable:
			return deliveryResult(delivery.OutcomeAmbiguous)
		default:
			return deliveryResult(delivery.OutcomeAmbiguous)
		}
	}
	if response == nil {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	return adapter.classifyTraceResponse(response, spanCount, projected.CanaryTraceIDs)
}

func (adapter *ProjectedTraceAdapter) classifyTraceResponse(
	result *collectortracepb.ExportTraceServiceResponse,
	spanCount int,
	canaryTraceIDs []string,
) delivery.DeliveryResult {
	if result == nil {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	if result.PartialSuccess != nil && result.PartialSuccess.RejectedSpans < 0 {
		adapter.recordTraceFailure(spanCount)
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if result.PartialSuccess != nil && result.PartialSuccess.RejectedSpans > 0 {
		accepted, rejected := adapter.recordTraceSuccess(spanCount, result.PartialSuccess.RejectedSpans)
		if accepted > 0 && rejected > 0 {
			return delivery.DeliveryResult{
				Outcome: delivery.OutcomePartial, DeliveredItems: accepted, RejectedItems: rejected,
			}
		}
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	adapter.recordTraceSuccess(spanCount, 0)
	for _, traceID := range canaryTraceIDs {
		observeCanaryAcknowledgement(adapter.config.canary, CanaryAcknowledgement{
			Destination: adapter.destination, TraceID: traceID,
		})
	}
	return deliveryResult(delivery.OutcomeDelivered)
}

func (adapter *ProjectedTraceAdapter) recordTraceFailure(total int) {
	if total <= 0 {
		return
	}
	adapter.counters.failed.Add(uint64(total))
	observe(adapter.config.observer, SignalEvent{
		Signal: observability.SignalTraces, Outcome: SignalOutcomeExportFailed, Count: uint64(total),
	})
}

func (adapter *ProjectedTraceAdapter) recordTraceSuccess(total int, rejected int64) (int, int) {
	if total < 0 {
		total = 0
	}
	if rejected < 0 {
		rejected = 0
	}
	if rejected > int64(total) {
		rejected = int64(total)
	}
	accepted := total - int(rejected)
	if accepted > 0 {
		adapter.counters.exported.Add(uint64(accepted))
		observe(adapter.config.observer, SignalEvent{
			Signal: observability.SignalTraces, Outcome: SignalOutcomeExported, Count: uint64(accepted),
		})
	}
	if rejected > 0 {
		adapter.counters.rejectedPartial.Add(uint64(rejected))
		observe(adapter.config.observer, SignalEvent{
			Signal: observability.SignalTraces, Outcome: SignalOutcomePartialRejected, Count: uint64(rejected),
		})
	}
	return accepted, int(rejected)
}

func (adapter *ProjectedTraceAdapter) Close(ctx context.Context) error {
	if adapter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorShutdown, nil)
	}
	if !adapter.lock(ctx) {
		return newError(ErrorShutdown, ctx.Err())
	}
	defer adapter.unlock()
	if adapter.closed {
		return nil
	}
	closeHTTPTransport(adapter.httpTransport)
	if adapter.connection != nil {
		if err := adapter.connection.Close(); err != nil {
			return newError(ErrorShutdown, err)
		}
	}
	adapter.closed = true
	return nil
}

func (adapter *ProjectedTraceAdapter) lock(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-adapter.gate:
		return true
	}
}

func (adapter *ProjectedTraceAdapter) unlock() { adapter.gate <- struct{}{} }

func (adapter *ProjectedTraceAdapter) Counters() ExportCounters {
	if adapter == nil {
		return ExportCounters{}
	}
	return adapter.counters.snapshot()
}

func countTraceSpans(request *collectortracepb.ExportTraceServiceRequest) int {
	if request == nil {
		return 0
	}
	total := 0
	for _, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeSpans {
			if scope != nil {
				total += len(scope.Spans)
			}
		}
	}
	return total
}
