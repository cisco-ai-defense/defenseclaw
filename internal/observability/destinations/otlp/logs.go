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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	logRequestBaseBytes     = 128
	logRecordWrapperBytes   = 65_536
	maxLogResponseBodyBytes = 64 * 1024
)

type LogAdapter struct {
	config        signalConfig
	builder       *CanonicalLogRequestBuilder
	httpClient    *http.Client
	httpTransport *http.Transport
	connection    *grpc.ClientConn
	grpcClient    collectorlogpb.LogsServiceClient
	maxBytes      int
	counters      mutableCounters
	gate          chan struct{}
	closed        bool
}

// LogResourceSnapshot is the complete generation-bound OTLP resource attached
// to every log request prepared by one adapter. NewLogAdapter copies Values and
// converts them into immutable protobuf state before it returns; callers may
// therefore reuse or mutate their input map without changing queued delivery.
//
// The destination assembly layer supplies this from telemetry.V8ResourceContext.
// It must never be reconstructed from a projected log body.
type LogResourceSnapshot struct {
	SchemaURL              string
	Values                 map[string]string
	DroppedAttributesCount uint32
}

// NewLogAdapter creates a synchronous delivery.Adapter. The common delivery
// dispatcher owns batching/retry; this adapter encodes only immutable
// destination-projected bytes and never receives a canonical record.
func (factory *Factory) NewLogAdapter(ctx context.Context, snapshot LogResourceSnapshot) (*LogAdapter, error) {
	if ctx == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	config, err := factory.claim(observability.SignalLogs)
	if err != nil {
		return nil, err
	}
	builder, err := NewCanonicalLogRequestBuilder(factory.config.Destination, factory.config.LoggerName, snapshot)
	if err != nil {
		return nil, err
	}
	adapter := &LogAdapter{
		config: config, builder: builder,
		maxBytes: factory.config.Batch.MaxExportBatchBytes, gate: make(chan struct{}, 1),
	}
	adapter.gate <- struct{}{}
	if config.protocol == ProtocolHTTP {
		adapter.httpClient, adapter.httpTransport = newHTTPClient(config)
		return adapter, nil
	}
	connection, err := newGRPCConnection(config)
	if err != nil {
		return nil, err
	}
	adapter.connection = connection
	adapter.grpcClient = collectorlogpb.NewLogsServiceClient(connection)
	return adapter, nil
}

// EncodedSize conservatively accounts for the complete protobuf request. The
// fixed per-record allowance is the normative v8 projection-wrapper ceiling.
func (adapter *LogAdapter) EncodedSize(projectedSizes []int) (int, bool) {
	if adapter == nil {
		return 0, false
	}
	return canonicalLogEncodedSize(projectedSizes)
}

func (adapter *LogAdapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	estimate, ok := adapter.EncodedSize(batchSizes(batch))
	if !ok || estimate != batch.EncodedSize() || estimate > adapter.maxBytes {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	request, ok := adapter.builder.Build(batch)
	if !ok || proto.Size(request) > estimate {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if !adapter.lock(ctx) {
		return deliveryResult(delivery.OutcomeTransient)
	}
	defer adapter.unlock()
	if adapter.closed {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	recordCount := batch.Len()
	adapter.counters.accepted.Add(uint64(recordCount))
	attemptContext, cancel := context.WithTimeout(ctx, adapter.config.timeout)
	defer cancel()
	if adapter.config.protocol == ProtocolHTTP {
		return adapter.deliverHTTP(attemptContext, request, recordCount)
	}
	return adapter.deliverGRPC(attemptContext, request, recordCount)
}

// projectCanonicalLogFields promotes canonical record metadata into the
// standard OTLP LogRecord fields used by backends for log-to-trace joins,
// timestamp ordering, and severity filtering. The complete destination-
// projected canonical JSON remains the body and is still authoritative.
func projectCanonicalLogFields(record *logspb.LogRecord, projected []byte) {
	if record == nil {
		return
	}
	var wire struct {
		Timestamp   string         `json:"timestamp"`
		Severity    string         `json:"severity"`
		LogLevel    string         `json:"log_level"`
		Correlation map[string]any `json:"correlation"`
	}
	if err := json.Unmarshal(projected, &wire); err != nil {
		return
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, wire.Timestamp); err == nil {
		record.TimeUnixNano = uint64(timestamp.UnixNano())
		record.ObservedTimeUnixNano = record.TimeUnixNano
	}
	level := strings.ToUpper(strings.TrimSpace(wire.LogLevel))
	if level == "" {
		level = strings.ToUpper(strings.TrimSpace(wire.Severity))
	}
	record.SeverityText = level
	record.SeverityNumber = canonicalLogSeverityNumber(level)
	if wire.Correlation == nil {
		return
	}
	if value, _ := wire.Correlation["trace_id"].(string); value != "" {
		if decoded, ok := exactHex(value, 16); ok {
			record.TraceId = decoded
		}
	}
	if value, _ := wire.Correlation["span_id"].(string); value != "" {
		if decoded, ok := exactHex(value, 8); ok {
			record.SpanId = decoded
		}
	}
}

func canonicalLogSeverityNumber(level string) logspb.SeverityNumber {
	switch level {
	case "TRACE":
		return logspb.SeverityNumber_SEVERITY_NUMBER_TRACE
	case "DEBUG":
		return logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG
	case "INFO":
		return logspb.SeverityNumber_SEVERITY_NUMBER_INFO
	case "WARN", "WARNING":
		return logspb.SeverityNumber_SEVERITY_NUMBER_WARN
	case "ERROR":
		return logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
	case "FATAL":
		return logspb.SeverityNumber_SEVERITY_NUMBER_FATAL
	default:
		return logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED
	}
}

func (adapter *LogAdapter) deliverHTTP(ctx context.Context, request *collectorlogpb.ExportLogsServiceRequest, recordCount int) delivery.DeliveryResult {
	encoded, err := proto.Marshal(request)
	if err != nil {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, signalURL(adapter.config), bytes.NewReader(encoded))
	if err != nil {
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	httpRequest.Header.Set("Content-Type", "application/x-protobuf")
	for key, value := range adapter.config.headers {
		httpRequest.Header.Set(key, value)
	}
	var wroteRequest atomic.Bool
	httpRequest = httpRequest.WithContext(httptrace.WithClientTrace(httpRequest.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}))
	dialSequence := adapter.config.tracker.snapshot()
	response, err := adapter.httpClient.Do(httpRequest)
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
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxLogResponseBodyBytes+1))
	if readErr != nil || len(body) > maxLogResponseBodyBytes {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	if len(body) == 0 {
		adapter.recordLogSuccess(recordCount, 0)
		return deliveryResult(delivery.OutcomeDelivered)
	}
	var result collectorlogpb.ExportLogsServiceResponse
	if err := proto.Unmarshal(body, &result); err != nil {
		return deliveryResult(delivery.OutcomeAmbiguous)
	}
	if result.PartialSuccess != nil && result.PartialSuccess.RejectedLogRecords < 0 {
		adapter.recordLogFailure(recordCount)
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if result.PartialSuccess != nil && result.PartialSuccess.RejectedLogRecords > 0 {
		accepted, rejected := adapter.recordLogSuccess(recordCount, result.PartialSuccess.RejectedLogRecords)
		if accepted > 0 && rejected > 0 {
			return delivery.DeliveryResult{
				Outcome: delivery.OutcomePartial, DeliveredItems: accepted, RejectedItems: rejected,
			}
		}
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	adapter.recordLogSuccess(recordCount, 0)
	return deliveryResult(delivery.OutcomeDelivered)
}

func (adapter *LogAdapter) deliverGRPC(ctx context.Context, request *collectorlogpb.ExportLogsServiceRequest, recordCount int) delivery.DeliveryResult {
	dialSequence := adapter.config.tracker.snapshot()
	headers := make(map[string]string, len(adapter.config.headers))
	for key, value := range adapter.config.headers {
		headers[strings.ToLower(key)] = value
	}
	if len(headers) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, metadata.New(headers))
	}
	response, err := adapter.grpcClient.Export(ctx, request)
	if err != nil {
		if adapter.config.tracker.unsafeSince(dialSequence) || errors.Is(err, netguard.ErrV8AddressProhibited) || errors.Is(err, netguard.ErrV8EndpointInvalid) {
			return deliveryResult(delivery.OutcomeUnsafeEndpoint)
		}
		switch status.Code(err) {
		case codes.Unauthenticated, codes.PermissionDenied:
			return deliveryResult(delivery.OutcomeAuthentication)
		case codes.InvalidArgument, codes.FailedPrecondition, codes.Unimplemented, codes.OutOfRange:
			return deliveryResult(delivery.OutcomePermanentPayload)
		case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Canceled:
			return deliveryResult(delivery.OutcomeTransient)
		default:
			return deliveryResult(delivery.OutcomeAmbiguous)
		}
	}
	if response != nil && response.PartialSuccess != nil && response.PartialSuccess.RejectedLogRecords < 0 {
		adapter.recordLogFailure(recordCount)
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	if response != nil && response.PartialSuccess != nil && response.PartialSuccess.RejectedLogRecords > 0 {
		accepted, rejected := adapter.recordLogSuccess(recordCount, response.PartialSuccess.RejectedLogRecords)
		if accepted > 0 && rejected > 0 {
			return delivery.DeliveryResult{
				Outcome: delivery.OutcomePartial, DeliveredItems: accepted, RejectedItems: rejected,
			}
		}
		return deliveryResult(delivery.OutcomePermanentPayload)
	}
	adapter.recordLogSuccess(recordCount, 0)
	return deliveryResult(delivery.OutcomeDelivered)
}

func (adapter *LogAdapter) recordLogFailure(total int) {
	if total <= 0 {
		return
	}
	adapter.counters.failed.Add(uint64(total))
	observe(adapter.config.observer, SignalEvent{
		Signal: observability.SignalLogs, Outcome: SignalOutcomeExportFailed, Count: uint64(total),
	})
}

func (adapter *LogAdapter) recordLogSuccess(total int, rejected int64) (int, int) {
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
		observe(adapter.config.observer, SignalEvent{Signal: observability.SignalLogs, Outcome: SignalOutcomeExported, Count: uint64(accepted)})
	}
	if rejected > 0 {
		adapter.counters.rejectedPartial.Add(uint64(rejected))
		observe(adapter.config.observer, SignalEvent{Signal: observability.SignalLogs, Outcome: SignalOutcomePartialRejected, Count: uint64(rejected)})
	}
	return accepted, int(rejected)
}

func (adapter *LogAdapter) Close(ctx context.Context) error {
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

func (adapter *LogAdapter) lock(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-adapter.gate:
		return true
	}
}

func (adapter *LogAdapter) unlock() { adapter.gate <- struct{}{} }

func (adapter *LogAdapter) Counters() ExportCounters {
	if adapter == nil {
		return ExportCounters{}
	}
	return adapter.counters.snapshot()
}

func stringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}}
}

func batchSizes(batch delivery.Batch) []int {
	items := batch.Items()
	sizes := make([]int, len(items))
	for index := range items {
		sizes[index] = items[index].Size()
	}
	return sizes
}

func deliveryResult(outcome delivery.DeliveryOutcome) delivery.DeliveryResult {
	return delivery.DeliveryResult{Outcome: outcome}
}

const maxInt = int(^uint(0) >> 1)
