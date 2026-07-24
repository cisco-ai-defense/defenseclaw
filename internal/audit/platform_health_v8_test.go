// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type sinkHealthTestRuntime struct {
	logs *testRuntimeV8Emitter

	mu      sync.Mutex
	metrics []observability.Record
	err     error
}

type rejectingSinkHealthRuntime struct {
	logCalls    int
	metricCalls int
}

type evaluatingSinkHealthRuntime struct {
	base      *sinkHealthTestRuntime
	evaluator *router.Evaluator

	mu         sync.Mutex
	deliveries [][]router.Delivery
}

func (runtime *evaluatingSinkHealthRuntime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	result, err := runtime.evaluator.Evaluate(metadata, func(admission router.Admission) (observability.Record, error) {
		return builder(RuntimeV8BuildContext{
			ConfigGeneration: 23, ConfigDigest: testEventHistoryGraphDigest,
		}, admission)
	})
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	runtime.mu.Lock()
	runtime.deliveries = append(runtime.deliveries, result.Deliveries())
	runtime.mu.Unlock()
	if result.Admission() == router.AdmissionDrop {
		return RuntimeV8EmitOutcome{Admission: router.AdmissionDrop}, nil
	}
	record, ok := result.Record()
	if !ok {
		return RuntimeV8EmitOutcome{}, errors.New("test evaluator admitted no record")
	}
	projection, _, err := testEventHistoryProjectionEngine.Project(record, runtime.base.logs.profile)
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	if err := runtime.base.logs.writer.AppendContext(ctx, record, projection); err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	runtime.base.logs.mu.Lock()
	runtime.base.logs.metadata = append(runtime.base.logs.metadata, metadata)
	runtime.base.logs.records = append(runtime.base.logs.records, record.Clone())
	runtime.base.logs.mu.Unlock()
	return RuntimeV8EmitOutcome{Admission: result.Admission(), LocalPersisted: true}, nil
}

func (runtime *evaluatingSinkHealthRuntime) RecordRuntimeV8GeneratedMetric(
	ctx context.Context,
	metric RuntimeV8GeneratedMetric,
) error {
	return runtime.base.RecordRuntimeV8GeneratedMetric(ctx, metric)
}

func (runtime *evaluatingSinkHealthRuntime) RecordRuntimeV8GeneratedMetricBatch(
	ctx context.Context,
	metrics []RuntimeV8GeneratedMetric,
) error {
	return runtime.base.RecordRuntimeV8GeneratedMetricBatch(ctx, metrics)
}

func (runtime *evaluatingSinkHealthRuntime) deliverySnapshot() [][]router.Delivery {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	result := make([][]router.Delivery, len(runtime.deliveries))
	for index := range runtime.deliveries {
		result[index] = append([]router.Delivery(nil), runtime.deliveries[index]...)
	}
	return result
}

func (runtime *rejectingSinkHealthRuntime) EmitRuntimeV8(
	context.Context,
	router.Metadata,
	RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	runtime.logCalls++
	return RuntimeV8EmitOutcome{}, errors.New("private runtime failure")
}

func (runtime *rejectingSinkHealthRuntime) RecordRuntimeV8GeneratedMetric(
	context.Context,
	RuntimeV8GeneratedMetric,
) error {
	runtime.metricCalls++
	return errors.New("private metric failure")
}

func (runtime *rejectingSinkHealthRuntime) RecordRuntimeV8GeneratedMetricBatch(
	context.Context,
	[]RuntimeV8GeneratedMetric,
) error {
	runtime.metricCalls++
	return errors.New("private metric batch failure")
}

func newSinkHealthTestRuntime(
	t *testing.T,
	logger *Logger,
	admission router.Admission,
) *sinkHealthTestRuntime {
	t.Helper()
	return &sinkHealthTestRuntime{
		logs: newTestRuntimeV8Emitter(t, logger.store, admission),
	}
}

func (runtime *sinkHealthTestRuntime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	return runtime.logs.EmitRuntimeV8(ctx, metadata, builder)
}

func (runtime *sinkHealthTestRuntime) RecordRuntimeV8GeneratedMetric(
	_ context.Context,
	metric RuntimeV8GeneratedMetric,
) error {
	if runtime.err != nil {
		return runtime.err
	}
	record, err := metric.Build(RuntimeV8BuildContext{
		ConfigGeneration: 23,
		ConfigDigest:     testEventHistoryGraphDigest,
	})
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.metrics = append(runtime.metrics, record.Clone())
	runtime.mu.Unlock()
	return nil
}

func (runtime *sinkHealthTestRuntime) RecordRuntimeV8GeneratedMetricBatch(
	_ context.Context,
	metrics []RuntimeV8GeneratedMetric,
) error {
	if runtime.err != nil {
		return runtime.err
	}
	records := make([]observability.Record, len(metrics))
	for index, metric := range metrics {
		record, err := metric.Build(RuntimeV8BuildContext{
			ConfigGeneration: 23,
			ConfigDigest:     testEventHistoryGraphDigest,
		})
		if err != nil {
			return err
		}
		records[index] = record.Clone()
	}
	runtime.mu.Lock()
	runtime.metrics = append(runtime.metrics, records...)
	runtime.mu.Unlock()
	return nil
}

func (runtime *sinkHealthTestRuntime) snapshot() ([]observability.Record, []observability.Record) {
	_, logs := runtime.logs.snapshot()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	metrics := make([]observability.Record, len(runtime.metrics))
	for index := range runtime.metrics {
		metrics[index] = runtime.metrics[index].Clone()
	}
	return logs, metrics
}

func TestSafeSinkHealthDimensionPreservesNamesAndHashesEndpoints(t *testing.T) {
	if got := safeSinkHealthDimension("primary"); got != "primary" {
		t.Fatalf("stable name = %q", got)
	}
	if got := safeSinkHealthDimension("SOC Primary"); got != "soc-primary" {
		t.Fatalf("display name = %q", got)
	}
	first := safeSinkHealthDimension("https://collector-a.example/v1")
	second := safeSinkHealthDimension("HTTPS://collector-b.example/v1")
	if first == second || !observability.IsStableToken(first) || !observability.IsStableToken(second) ||
		strings.Contains(first, "collector") || strings.Contains(second, "collector") {
		t.Fatalf("endpoint identities = %q, %q", first, second)
	}
}

func TestRuntimeV8GeneratedMetricRejectsZeroAndIdentityMismatch(t *testing.T) {
	if _, err := (RuntimeV8GeneratedMetric{}).Build(RuntimeV8BuildContext{}); err == nil {
		t.Fatal("zero generated metric operation was accepted")
	}
	metric := RuntimeV8GeneratedMetric{
		family: observability.EventName(observability.TelemetryInstrumentDefenseClawAuditSinkFailures),
		build: func(RuntimeV8BuildContext) (observability.Record, error) {
			valid, err := newSinkRuntimeV8GeneratedMetric(sinkMetricV8Input{
				kind: sinkMetricV8CircuitState, valueInt: 1,
				sinkKind: "splunk_hec", sinkName: "primary",
				action:    string(ActionSinkFailure),
				timestamp: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				return observability.Record{}, err
			}
			return valid.Build(RuntimeV8BuildContext{
				ConfigGeneration: 23, ConfigDigest: testEventHistoryGraphDigest,
			})
		},
	}
	if _, err := metric.Build(RuntimeV8BuildContext{}); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("identity mismatch error = %v", err)
	}
}
