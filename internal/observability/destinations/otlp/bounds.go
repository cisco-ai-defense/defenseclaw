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
	"reflect"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const encodedEnvelopeAllowance = 65_536

// ExportCounters are content-free, monotonic per-signal counters.
type ExportCounters struct {
	Accepted         uint64
	Exported         uint64
	Retried          uint64
	RejectedPartial  uint64
	RejectedOversize uint64
	Failed           uint64
	DroppedQueueFull uint64
}

type mutableCounters struct {
	accepted, exported, retried, rejectedPartial, rejectedOversize, failed, droppedQueueFull atomic.Uint64
}

func (c *mutableCounters) snapshot() ExportCounters {
	if c == nil {
		return ExportCounters{}
	}
	return ExportCounters{
		Accepted: c.accepted.Load(), Exported: c.exported.Load(),
		Retried:          c.retried.Load(),
		RejectedPartial:  c.rejectedPartial.Load(),
		RejectedOversize: c.rejectedOversize.Load(), Failed: c.failed.Load(),
		DroppedQueueFull: c.droppedQueueFull.Load(),
	}
}

func observe(observer SignalObserver, event SignalEvent) {
	if observer == nil {
		return
	}
	defer func() { _ = recover() }()
	observer.ObserveOTLPSignal(event)
}

func recordRetryAttempts(counters *mutableCounters, observer SignalObserver, signal observability.Signal, count, attempts uint64) {
	if counters == nil || attempts <= 1 || count == 0 {
		return
	}
	retried := (attempts - 1) * count
	counters.retried.Add(retried)
	observe(observer, SignalEvent{Signal: signal, Outcome: SignalOutcomeRetried, Count: retried})
}

// conservativeSpanBytes is a strict upper bound for the OTLP protobuf produced
// from one ReadOnlySpan. Every source byte is charged twice, every primitive or
// message edge is charged 128 bytes (protobuf tags and length varints need at
// most 20), and a 64-KiB envelope covers resource/scope/request grouping. The
// transform does not synthesize content bytes that are absent from these public
// span/resource/scope values.
func conservativeSpanBytes(span sdktrace.ReadOnlySpan) (int, bool) {
	if span == nil {
		return 0, false
	}
	bytes, nodes := 0, 1
	addString := func(value string) bool { return safeAdd(&bytes, len(value)) }
	if !addString(span.Name()) {
		return 0, false
	}
	if !safeNodeAdd(&nodes, 16) {
		return 0, false
	}
	for _, value := range span.Attributes() {
		if !addAttributeBound(&bytes, &nodes, value) {
			return 0, false
		}
	}
	for _, event := range span.Events() {
		if !safeNodeAdd(&nodes, 8) {
			return 0, false
		}
		if !addString(event.Name) {
			return 0, false
		}
		for _, value := range event.Attributes {
			if !addAttributeBound(&bytes, &nodes, value) {
				return 0, false
			}
		}
	}
	for _, link := range span.Links() {
		if !safeNodeAdd(&nodes, 8) {
			return 0, false
		}
		for _, value := range link.Attributes {
			if !addAttributeBound(&bytes, &nodes, value) {
				return 0, false
			}
		}
	}
	status := span.Status()
	if !addString(status.Description) {
		return 0, false
	}
	scope := span.InstrumentationScope()
	for _, value := range []string{scope.Name, scope.Version, scope.SchemaURL} {
		if !addString(value) {
			return 0, false
		}
	}
	if resource := span.Resource(); resource != nil {
		if !addString(resource.SchemaURL()) {
			return 0, false
		}
		for _, value := range resource.Set().ToSlice() {
			if !addAttributeBound(&bytes, &nodes, value) {
				return 0, false
			}
		}
	}
	return finishBound(bytes, nodes)
}

func conservativeMetricBytes(metrics *metricdata.ResourceMetrics) (int, bool) {
	if metrics == nil {
		return 0, false
	}
	bytes, nodes := 0, 1
	if metrics.Resource != nil {
		if !safeAdd(&bytes, len(metrics.Resource.SchemaURL())) {
			return 0, false
		}
		for _, value := range metrics.Resource.Set().ToSlice() {
			if !addAttributeBound(&bytes, &nodes, value) {
				return 0, false
			}
		}
	}
	for _, scope := range metrics.ScopeMetrics {
		if !safeNodeAdd(&nodes, 4) {
			return 0, false
		}
		for _, value := range []string{scope.Scope.Name, scope.Scope.Version, scope.Scope.SchemaURL} {
			if !safeAdd(&bytes, len(value)) {
				return 0, false
			}
		}
		for _, metric := range scope.Metrics {
			if !safeNodeAdd(&nodes, 8) {
				return 0, false
			}
			for _, value := range []string{metric.Name, metric.Description, metric.Unit} {
				if !safeAdd(&bytes, len(value)) {
					return 0, false
				}
			}
			if !addReflectedBound(&bytes, &nodes, reflect.ValueOf(metric.Data), make(map[visit]struct{}), 0) {
				return 0, false
			}
		}
	}
	return finishBound(bytes, nodes)
}

func addAttributeBound(bytes, nodes *int, value attribute.KeyValue) bool {
	if !safeNodeAdd(nodes, 4) {
		return false
	}
	if !safeAdd(bytes, len(value.Key)) {
		return false
	}
	switch value.Value.Type() {
	case attribute.STRING:
		return safeAdd(bytes, len(value.Value.AsString()))
	case attribute.STRINGSLICE:
		for _, item := range value.Value.AsStringSlice() {
			if !safeNodeAdd(nodes, 2) {
				return false
			}
			if !safeAdd(bytes, len(item)) {
				return false
			}
		}
	case attribute.BOOLSLICE:
		return safeNodeAdd(nodes, len(value.Value.AsBoolSlice()))
	case attribute.INT64SLICE:
		return safeNodeAdd(nodes, len(value.Value.AsInt64Slice()))
	case attribute.FLOAT64SLICE:
		return safeNodeAdd(nodes, len(value.Value.AsFloat64Slice()))
	default:
		return safeNodeAdd(nodes, 1)
	}
	return true
}

type visit struct {
	typeName reflect.Type
	pointer  uintptr
}

func addReflectedBound(bytes, nodes *int, value reflect.Value, seen map[visit]struct{}, depth int) bool {
	if !value.IsValid() || depth > 64 {
		return depth <= 64
	}
	if !safeNodeAdd(nodes, 1) {
		return false
	}
	if value.CanInterface() {
		switch typed := value.Interface().(type) {
		case time.Time:
			return safeNodeAdd(nodes, 4)
		case attribute.Set:
			for _, item := range typed.ToSlice() {
				if !addAttributeBound(bytes, nodes, item) {
					return false
				}
			}
			return true
		case attribute.Value:
			return addAttributeBound(bytes, nodes, attribute.KeyValue{Value: typed})
		}
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return true
		}
		key := visit{typeName: value.Type(), pointer: value.Pointer()}
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
		return addReflectedBound(bytes, nodes, value.Elem(), seen, depth+1)
	case reflect.String:
		return safeAdd(bytes, value.Len())
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && !value.IsNil() {
			key := visit{typeName: value.Type(), pointer: value.Pointer()}
			if _, ok := seen[key]; ok {
				return true
			}
			seen[key] = struct{}{}
		}
		for index := 0; index < value.Len(); index++ {
			if !addReflectedBound(bytes, nodes, value.Index(index), seen, depth+1) {
				return false
			}
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if !addReflectedBound(bytes, nodes, value.Field(index), seen, depth+1) {
				return false
			}
		}
	case reflect.Map:
		if value.IsNil() {
			return true
		}
		iterator := value.MapRange()
		for iterator.Next() {
			if !addReflectedBound(bytes, nodes, iterator.Key(), seen, depth+1) ||
				!addReflectedBound(bytes, nodes, iterator.Value(), seen, depth+1) {
				return false
			}
		}
	default:
		return safeNodeAdd(nodes, 1)
	}
	return true
}

func finishBound(contentBytes, nodes int) (int, bool) {
	if contentBytes < 0 || nodes < 0 || contentBytes > (maxInt-encodedEnvelopeAllowance)/2 {
		return 0, false
	}
	total := encodedEnvelopeAllowance + 2*contentBytes
	if nodes > (maxInt-total)/128 {
		return 0, false
	}
	return total + nodes*128, true
}

func safeAdd(target *int, value int) bool {
	if value < 0 || *target > maxInt-value {
		return false
	}
	*target += value
	return true
}

func safeNodeAdd(target *int, value int) bool { return safeAdd(target, value) }
