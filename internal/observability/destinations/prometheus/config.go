// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package prometheus implements the generation-owned observability-v8 native
// Prometheus pull destination. It uses the official OpenTelemetry Prometheus
// exporter with a private registry and never registers with Prometheus or OTel
// process globals.
//
// Prometheus pull readers are cumulative by protocol convention. A v8 plan's
// delta temporality remains authoritative for independent push readers; the
// SDK gives this pull reader its own cumulative aggregation pipeline. The
// configured export interval is likewise not a hidden scrape interval: the
// Prometheus server collects only when requested and owns no push queue.
package prometheus

import (
	"context"
	"errors"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	prom "github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	maxListenBytes = 512
	maxPathBytes   = 4_096
)

// ErrorCode is a closed content-free destination failure identity.
type ErrorCode string

const (
	ErrorInvalidConfig  ErrorCode = "invalid_config"
	ErrorUnsafeListen   ErrorCode = "unsafe_listen"
	ErrorExporterInit   ErrorCode = "exporter_initialization_failed"
	ErrorListenFailed   ErrorCode = "listener_failed"
	ErrorGatherFailed   ErrorCode = "gather_failed"
	ErrorUnknownFamily  ErrorCode = "unknown_metric_family"
	ErrorUnknownLabel   ErrorCode = "unknown_metric_label"
	ErrorRecordFailed   ErrorCode = "metric_record_failed"
	ErrorFlushFailed    ErrorCode = "metric_flush_failed"
	ErrorServerFailed   ErrorCode = "server_failed"
	ErrorShutdownFailed ErrorCode = "shutdown_failed"
)

// Error contains neither listener addresses, paths, metric/label names, nor
// wrapped transport diagnostics. Context cancellation identity is retained.
type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string {
	if err == nil {
		return "prometheus destination failed"
	}
	return "prometheus destination failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func newError(code ErrorCode, cause error) *Error {
	switch {
	case errors.Is(cause, context.Canceled):
		cause = context.Canceled
	case errors.Is(cause, context.DeadlineExceeded):
		cause = context.DeadlineExceeded
	default:
		cause = nil
	}
	return &Error{code: code, cause: cause}
}

func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

// ListenFunc is an injectable equivalent of net.ListenConfig.Listen.
type ListenFunc func(context.Context, string, string) (net.Listener, error)

// Options are process-stable dependencies. Neither option is sourced from the
// environment. Nil selects the standard TCP listener and a no-op observer.
type Options struct {
	Listen   ListenFunc
	Observer Observer
}

// Factory snapshots one compiled destination and can prepare a fresh reader
// and private HTTP server for each graph generation.
type Factory struct {
	destination  string
	listen       string
	path         string
	selected     map[string]struct{}
	matcher      familyMatcher
	labels       map[string]struct{}
	listenFunc   ListenFunc
	observer     *boundedObserver
	drainTimeout time.Duration
}

// NewFactory validates the detached effective destination without resolving
// environment state or binding its listener.
func NewFactory(destination config.ObservabilityV8EffectiveDestination, options Options) (*Factory, error) {
	if destination.Kind != config.ObservabilityV8DestinationPrometheus || !destination.Enabled ||
		!observability.IsStableToken(destination.Name) ||
		!destination.Capabilities.Supports(observability.SignalMetrics) ||
		!containsSignal(destination.SelectedSignals, observability.SignalMetrics) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	if err := validateListen(destination.Transport.Listen); err != nil {
		return nil, err
	}
	if !validPath(destination.Transport.Path) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	catalog := telemetry.V8MetricCatalog()
	selected := selectMetrics(catalog, destination.Routes)
	matcher, err := newFamilyMatcher(catalog, selected)
	if err != nil {
		return nil, err
	}
	labels, err := normalizedAllowedLabels(telemetry.V8MetricAllowedAttributeKeys())
	if err != nil {
		return nil, err
	}
	listenFunc := options.Listen
	if listenFunc == nil {
		listener := &net.ListenConfig{}
		listenFunc = listener.Listen
	}
	observer := newBoundedObserver(options.Observer)
	return &Factory{
		destination:  destination.Name,
		listen:       destination.Transport.Listen,
		path:         destination.Transport.Path,
		selected:     cloneSet(selected),
		matcher:      matcher,
		labels:       labels,
		listenFunc:   listenFunc,
		observer:     observer,
		drainTimeout: defaultDrainTimeout,
	}, nil
}

func validateListen(address string) error {
	if !utf8.ValidString(address) || len(address) == 0 || len(address) > maxListenBytes {
		return newError(ErrorInvalidConfig, nil)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || host == "" {
		return newError(ErrorInvalidConfig, nil)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65_535 {
		return newError(ErrorInvalidConfig, nil)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	parsed := net.ParseIP(strings.Trim(host, "[]"))
	if parsed == nil {
		return newError(ErrorUnsafeListen, nil)
	}
	if !parsed.IsLoopback() {
		return newError(ErrorUnsafeListen, nil)
	}
	return nil
}

func validPath(value string) bool {
	return utf8.ValidString(value) && len(value) > 0 && len(value) <= maxPathBytes &&
		strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "?#\x00\r\n") &&
		path.Clean(value) == value
}

func containsSignal(signals []observability.Signal, signal observability.Signal) bool {
	for _, candidate := range signals {
		if candidate == signal {
			return true
		}
	}
	return false
}

func selectMetrics(
	catalog []telemetry.V8MetricDefinition,
	routes []config.ObservabilityV8EffectiveRoute,
) map[string]struct{} {
	selected := make(map[string]struct{}, len(catalog))
	for _, metric := range catalog {
		for _, route := range routes {
			if !containsSignal(route.Signals, observability.SignalMetrics) ||
				!metricMatchesSelector(metric, route.Selector) {
				continue
			}
			if route.Action == config.ObservabilityV8RouteSend {
				selected[metric.Name] = struct{}{}
			}
			break
		}
	}
	return selected
}

func metricMatchesSelector(
	metric telemetry.V8MetricDefinition,
	selector config.ObservabilityV8EffectiveSelector,
) bool {
	// Metrics have no per-measurement source, connector, producer action, or
	// severity identity. A selector requiring one of those fields cannot match.
	if len(selector.Sources) > 0 || len(selector.Connectors) > 0 || len(selector.Actions) > 0 || selector.MinSeverity != "" {
		return false
	}
	if !selector.BucketWildcard && !containsBucket(selector.Buckets, metric.Bucket) {
		return false
	}
	if len(selector.EventNames) > 0 && !containsEventName(selector.EventNames, observability.EventName(metric.Name)) {
		return false
	}
	return true
}

func containsBucket(buckets []observability.Bucket, bucket observability.Bucket) bool {
	for _, candidate := range buckets {
		if candidate == bucket {
			return true
		}
	}
	return false
}

func containsEventName(names []observability.EventName, name observability.EventName) bool {
	for _, candidate := range names {
		if candidate == name || candidate == "*" {
			return true
		}
	}
	return false
}

type familyMatch struct {
	original       string
	base           string
	instrumentType string
	selected       bool
}

type familyMatcher struct{ entries []familyMatch }

func newFamilyMatcher(
	catalog []telemetry.V8MetricDefinition,
	selected map[string]struct{},
) (familyMatcher, error) {
	descriptors, err := telemetry.V8MetricDescriptorCatalog()
	if err != nil {
		return familyMatcher{}, newError(ErrorInvalidConfig, nil)
	}
	instrumentTypes := make(map[string]string, len(descriptors))
	for _, descriptor := range descriptors {
		instrumentTypes[descriptor.Name] = descriptor.InstrumentType
	}
	entries := make([]familyMatch, 0, len(catalog))
	seen := make(map[string]struct{}, len(catalog))
	for _, metric := range catalog {
		base, err := normalizeIdentifier(metric.Name)
		if err != nil {
			return familyMatcher{}, newError(ErrorInvalidConfig, nil)
		}
		instrumentType := instrumentTypes[metric.Name]
		if instrumentType == "" {
			return familyMatcher{}, newError(ErrorInvalidConfig, nil)
		}
		if _, duplicate := seen[base]; duplicate {
			return familyMatcher{}, newError(ErrorInvalidConfig, nil)
		}
		seen[base] = struct{}{}
		_, enabled := selected[metric.Name]
		entries = append(entries, familyMatch{
			original: metric.Name, base: base,
			instrumentType: instrumentType, selected: enabled,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		if len(entries[left].base) == len(entries[right].base) {
			return entries[left].base < entries[right].base
		}
		return len(entries[left].base) > len(entries[right].base)
	})
	return familyMatcher{entries: entries}, nil
}

func (matcher familyMatcher) instrumentType(name string, metricType dto.MetricType) (string, bool) {
	for _, entry := range matcher.entries {
		if officialFamilyShape(name, entry.base, metricType) {
			return entry.instrumentType, true
		}
	}
	return "", false
}

func (matcher familyMatcher) selectedFamily(name string, metricType dto.MetricType) (selected, known bool) {
	for _, entry := range matcher.entries {
		if officialFamilyShape(name, entry.base, metricType) {
			return entry.selected, true
		}
	}
	return false, false
}

// officialFamilyShape accepts only the closed name shapes produced by the
// configured OTel-to-Prometheus translation strategy for DefenseClaw's metric
// types and units. In particular, an arbitrary producer-created name that only
// shares a catalog prefix is not allowed to inherit that catalog entry's route.
func officialFamilyShape(name, base string, metricType dto.MetricType) bool {
	if metricType != dto.MetricType_COUNTER && metricType != dto.MetricType_HISTOGRAM &&
		metricType != dto.MetricType_GAUGE {
		return false
	}
	if name == base {
		return true
	}
	if !strings.HasPrefix(name, base+"_") {
		return false
	}
	suffix := strings.TrimPrefix(name, base)
	switch metricType {
	case dto.MetricType_COUNTER:
		return suffix == "_total" || suffix == "_bytes_total"
	case dto.MetricType_HISTOGRAM:
		return suffix == "_bytes" || suffix == "_milliseconds" ||
			suffix == "_nanoseconds" || suffix == "_seconds"
	case dto.MetricType_GAUGE:
		return suffix == "_bytes" || suffix == "_seconds" ||
			suffix == "_ratio" || suffix == "_USD"
	default:
		return false
	}
}

func normalizeIdentifier(value string) (string, error) {
	namer := otlptranslator.LabelNamer{UTF8Allowed: false}
	result, err := namer.Build(value)
	if err != nil || result == "" {
		return "", err
	}
	return result, nil
}

func normalizedAllowedLabels(source []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(source)+3)
	for _, key := range source {
		normalized, err := normalizeIdentifier(key)
		if err != nil {
			return nil, newError(ErrorInvalidConfig, nil)
		}
		result[normalized] = struct{}{}
	}
	// These are protocol/SDK labels, not producer-controlled metric labels.
	for _, key := range []string{"le", "quantile", "otel_metric_overflow"} {
		result[key] = struct{}{}
	}
	return result, nil
}

type filteredGatherer struct {
	source  prom.Gatherer
	matcher familyMatcher
	labels  map[string]struct{}
}

func (gatherer *filteredGatherer) Gather() ([]*dto.MetricFamily, error) {
	if gatherer == nil || gatherer.source == nil {
		return nil, newError(ErrorGatherFailed, nil)
	}
	families, err := gatherer.source.Gather()
	if err != nil {
		return nil, newError(ErrorGatherFailed, nil)
	}
	result := make([]*dto.MetricFamily, 0, len(families))
	for _, family := range families {
		if family == nil || family.Name == nil {
			return nil, newError(ErrorUnknownFamily, nil)
		}
		if family.Type == nil {
			return nil, newError(ErrorUnknownFamily, nil)
		}
		selected, known := gatherer.matcher.selectedFamily(family.GetName(), family.GetType())
		if !known {
			return nil, newError(ErrorUnknownFamily, nil)
		}
		if !selected {
			continue
		}
		if !knownLabels(family, gatherer.labels) {
			return nil, newError(ErrorUnknownLabel, nil)
		}
		// The DTO pointer is retained byte-for-byte: this destination filters
		// complete official-exporter families and never rebuilds names,
		// labels, samples, exemplars, or histogram buckets.
		result = append(result, family)
	}
	return result, nil
}

func knownLabels(family *dto.MetricFamily, allowed map[string]struct{}) bool {
	for _, metric := range family.Metric {
		if metric == nil {
			return false
		}
		for _, label := range metric.Label {
			if label == nil || label.Name == nil {
				return false
			}
			if _, ok := allowed[label.GetName()]; !ok {
				return false
			}
		}
	}
	return true
}

func cloneSet(input map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(input))
	for key := range input {
		result[key] = struct{}{}
	}
	return result
}

// PrometheusTemporality documents the fixed pull-reader conversion without
// changing the process metric policy used by independent push readers.
func PrometheusTemporality() metricdata.Temporality { return metricdata.CumulativeTemporality }

// SelectedMetrics returns a detached lexical catalog subset.
func (factory *Factory) SelectedMetrics() []string {
	if factory == nil {
		return nil
	}
	result := make([]string, 0, len(factory.selected))
	for name := range factory.selected {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// ReaderFactory returns the generation callback consumed by
// telemetry.V8ProviderOptions.MetricReaderFactories.
func (factory *Factory) ReaderFactory() telemetry.V8MetricReaderFactory {
	if factory == nil {
		return nil
	}
	return factory.Prepare
}

var _ prom.Gatherer = (*filteredGatherer)(nil)
