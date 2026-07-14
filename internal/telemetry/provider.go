// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	logNoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricNoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	traceNoop "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/credentials"

	loggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	loghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	metricgrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	tracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	tracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
)

// Provider holds the OTel SDK providers and exposes telemetry emission methods.
// When OTel is disabled, a no-op provider is returned whose methods do nothing.
type Provider struct {
	cfg            config.OTelConfig
	res            *resource.Resource
	tracerProvider *sdktrace.TracerProvider
	loggerProvider *sdklog.LoggerProvider
	meterProvider  *sdkmetric.MeterProvider

	tracer  trace.Tracer
	logger  otellog.Logger
	meter   metric.Meter
	metrics *metricsSet

	enabled bool

	startTime time.Time

	// capacityShutdown stops the 15s runtime/SQLite metrics goroutine.
	capacityShutdown context.CancelFunc
	shutdown         atomic.Bool

	// agentInstanceID is the per-process stable identifier the
	// sidecar mints at boot. Accessed from multiple goroutines
	// (every StartAgentSpan / StartToolSpan call reads it) so we
	// guard it with an atomic load rather than a mutex; writes
	// happen exactly once during NewSidecar.
	agentInstanceID atomic.Value // string

	routingMu      sync.RWMutex
	routingByName  map[string]*destinationRoutingCounters
	deliveryMu     sync.RWMutex
	deliveryByName map[string]*destinationDeliveryCounters

	// cloudAuth is the CMID credential source shared with the managed
	// inspector. Set only in managed_enterprise when the Cisco AI Defense
	// telemetry log sink is provisioned (see newCiscoAIDLogProcessor).
	cloudAuth cloudreg.Provider
}

// ProviderOption customizes provider construction.
type ProviderOption func(*providerOptions)

type providerOptions struct {
	cloudAuth cloudreg.Provider
}

// WithCloudAuthProvider injects a shared CMID credential provider so the
// managed inspector and the Cisco AI Defense telemetry log sink coordinate one
// token cache and one Invalidate lifecycle. When omitted, the provider is
// lazily constructed via cloudreg.New only if the Cisco sink is required.
func WithCloudAuthProvider(p cloudreg.Provider) ProviderOption {
	return func(o *providerOptions) {
		o.cloudAuth = p
	}
}

// NewProvider initializes the OTel SDK providers and exporters. When
// cfg.Enabled is false, it returns a no-op provider safe to call.
func NewProvider(ctx context.Context, fullCfg *config.Config, version string, opts ...ProviderOption) (*Provider, error) {
	return newProvider(ctx, fullCfg, version, true, opts...)
}

// NewProviderInactive constructs a provider without installing it as the
// package-global telemetry provider. Config reload uses this to validate and
// prepare a replacement before committing the new config snapshot.
func NewProviderInactive(ctx context.Context, fullCfg *config.Config, version string, opts ...ProviderOption) (*Provider, error) {
	return newProvider(ctx, fullCfg, version, false, opts...)
}

func newProvider(ctx context.Context, fullCfg *config.Config, version string, install bool, opts ...ProviderOption) (*Provider, error) {
	var po providerOptions
	for _, opt := range opts {
		opt(&po)
	}
	cfg := fullCfg.OTel
	// The managed_enterprise Cisco AI Defense log sink is auto-provisioned
	// from deployment_mode + cisco_ai_defense.endpoint alone — it does NOT
	// require otel.enabled or any user destination. So the SDK must be built
	// (not short-circuited to a no-op) whenever either otel.enabled is set OR
	// the managed sink applies. Shares config.HasManagedAIDLogSink so this
	// predicate has a single definition and cannot drift.
	ciscoAIDLogSink := fullCfg.HasManagedAIDLogSink()
	if !cfg.Enabled && !ciscoAIDLogSink {
		p := &Provider{
			enabled: false,
			tracer:  traceNoop.NewTracerProvider().Tracer("defenseclaw"),
			logger:  logNoop.NewLoggerProvider().Logger("defenseclaw"),
			meter:   metricNoop.NewMeterProvider().Meter("defenseclaw"),
		}
		if install {
			installGlobalHooks(p)
		}
		return p, nil
	}

	res := buildResource(fullCfg, version)
	destinations := effectiveOTelDestinations(cfg)

	p := &Provider{
		cfg:       cfg,
		res:       res,
		enabled:   true,
		startTime: time.Now(),
	}

	traceOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(buildSampler(cfg.Traces.Sampler, cfg.Traces.SamplerArg)),
	}
	traceCount := 0
	for _, destination := range destinations {
		if !destination.cfg.Enabled || !destination.cfg.Traces.Enabled {
			continue
		}
		processor, err := newSpanProcessor(
			ctx, destination.cfg, expandHeaders(destination.cfg.Headers), p, destination.name,
		)
		if err != nil {
			return nil, fmt.Errorf("telemetry: destination %q traces: %w", destination.name, err)
		}
		if destination.filter.Enabled() {
			processor = &filteredSpanProcessor{
				next:        processor,
				provider:    p,
				destination: destination.name,
				filter:      destination.filter,
			}
		}
		traceOpts = append(traceOpts, sdktrace.WithSpanProcessor(processor))
		traceCount++
	}
	if traceCount > 0 {
		tp := sdktrace.NewTracerProvider(traceOpts...)
		p.tracerProvider = tp
		p.tracer = tp.Tracer("defenseclaw")
	} else {
		tp := traceNoop.NewTracerProvider()
		p.tracer = tp.Tracer("defenseclaw")
	}

	logOpts := []sdklog.LoggerProviderOption{sdklog.WithResource(res)}
	logCount := 0
	for _, destination := range destinations {
		if !destination.cfg.Enabled || !destination.cfg.Logs.Enabled {
			continue
		}
		processor, err := newLogProcessor(ctx, destination.cfg, expandHeaders(destination.cfg.Headers))
		if err != nil {
			return nil, fmt.Errorf("telemetry: destination %q logs: %w", destination.name, err)
		}
		logOpts = append(logOpts, sdklog.WithProcessor(processor))
		logCount++
	}
	// Managed_enterprise fast path: fan DefenseClaw's own OTEL log events to
	// the Cisco AI Defense event-ingest API, authenticated with a CMID bearer
	// token. This sink is auto-provisioned (not a user destination), never
	// receives user credentials, and is independent of otel.enabled and of any
	// otel.destinations[] entry. Fail-closed: if the CMID provider or token is
	// unavailable (e.g. OSS build, agent down), the sink is skipped and user
	// destinations are unaffected.
	if ciscoAIDLogSink {
		processor, err := p.newCiscoAIDLogProcessor(ctx, fullCfg, po.cloudAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: cisco ai defense telemetry log sink disabled: %v\n", err)
		} else {
			logOpts = append(logOpts, sdklog.WithProcessor(processor))
			logCount++
		}
	}
	if logCount > 0 {
		lp := sdklog.NewLoggerProvider(logOpts...)
		p.loggerProvider = lp
		p.logger = lp.Logger("defenseclaw")
	} else {
		lp := logNoop.NewLoggerProvider()
		p.logger = lp.Logger("defenseclaw")
	}

	meterOpts := []sdkmetric.Option{sdkmetric.WithResource(res)}
	metricCount := 0
	for _, destination := range destinations {
		if !destination.cfg.Enabled || !destination.cfg.Metrics.Enabled {
			continue
		}
		reader, err := newMetricReader(
			ctx, destination.cfg, expandHeaders(destination.cfg.Headers), p,
		)
		if err != nil {
			return nil, fmt.Errorf("telemetry: destination %q metrics: %w", destination.name, err)
		}
		meterOpts = append(meterOpts, sdkmetric.WithReader(reader))
		metricCount++
	}
	if metricCount > 0 {
		mp := sdkmetric.NewMeterProvider(meterOpts...)
		p.meterProvider = mp
		p.meter = mp.Meter("defenseclaw")
	} else {
		mp := metricNoop.NewMeterProvider()
		p.meter = mp.Meter("defenseclaw")
	}

	ms, err := newMetricsSet(p.meter)
	if err != nil {
		return nil, fmt.Errorf("telemetry: register metrics: %w", err)
	}
	p.metrics = ms

	if install {
		installGlobalHooks(p)
	}

	if metricCount > 0 {
		capCtx, capCancel := context.WithCancel(context.Background())
		p.capacityShutdown = capCancel
		startCapacityBackground(capCtx, p)
	}

	return p, nil
}

func ActivateProvider(p *Provider) {
	installGlobalHooks(p)
}

func installGlobalHooks(p *Provider) {
	installOpenTelemetryGlobals(p)
	setGlobalTelemetryProvider(p)
	if p == nil {
		config.ReportConfigLoadError = nil
		return
	}
	config.ReportConfigLoadError = func(ctx context.Context, reason string) {
		p.RecordConfigLoadError(ctx, reason)
	}
}

func installOpenTelemetryGlobals(p *Provider) {
	if p == nil {
		otel.SetTracerProvider(traceNoop.NewTracerProvider())
		global.SetLoggerProvider(logNoop.NewLoggerProvider())
		otel.SetMeterProvider(metricNoop.NewMeterProvider())
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
		return
	}
	if p.tracerProvider != nil {
		otel.SetTracerProvider(p.tracerProvider)
	} else {
		otel.SetTracerProvider(traceNoop.NewTracerProvider())
	}
	if p.loggerProvider != nil {
		global.SetLoggerProvider(p.loggerProvider)
	} else {
		global.SetLoggerProvider(logNoop.NewLoggerProvider())
	}
	if p.meterProvider != nil {
		otel.SetMeterProvider(p.meterProvider)
	} else {
		otel.SetMeterProvider(metricNoop.NewMeterProvider())
	}
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		if err == nil || p.metrics == nil {
			return
		}
		reason := err.Error()
		if len(reason) > 200 {
			reason = reason[:200] + "…"
		}
		p.metrics.telemetryExporterErrs.Add(context.Background(), 1,
			metric.WithAttributes(
				attribute.String("signal", "otel_sdk"),
				attribute.String("reason", reason),
			))
		p.emitExporterFailure(context.Background(), "otel_sdk")
	}))
}

// Enabled reports whether OTel export is active.
func (p *Provider) Enabled() bool {
	return p != nil && p.enabled
}

// Tracer returns the defenseclaw tracer, or a no-op tracer when the
// provider is nil or OTel is disabled.
func (p *Provider) Tracer() trace.Tracer {
	if p == nil || p.tracer == nil {
		return traceNoop.NewTracerProvider().Tracer("defenseclaw")
	}
	return p.tracer
}

// EmitTUIFilterTrace records a short-lived span when an operator changes
// a TUI filter (severity, subsystem, agent id, …).
func (p *Provider) EmitTUIFilterTrace(ctx context.Context, panel, filterType, oldVal, newVal string) {
	if p == nil || !p.Enabled() || p.tracer == nil {
		return
	}
	_, sp := p.tracer.Start(ctx, "defenseclaw.tui.filter",
		trace.WithAttributes(
			attribute.String("panel", panel),
			attribute.String("filter_type", filterType),
			attribute.String("old", oldVal),
			attribute.String("new", newVal),
		))
	sp.End()
}

// LogsEnabled reports whether OTel log export is active.
func (p *Provider) LogsEnabled() bool {
	return p.Enabled() && p.loggerProvider != nil
}

// TracesEnabled reports whether OTel trace export is active.
func (p *Provider) TracesEnabled() bool {
	return p.Enabled() && p.tracerProvider != nil
}

// SetAgentInstanceID installs the per-process stable agent instance
// identifier. The sidecar mints it once at boot and propagates it to
// both the telemetry Provider (for every span/log it emits) and the
// audit package (for every row it persists). Safe to call on a nil
// provider — no-op in that case.
func (p *Provider) SetAgentInstanceID(id string) {
	if p == nil {
		return
	}
	p.agentInstanceID.Store(strings.TrimSpace(id))
}

// AgentInstanceID returns the currently registered per-process
// agent instance id, or empty string if none was set.
func (p *Provider) AgentInstanceID() string {
	if p == nil {
		return ""
	}
	v, _ := p.agentInstanceID.Load().(string)
	return v
}

// Shutdown flushes pending telemetry and releases resources.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || !p.Enabled() {
		return nil
	}
	if !p.shutdown.CompareAndSwap(false, true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var errs []error
	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("traces: %w", err))
		}
	}
	if p.loggerProvider != nil {
		if err := p.loggerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("logs: %w", err))
		}
	}
	if p.capacityShutdown != nil {
		p.capacityShutdown()
	}
	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("metrics: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("telemetry: shutdown: %v", errs)
	}
	return nil
}

type namedOTelDestination struct {
	name   string
	filter config.OTelSpanFilterConfig
	cfg    destinationExporterConfig
}

type destinationExporterConfig struct {
	Enabled  bool
	Protocol string
	Endpoint string
	Headers  map[string]string
	TLS      config.OTelTLSConfig
	Traces   config.OTelTracesConfig
	Logs     config.OTelLogsConfig
	Metrics  config.OTelMetricsConfig
	Batch    config.OTelBatchConfig
}

// effectiveOTelDestinations resolves process-wide policy defaults into each
// explicitly named exporter. An empty destination list means no export.
func effectiveOTelDestinations(global config.OTelConfig) []namedOTelDestination {
	out := make([]namedOTelDestination, 0, len(global.Destinations))
	for i, destination := range global.Destinations {
		name := strings.TrimSpace(destination.Name)
		if name == "" {
			name = fmt.Sprintf("destination-%d", i+1)
		}
		batch := destination.Batch
		if batch.MaxExportBatchSize <= 0 {
			batch.MaxExportBatchSize = global.Batch.MaxExportBatchSize
		}
		if batch.ScheduledDelayMs <= 0 {
			batch.ScheduledDelayMs = global.Batch.ScheduledDelayMs
		}
		if batch.MaxQueueSize <= 0 {
			batch.MaxQueueSize = global.Batch.MaxQueueSize
		}

		traces := destination.Traces
		traces.Sampler = global.Traces.Sampler
		traces.SamplerArg = global.Traces.SamplerArg
		logs := destination.Logs
		logs.EmitIndividualFindings = global.Logs.EmitIndividualFindings
		metrics := destination.Metrics
		if metrics.ExportIntervalS <= 0 {
			metrics.ExportIntervalS = global.Metrics.ExportIntervalS
		}
		if metrics.Temporality == "" {
			metrics.Temporality = global.Metrics.Temporality
		}

		out = append(out, namedOTelDestination{
			name:   name,
			filter: destination.SpanFilter,
			cfg: destinationExporterConfig{
				Enabled:  destination.Enabled,
				Protocol: destination.Protocol,
				Endpoint: destination.Endpoint,
				Headers:  destination.Headers,
				TLS:      destination.TLS,
				Traces:   traces,
				Logs:     logs,
				Metrics:  metrics,
				Batch:    batch,
			},
		})
	}
	return out
}

// filteredSpanProcessor projects a destination-specific subset of the process
// trace graph without changing what general OTLP destinations receive.
type filteredSpanProcessor struct {
	next        sdktrace.SpanProcessor
	provider    *Provider
	destination string
	filter      config.OTelSpanFilterConfig
}

func (p *filteredSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (p *filteredSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if spanMatchesFilter(span, p.filter) {
		p.provider.recordDestinationRoute(p.destination, true)
		p.provider.RecordDestinationSpanRoute(
			context.Background(), p.destination, "accepted", "span_filter_match",
		)
		p.next.OnEnd(span)
		return
	}
	p.provider.recordDestinationRoute(p.destination, false)
	p.provider.RecordDestinationSpanRoute(
		context.Background(), p.destination, "dropped", "span_filter_miss",
	)
}

func (p *filteredSpanProcessor) Shutdown(ctx context.Context) error {
	return p.next.Shutdown(ctx)
}

func (p *filteredSpanProcessor) ForceFlush(ctx context.Context) error {
	return p.next.ForceFlush(ctx)
}

func spanMatchesFilter(span sdktrace.ReadOnlySpan, filter config.OTelSpanFilterConfig) bool {
	tracked := make(map[string]struct{}, len(filter.RequireAttributes)+1)
	for _, key := range filter.RequireAttributes {
		tracked[strings.TrimSpace(key)] = struct{}{}
	}
	if strings.TrimSpace(filter.RequireOperation) != "" {
		tracked["gen_ai.operation.name"] = struct{}{}
	}
	for _, operation := range filter.Operations {
		tracked["gen_ai.operation.name"] = struct{}{}
		for _, key := range operation.RequireAttributes {
			tracked[strings.TrimSpace(key)] = struct{}{}
		}
	}
	values := make(map[string]string, len(tracked))
	for _, item := range span.Attributes() {
		key := string(item.Key)
		if _, ok := tracked[key]; ok {
			values[key] = strings.TrimSpace(item.Value.AsString())
		}
	}
	if len(filter.Operations) > 0 {
		operationName := values["gen_ai.operation.name"]
		for _, operation := range filter.Operations {
			if strings.TrimSpace(operation.Name) != operationName {
				continue
			}
			for _, key := range operation.RequireAttributes {
				if values[strings.TrimSpace(key)] == "" {
					return false
				}
			}
			return true
		}
		return false
	}
	if operation := strings.TrimSpace(filter.RequireOperation); operation != "" &&
		values["gen_ai.operation.name"] != operation {
		return false
	}
	for _, key := range filter.RequireAttributes {
		if values[strings.TrimSpace(key)] == "" {
			return false
		}
	}
	return true
}

// DestinationRoutingSnapshot reports process-lifetime results for one named
// destination filter independently of metrics export.
type DestinationRoutingSnapshot struct {
	Accepted uint64 `json:"accepted"`
	Dropped  uint64 `json:"dropped"`
}

type destinationRoutingCounters struct {
	accepted atomic.Uint64
	dropped  atomic.Uint64
}

// DestinationDeliverySnapshot reports batch-level exporter outcomes.
// CollectorAccepted is the number of spans in error-free OTLP requests plus
// the accepted-count inferred from protocol partial-success rejection counts.
// It is not per-span acknowledgement and does not claim backend indexing.
type DestinationDeliverySnapshot struct {
	Attempted         uint64    `json:"attempted"`
	Pending           uint64    `json:"pending"`
	CollectorAccepted uint64    `json:"collector_accepted"`
	Delivered         uint64    `json:"delivered"` // compatibility alias
	Rejected          uint64    `json:"rejected"`
	Failed            uint64    `json:"failed"`
	ExportBatches     uint64    `json:"export_batches"`
	FailedBatches     uint64    `json:"failed_batches"`
	LastAttemptAt     time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt     time.Time `json:"last_success_at,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	IndexingStatus    string    `json:"indexing_status"`
}

type destinationDeliveryCounters struct {
	attempted                    atomic.Uint64
	delivered                    atomic.Uint64
	rejected                     atomic.Uint64
	failed                       atomic.Uint64
	exportBatches                atomic.Uint64
	failedBatches                atomic.Uint64
	mu                           sync.RWMutex
	lastAttemptAt                time.Time
	lastSuccessAt                time.Time
	lastError                    string
	acknowledgedCanaryTraceIDs   map[string]struct{}
	acknowledgedCanaryTraceOrder []string
}

const recentAcknowledgedCanaryTraceLimit = 256

func (p *Provider) recordDestinationRoute(destination string, accepted bool) {
	p.routingMu.RLock()
	counters := p.routingByName[destination]
	p.routingMu.RUnlock()
	if counters == nil {
		p.routingMu.Lock()
		if p.routingByName == nil {
			p.routingByName = make(map[string]*destinationRoutingCounters)
		}
		counters = p.routingByName[destination]
		if counters == nil {
			counters = &destinationRoutingCounters{}
			p.routingByName[destination] = counters
		}
		p.routingMu.Unlock()
	}
	if accepted {
		counters.accepted.Add(1)
	} else {
		counters.dropped.Add(1)
	}
}

// DestinationRoutingStats reports process-lifetime routing for one named
// destination and remains correct with multiple filtered destinations.
func (p *Provider) DestinationRoutingStats(destination string) DestinationRoutingSnapshot {
	if p == nil {
		return DestinationRoutingSnapshot{}
	}
	p.routingMu.RLock()
	counters := p.routingByName[destination]
	p.routingMu.RUnlock()
	if counters == nil {
		return DestinationRoutingSnapshot{}
	}
	return DestinationRoutingSnapshot{
		Accepted: counters.accepted.Load(),
		Dropped:  counters.dropped.Load(),
	}
}

func (p *Provider) deliveryCounters(destination string) *destinationDeliveryCounters {
	p.deliveryMu.RLock()
	counters := p.deliveryByName[destination]
	p.deliveryMu.RUnlock()
	if counters != nil {
		return counters
	}
	p.deliveryMu.Lock()
	defer p.deliveryMu.Unlock()
	if p.deliveryByName == nil {
		p.deliveryByName = make(map[string]*destinationDeliveryCounters)
	}
	if p.deliveryByName[destination] == nil {
		p.deliveryByName[destination] = &destinationDeliveryCounters{}
	}
	return p.deliveryByName[destination]
}

// DestinationDeliveryStats returns process-lifetime delivery results for one
// named OTLP trace destination.
func (p *Provider) DestinationDeliveryStats(destination string) DestinationDeliverySnapshot {
	if p == nil {
		return DestinationDeliverySnapshot{}
	}
	p.deliveryMu.RLock()
	counters := p.deliveryByName[destination]
	p.deliveryMu.RUnlock()
	if counters == nil {
		return DestinationDeliverySnapshot{}
	}
	counters.mu.RLock()
	defer counters.mu.RUnlock()
	snapshot := DestinationDeliverySnapshot{
		Attempted: counters.attempted.Load(), Delivered: counters.delivered.Load(),
		CollectorAccepted: counters.delivered.Load(), IndexingStatus: "unverified",
		Rejected: counters.rejected.Load(), Failed: counters.failed.Load(),
		ExportBatches: counters.exportBatches.Load(), FailedBatches: counters.failedBatches.Load(),
		LastAttemptAt: counters.lastAttemptAt, LastSuccessAt: counters.lastSuccessAt,
		LastError: counters.lastError,
	}
	routing := p.DestinationRoutingStats(destination)
	if routing.Accepted > snapshot.Attempted {
		snapshot.Pending = routing.Accepted - snapshot.Attempted
	}
	return snapshot
}

// DestinationAcknowledgedCanaryTrace reports whether a marked canary trace was
// part of an isolated export request with zero reported rejections. OTLP
// partial success reports only a count, so any rejected span makes that
// canary trace unacknowledged.
func (p *Provider) DestinationAcknowledgedCanaryTrace(destination, traceID string) bool {
	if p == nil || strings.TrimSpace(traceID) == "" {
		return false
	}
	p.deliveryMu.RLock()
	counters := p.deliveryByName[destination]
	p.deliveryMu.RUnlock()
	if counters == nil {
		return false
	}
	counters.mu.RLock()
	_, ok := counters.acknowledgedCanaryTraceIDs[traceID]
	counters.mu.RUnlock()
	return ok
}

func recordAcknowledgedCanaryTraceIDs(counters *destinationDeliveryCounters, spans []sdktrace.ReadOnlySpan) {
	counters.mu.Lock()
	defer counters.mu.Unlock()
	if counters.acknowledgedCanaryTraceIDs == nil {
		counters.acknowledgedCanaryTraceIDs = make(map[string]struct{})
	}
	for _, span := range spans {
		if !isCanarySpan(span) || !span.SpanContext().TraceID().IsValid() {
			continue
		}
		traceID := span.SpanContext().TraceID().String()
		if _, exists := counters.acknowledgedCanaryTraceIDs[traceID]; exists {
			continue
		}
		counters.acknowledgedCanaryTraceIDs[traceID] = struct{}{}
		counters.acknowledgedCanaryTraceOrder = append(counters.acknowledgedCanaryTraceOrder, traceID)
	}
	for len(counters.acknowledgedCanaryTraceOrder) > recentAcknowledgedCanaryTraceLimit {
		oldest := counters.acknowledgedCanaryTraceOrder[0]
		counters.acknowledgedCanaryTraceOrder = counters.acknowledgedCanaryTraceOrder[1:]
		delete(counters.acknowledgedCanaryTraceIDs, oldest)
	}
}

var partialSuccessRejectedSpans = regexp.MustCompile(`\(([0-9]+) spans rejected\)`)

// destinationSpanExporter gives every independently queued destination an
// observable acknowledgement boundary. The upstream OTLP exporters return an
// error for protocol-level partial_success responses, so rejected counts can
// be separated from transport/auth failures without reimplementing OTLP.
type destinationSpanExporter struct {
	next        sdktrace.SpanExporter
	provider    *Provider
	destination string
}

func (e *destinationSpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	spans = canarySpansForDestination(spans, e.destination)
	if len(spans) == 0 {
		return nil
	}
	regular, canaries := partitionCanarySpans(spans)
	var errs []error
	if len(regular) > 0 {
		if err := e.exportBatch(ctx, regular); err != nil {
			errs = append(errs, err)
		}
	}
	for _, canary := range canaries {
		if err := e.exportBatch(ctx, canary); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func canarySpansForDestination(spans []sdktrace.ReadOnlySpan, destination string) []sdktrace.ReadOnlySpan {
	filtered := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		target := canaryDestination(span)
		if target == "" || target == destination {
			filtered = append(filtered, span)
		}
	}
	return filtered
}

func canaryDestination(span sdktrace.ReadOnlySpan) string {
	if span == nil || !isCanarySpan(span) {
		return ""
	}
	for _, attr := range span.Attributes() {
		if string(attr.Key) == telemetryCanaryDestinationAttribute && attr.Value.Type() == attribute.STRING {
			return strings.TrimSpace(attr.Value.AsString())
		}
	}
	return ""
}

// partitionCanarySpans prevents unrelated traffic from sharing a canary OTLP
// request. Each canary trace gets a single-use export boundary, so an
// zero-rejection response can be attributed to that exact trace ID.
func partitionCanarySpans(spans []sdktrace.ReadOnlySpan) ([]sdktrace.ReadOnlySpan, [][]sdktrace.ReadOnlySpan) {
	regular := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	byTrace := make(map[string][]sdktrace.ReadOnlySpan)
	order := make([]string, 0)
	for _, span := range spans {
		if !isCanarySpan(span) {
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

func isCanarySpan(span sdktrace.ReadOnlySpan) bool {
	if span == nil {
		return false
	}
	for _, attr := range span.Attributes() {
		if string(attr.Key) == telemetryCanaryAttribute && attr.Value.Type() == attribute.BOOL {
			return attr.Value.AsBool()
		}
	}
	return false
}

func (e *destinationSpanExporter) exportBatch(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	counters := e.provider.deliveryCounters(e.destination)
	now := time.Now().UTC()
	count := uint64(len(spans))
	counters.attempted.Add(count)
	e.provider.recordDestinationExport(ctx, e.destination, "attempted", count)
	counters.exportBatches.Add(1)
	counters.mu.Lock()
	counters.lastAttemptAt = now
	counters.mu.Unlock()

	err := e.next.ExportSpans(ctx, spans)
	if err == nil {
		counters.delivered.Add(count)
		e.provider.recordDestinationExport(ctx, e.destination, "delivered", count)
		recordAcknowledgedCanaryTraceIDs(counters, spans)
		counters.mu.Lock()
		counters.lastSuccessAt = time.Now().UTC()
		counters.lastError = ""
		counters.mu.Unlock()
		return nil
	}

	message := err.Error()
	if match := partialSuccessRejectedSpans.FindStringSubmatch(message); len(match) == 2 {
		rejected, parseErr := strconv.ParseUint(match[1], 10, 64)
		if parseErr == nil {
			if rejected > count {
				rejected = count
			}
			counters.rejected.Add(rejected)
			counters.delivered.Add(count - rejected)
			if rejected == 0 {
				recordAcknowledgedCanaryTraceIDs(counters, spans)
			}
			e.provider.recordDestinationExport(ctx, e.destination, "rejected", rejected)
			e.provider.recordDestinationExport(ctx, e.destination, "delivered", count-rejected)
		}
	} else {
		counters.failed.Add(count)
		e.provider.recordDestinationExport(ctx, e.destination, "failed", count)
	}
	counters.failedBatches.Add(1)
	if len(message) > 300 {
		message = message[:300] + "…"
	}
	counters.mu.Lock()
	counters.lastError = message
	counters.mu.Unlock()
	return err
}

func (e *destinationSpanExporter) Shutdown(ctx context.Context) error {
	return e.next.Shutdown(ctx)
}

func newSpanProcessor(
	ctx context.Context,
	cfg destinationExporterConfig,
	headers map[string]string,
	provider *Provider,
	destination string,
) (sdktrace.SpanProcessor, error) {
	var exporter sdktrace.SpanExporter
	var err error

	endpoint := resolveValue(cfg.Traces.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(cfg.Traces.Protocol, cfg.Protocol)
	if err := validateCredentialTransport(endpoint, cfg.TLS.Insecure, headers); err != nil {
		return nil, err
	}

	if protocol == "http" {
		opts := []tracehttp.Option{}
		if endpoint != "" {
			if host, path, insecure, ok := splitEndpointURL(endpoint); ok {
				opts = append(opts, tracehttp.WithEndpoint(host))
				if insecure {
					opts = append(opts, tracehttp.WithInsecure())
				}
				if cfg.Traces.URLPath == "" && path != "" && path != "/" {
					opts = append(opts, tracehttp.WithURLPath(path))
				}
			} else {
				opts = append(opts, tracehttp.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, tracehttp.WithHeaders(headers))
		if cfg.Traces.URLPath != "" {
			opts = append(opts, tracehttp.WithURLPath(cfg.Traces.URLPath))
		}
		if cfg.TLS.Insecure {
			opts = append(opts, tracehttp.WithInsecure())
		}
		if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, tracehttp.WithTLSClientConfig(tlsCfg))
		}
		exporter, err = tracehttp.New(ctx, opts...)
	} else {
		opts := []tracegrpc.Option{}
		if endpoint != "" {
			if endpointLooksLikeURL(endpoint) {
				opts = append(opts, tracegrpc.WithEndpointURL(endpoint))
			} else {
				opts = append(opts, tracegrpc.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, tracegrpc.WithHeaders(headers))
		if cfg.TLS.Insecure {
			opts = append(opts, tracegrpc.WithInsecure())
		} else if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, tracegrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		exporter, err = tracegrpc.New(ctx, opts...)
	}
	if err != nil {
		return nil, err
	}
	exporter = &destinationSpanExporter{
		next: exporter, provider: provider, destination: destination,
	}

	bsp := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithMaxExportBatchSize(cfg.Batch.MaxExportBatchSize),
		sdktrace.WithBatchTimeout(time.Duration(cfg.Batch.ScheduledDelayMs)*time.Millisecond),
		sdktrace.WithMaxQueueSize(cfg.Batch.MaxQueueSize),
	)
	return bsp, nil
}

func newLogProcessor(ctx context.Context, cfg destinationExporterConfig, headers map[string]string) (sdklog.Processor, error) {
	var exporter sdklog.Exporter
	var err error

	endpoint := resolveValue(cfg.Logs.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(cfg.Logs.Protocol, cfg.Protocol)
	if err := validateCredentialTransport(endpoint, cfg.TLS.Insecure, headers); err != nil {
		return nil, err
	}

	if protocol == "http" {
		opts := []loghttp.Option{}
		if endpoint != "" {
			if host, path, insecure, ok := splitEndpointURL(endpoint); ok {
				opts = append(opts, loghttp.WithEndpoint(host))
				if insecure {
					opts = append(opts, loghttp.WithInsecure())
				}
				if cfg.Logs.URLPath == "" && path != "" && path != "/" {
					opts = append(opts, loghttp.WithURLPath(path))
				}
			} else {
				opts = append(opts, loghttp.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, loghttp.WithHeaders(headers))
		if cfg.Logs.URLPath != "" {
			opts = append(opts, loghttp.WithURLPath(cfg.Logs.URLPath))
		}
		if cfg.TLS.Insecure {
			opts = append(opts, loghttp.WithInsecure())
		}
		if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, loghttp.WithTLSClientConfig(tlsCfg))
		}
		exporter, err = loghttp.New(ctx, opts...)
	} else {
		opts := []loggrpc.Option{}
		if endpoint != "" {
			if endpointLooksLikeURL(endpoint) {
				opts = append(opts, loggrpc.WithEndpointURL(endpoint))
			} else {
				opts = append(opts, loggrpc.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, loggrpc.WithHeaders(headers))
		if cfg.TLS.Insecure {
			opts = append(opts, loggrpc.WithInsecure())
		} else if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, loggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		exporter, err = loggrpc.New(ctx, opts...)
	}
	if err != nil {
		return nil, err
	}

	batcher := sdklog.NewBatchProcessor(exporter,
		sdklog.WithMaxQueueSize(cfg.Batch.MaxQueueSize),
		sdklog.WithExportMaxBatchSize(cfg.Batch.MaxExportBatchSize),
		sdklog.WithExportInterval(time.Duration(cfg.Batch.ScheduledDelayMs)*time.Millisecond),
	)

	return batcher, nil
}

// CloudAuthProvider returns the CMID credential provider backing the Cisco AI
// Defense telemetry log sink, or nil when no such sink was provisioned. The
// managed inspector reuses this instance so both share one token cache and one
// Invalidate lifecycle.
func (p *Provider) CloudAuthProvider() cloudreg.Provider {
	if p == nil {
		return nil
	}
	return p.cloudAuth
}

// newCiscoAIDLogProcessor builds the batched log processor that ships
// DefenseClaw's OTEL log events to the Cisco AI Defense event-ingest API. It
// resolves the CMID provider (injected shared instance, else lazily via
// cloudreg.New) and mints a token once to confirm availability, returning an
// error when the credential source is unavailable so the caller can fail-closed.
func (p *Provider) newCiscoAIDLogProcessor(ctx context.Context, fullCfg *config.Config, injected cloudreg.Provider) (sdklog.Processor, error) {
	provider := injected
	if provider == nil {
		var err error
		provider, err = cloudreg.New(cloudreg.Config{LibPath: fullCfg.CloudAuth.LibPath})
		if err != nil {
			return nil, fmt.Errorf("cloud auth provider: %w", err)
		}
	}

	// Mint once to confirm the credential source is reachable before wiring
	// the sink into the log fan-out. A short timeout keeps boot responsive.
	tokenCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := provider.Token(tokenCtx); err != nil {
		return nil, fmt.Errorf("cloud auth token: %w", err)
	}
	p.cloudAuth = provider

	exporter := newCiscoAIDLogExporter(ciscoAIDefenseIngestURL(fullCfg.CiscoAIDefense.Endpoint), provider)

	batchOpts := []sdklog.BatchProcessorOption{}
	if fullCfg.OTel.Batch.MaxQueueSize > 0 {
		batchOpts = append(batchOpts, sdklog.WithMaxQueueSize(fullCfg.OTel.Batch.MaxQueueSize))
	}
	if fullCfg.OTel.Batch.MaxExportBatchSize > 0 {
		batchOpts = append(batchOpts, sdklog.WithExportMaxBatchSize(fullCfg.OTel.Batch.MaxExportBatchSize))
	}
	if fullCfg.OTel.Batch.ScheduledDelayMs > 0 {
		batchOpts = append(batchOpts,
			sdklog.WithExportInterval(time.Duration(fullCfg.OTel.Batch.ScheduledDelayMs)*time.Millisecond))
	}
	return sdklog.NewBatchProcessor(exporter, batchOpts...), nil
}

// temporalitySelector returns a TemporalitySelector based on the config value.
// "delta" (default) prevents cumulative re-export of exemplars on every flush,
// so each metric data point is exported exactly once.
// "cumulative" preserves the Go SDK default behaviour.
func temporalitySelector(mode string) sdkmetric.TemporalitySelector {
	if strings.EqualFold(mode, "cumulative") {
		return sdkmetric.DefaultTemporalitySelector
	}
	return func(sdkmetric.InstrumentKind) metricdata.Temporality {
		return metricdata.DeltaTemporality
	}
}

func newMetricReader(ctx context.Context, cfg destinationExporterConfig, headers map[string]string, tel *Provider) (sdkmetric.Reader, error) {
	var exporter sdkmetric.Exporter
	var err error

	endpoint := resolveValue(cfg.Metrics.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(cfg.Metrics.Protocol, cfg.Protocol)
	if err := validateCredentialTransport(endpoint, cfg.TLS.Insecure, headers); err != nil {
		return nil, err
	}
	tsel := temporalitySelector(cfg.Metrics.Temporality)

	if protocol == "http" {
		opts := []metrichttp.Option{metrichttp.WithTemporalitySelector(tsel)}
		if endpoint != "" {
			if host, path, insecure, ok := splitEndpointURL(endpoint); ok {
				opts = append(opts, metrichttp.WithEndpoint(host))
				if insecure {
					opts = append(opts, metrichttp.WithInsecure())
				}
				if cfg.Metrics.URLPath == "" && path != "" && path != "/" {
					opts = append(opts, metrichttp.WithURLPath(path))
				}
			} else {
				opts = append(opts, metrichttp.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, metrichttp.WithHeaders(headers))
		if cfg.Metrics.URLPath != "" {
			opts = append(opts, metrichttp.WithURLPath(cfg.Metrics.URLPath))
		}
		if cfg.TLS.Insecure {
			opts = append(opts, metrichttp.WithInsecure())
		}
		if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, metrichttp.WithTLSClientConfig(tlsCfg))
		}
		exporter, err = metrichttp.New(ctx, opts...)
	} else {
		opts := []metricgrpc.Option{metricgrpc.WithTemporalitySelector(tsel)}
		if endpoint != "" {
			if endpointLooksLikeURL(endpoint) {
				opts = append(opts, metricgrpc.WithEndpointURL(endpoint))
			} else {
				opts = append(opts, metricgrpc.WithEndpoint(endpoint))
			}
		}
		opts = append(opts, metricgrpc.WithHeaders(headers))
		if cfg.TLS.Insecure {
			opts = append(opts, metricgrpc.WithInsecure())
		} else if cfg.TLS.CACert != "" {
			tlsCfg, tlsErr := buildTLSConfig(cfg.TLS.CACert)
			if tlsErr != nil {
				return nil, tlsErr
			}
			opts = append(opts, metricgrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		}
		exporter, err = metricgrpc.New(ctx, opts...)
	}
	if err != nil {
		return nil, err
	}

	wrapped := &metricExporterProbe{inner: exporter, p: tel}

	reader := sdkmetric.NewPeriodicReader(wrapped,
		sdkmetric.WithInterval(time.Duration(cfg.Metrics.ExportIntervalS)*time.Second),
	)

	return reader, nil
}

func buildTLSConfig(caCertPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("telemetry: read CA cert %s: %w", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("telemetry: failed to parse CA cert %s", caCertPath)
	}
	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func buildSampler(name, arg string) sdktrace.Sampler {
	switch name {
	case "always_off":
		return sdktrace.NeverSample()
	case "parentbased_traceidratio":
		ratio, err := strconv.ParseFloat(arg, 64)
		if err != nil {
			ratio = 1.0
		}
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		return sdktrace.AlwaysSample()
	}
}

// resolveValue returns the signal-level override if non-empty, otherwise the global value.
func resolveValue(signal, global string) string {
	if signal != "" {
		return signal
	}
	return global
}

func resolveProtocol(signal, destination string) string {
	value := ""
	if signal != "" {
		value = signal
	} else if destination != "" {
		value = destination
	}
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "http/protobuf", "http/json":
		return "http"
	case "grpc/protobuf":
		return "grpc"
	default:
		return value
	}
}

func endpointLooksLikeURL(endpoint string) bool {
	return strings.Contains(endpoint, "://")
}

func credentialHeaderName(name string) bool {
	// This is intentionally a heuristic for the credential headers used by
	// shipped presets. Preset authors adding a non-standard secret header (for
	// example X-Secret) must extend this matcher so plaintext remote endpoints
	// remain blocked by validateCredentialTransport.
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(
		strings.ToLower(strings.TrimSpace(name)),
	)
	return strings.Contains(normalized, "authorization") ||
		strings.Contains(normalized, "apikey") ||
		strings.Contains(normalized, "token") ||
		normalized == "xhoneycombteam"
}

func hasCredentialHeaders(headers map[string]string) bool {
	for name := range headers {
		if credentialHeaderName(name) {
			return true
		}
	}
	return false
}

func endpointTransport(endpoint string, tlsInsecure bool) (host string, insecure, userinfo bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		// Empty named-destination endpoints are rejected by config validation.
		return "localhost", tlsInsecure, false
	}
	if endpointLooksLikeURL(endpoint) {
		u, err := url.Parse(endpoint)
		if err != nil {
			return "", tlsInsecure, false
		}
		return u.Hostname(), tlsInsecure || strings.EqualFold(u.Scheme, "http"), u.User != nil
	}
	host = endpoint
	if parsedHost, _, err := net.SplitHostPort(endpoint); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return host, tlsInsecure, false
}

func loopbackEndpointHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateCredentialTransport is the runtime guard for hand-edited config.
// Setup commands validate their endpoints too, but the long-running exporter
// must independently refuse to attach credentials to plaintext remote links.
func validateCredentialTransport(endpoint string, tlsInsecure bool, headers map[string]string) error {
	host, insecure, userinfo := endpointTransport(endpoint, tlsInsecure)
	if userinfo {
		return fmt.Errorf("telemetry: OTLP endpoint must not contain URL userinfo")
	}
	if !hasCredentialHeaders(headers) {
		return nil
	}
	if insecure && !loopbackEndpointHost(host) {
		return fmt.Errorf(
			"telemetry: credential-bearing OTLP endpoint %q must use TLS unless it is loopback",
			host,
		)
	}
	return nil
}

func splitEndpointURL(endpoint string) (host, path string, insecure, ok bool) {
	if !endpointLooksLikeURL(endpoint) {
		return "", "", false, false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", "", false, false
	}
	return u.Host, u.Path, strings.EqualFold(u.Scheme, "http"), true
}

// expandHeaders substitutes ${ENV_VAR} references in header values so
// operators can keep secrets out of the YAML file. Header semantics stay
// vendor-neutral: auth headers (X-SF-Token, api-key, etc.) must be declared
// on the named destination that uses them.
func expandHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[k] = os.Expand(v, func(key string) string {
			if strings.HasPrefix(key, "{") && strings.HasSuffix(key, "}") {
				key = key[1 : len(key)-1]
			}
			return os.Getenv(key)
		})
	}
	return out
}
