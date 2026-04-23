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
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	logNoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricNoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
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

	// agentInstanceID is the per-process stable identifier the
	// sidecar mints at boot. Accessed from multiple goroutines
	// (every StartAgentSpan / StartToolSpan call reads it) so we
	// guard it with an atomic load rather than a mutex; writes
	// happen exactly once during NewSidecar.
	agentInstanceID atomic.Value // string
}

// NewProvider initializes the OTel SDK providers and exporters. When
// cfg.Enabled is false, it returns a no-op provider safe to call.
func NewProvider(ctx context.Context, fullCfg *config.Config, version string) (*Provider, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	cfg := fullCfg.OTel
	if !cfg.Enabled {
		return &Provider{
			enabled: false,
			tracer:  traceNoop.NewTracerProvider().Tracer("defenseclaw"),
		}, nil
	}

	res := buildResource(fullCfg, version)
	headers := expandHeaders(cfg.Headers)

	p := &Provider{
		cfg:       cfg,
		res:       res,
		enabled:   true,
		startTime: time.Now(),
	}

	if cfg.Traces.Enabled {
		tp, err := newTracerProvider(ctx, cfg, res, headers)
		if err != nil {
			return nil, fmt.Errorf("telemetry: traces: %w", err)
		}
		p.tracerProvider = tp
		otel.SetTracerProvider(tp)
		p.tracer = tp.Tracer("defenseclaw")
	} else {
		p.tracer = traceNoop.NewTracerProvider().Tracer("defenseclaw")
	}

	if cfg.Logs.Enabled {
		lp, err := newLoggerProvider(ctx, cfg, res, headers)
		if err != nil {
			return nil, fmt.Errorf("telemetry: logs: %w", err)
		}
		p.loggerProvider = lp
		global.SetLoggerProvider(lp)
		p.logger = lp.Logger("defenseclaw")
	} else {
		p.logger = logNoop.NewLoggerProvider().Logger("defenseclaw")
	}

	if cfg.Metrics.Enabled {
		mp, err := newMeterProvider(ctx, cfg, res, headers, p)
		if err != nil {
			return nil, fmt.Errorf("telemetry: metrics: %w", err)
		}
		p.meterProvider = mp
		otel.SetMeterProvider(mp)
		p.meter = mp.Meter("defenseclaw")
	} else {
		p.meter = metricNoop.NewMeterProvider().Meter("defenseclaw")
	}

	ms, err := newMetricsSet(p.meter)
	if err != nil {
		return nil, fmt.Errorf("telemetry: register metrics: %w", err)
	}
	p.metrics = ms

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

	setGlobalTelemetryProvider(p)
	config.ReportConfigLoadError = func(ctx context.Context, reason string) {
		p.RecordConfigLoadError(ctx, reason)
	}

	if cfg.Metrics.Enabled {
		capCtx, capCancel := context.WithCancel(context.Background())
		p.capacityShutdown = capCancel
		startCapacityBackground(capCtx, p)
	}

	return p, nil
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
	if !p.Enabled() {
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

func newTracerProvider(ctx context.Context, cfg config.OTelConfig, res *resource.Resource, headers map[string]string) (*sdktrace.TracerProvider, error) {
	var exporter sdktrace.SpanExporter
	var err error

	endpoint := resolveValue(cfg.Traces.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(
		cfg.Traces.Protocol,
		cfg.Protocol,
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
	)

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
		if len(headers) > 0 {
			opts = append(opts, tracehttp.WithHeaders(headers))
		}
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
		if len(headers) > 0 {
			opts = append(opts, tracegrpc.WithHeaders(headers))
		}
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

	sampler := buildSampler(cfg.Traces.Sampler, cfg.Traces.SamplerArg)

	bsp := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithMaxExportBatchSize(cfg.Batch.MaxExportBatchSize),
		sdktrace.WithBatchTimeout(time.Duration(cfg.Batch.ScheduledDelayMs)*time.Millisecond),
		sdktrace.WithMaxQueueSize(cfg.Batch.MaxQueueSize),
	)

	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithSampler(sampler),
	), nil
}

func newLoggerProvider(ctx context.Context, cfg config.OTelConfig, res *resource.Resource, headers map[string]string) (*sdklog.LoggerProvider, error) {
	var exporter sdklog.Exporter
	var err error

	endpoint := resolveValue(cfg.Logs.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(
		cfg.Logs.Protocol,
		cfg.Protocol,
		"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
	)

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
		if len(headers) > 0 {
			opts = append(opts, loghttp.WithHeaders(headers))
		}
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
		if len(headers) > 0 {
			opts = append(opts, loggrpc.WithHeaders(headers))
		}
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

	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(batcher),
	), nil
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

func newMeterProvider(ctx context.Context, cfg config.OTelConfig, res *resource.Resource, headers map[string]string, tel *Provider) (*sdkmetric.MeterProvider, error) {
	var exporter sdkmetric.Exporter
	var err error

	endpoint := resolveValue(cfg.Metrics.Endpoint, cfg.Endpoint)
	protocol := resolveProtocol(
		cfg.Metrics.Protocol,
		cfg.Protocol,
		"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
	)
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
		if len(headers) > 0 {
			opts = append(opts, metrichttp.WithHeaders(headers))
		}
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
		if len(headers) > 0 {
			opts = append(opts, metricgrpc.WithHeaders(headers))
		}
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

	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	), nil
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

func resolveProtocol(signal, global, signalEnv, globalEnv string) string {
	if signal != "" {
		return strings.ToLower(strings.TrimSpace(signal))
	}
	if global != "" {
		return strings.ToLower(strings.TrimSpace(global))
	}
	if v := strings.TrimSpace(os.Getenv(signalEnv)); v != "" {
		return strings.ToLower(v)
	}
	if v := strings.TrimSpace(os.Getenv(globalEnv)); v != "" {
		return strings.ToLower(v)
	}
	return ""
}

func endpointLooksLikeURL(endpoint string) bool {
	return strings.Contains(endpoint, "://")
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
// vendor-neutral: if you need an auth header (X-SF-Token, api-key, etc.)
// put it in cfg.OTel.Headers or export it via OTEL_EXPORTER_OTLP_HEADERS.
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
