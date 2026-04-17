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
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
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
}

// NewProvider initializes the OTel SDK providers and exporters. When
// cfg.Enabled is false, it returns a no-op provider safe to call.
func NewProvider(ctx context.Context, fullCfg *config.Config, version string) (*Provider, error) {
	cfg := fullCfg.OTel
	if !cfg.Enabled {
		return &Provider{enabled: false}, nil
	}

	res := buildResource(fullCfg, version)
	headers := expandHeaders(cfg.Headers)

	p := &Provider{
		cfg:     cfg,
		res:     res,
		enabled: true,
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
		mp, err := newMeterProvider(ctx, cfg, res, headers)
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

	return p, nil
}

// Enabled reports whether OTel export is active.
func (p *Provider) Enabled() bool {
	return p != nil && p.enabled
}

// LogsEnabled reports whether OTel log export is active.
func (p *Provider) LogsEnabled() bool {
	return p.Enabled() && p.loggerProvider != nil
}

// TracesEnabled reports whether OTel trace export is active.
func (p *Provider) TracesEnabled() bool {
	return p.Enabled() && p.tracerProvider != nil
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
	protocol := resolveValue(cfg.Traces.Protocol, cfg.Protocol)

	if protocol == "http" {
		opts := []tracehttp.Option{
			tracehttp.WithEndpoint(endpoint),
			tracehttp.WithHeaders(headers),
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
		opts := []tracegrpc.Option{
			tracegrpc.WithEndpoint(endpoint),
			tracegrpc.WithHeaders(headers),
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
	protocol := resolveValue(cfg.Logs.Protocol, cfg.Protocol)

	if protocol == "http" {
		opts := []loghttp.Option{
			loghttp.WithEndpoint(endpoint),
			loghttp.WithHeaders(headers),
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
		opts := []loggrpc.Option{
			loggrpc.WithEndpoint(endpoint),
			loggrpc.WithHeaders(headers),
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

func newMeterProvider(ctx context.Context, cfg config.OTelConfig, res *resource.Resource, headers map[string]string) (*sdkmetric.MeterProvider, error) {
	var exporter sdkmetric.Exporter
	var err error

	endpoint := resolveValue(cfg.Metrics.Endpoint, cfg.Endpoint)
	protocol := resolveValue(cfg.Metrics.Protocol, cfg.Protocol)
	tsel := temporalitySelector(cfg.Metrics.Temporality)

	if protocol == "http" {
		opts := []metrichttp.Option{
			metrichttp.WithEndpoint(endpoint),
			metrichttp.WithHeaders(headers),
			metrichttp.WithTemporalitySelector(tsel),
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
		opts := []metricgrpc.Option{
			metricgrpc.WithEndpoint(endpoint),
			metricgrpc.WithHeaders(headers),
			metricgrpc.WithTemporalitySelector(tsel),
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

	reader := sdkmetric.NewPeriodicReader(exporter,
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
