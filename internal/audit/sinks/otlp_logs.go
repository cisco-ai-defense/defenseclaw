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

package sinks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"

	loggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	loghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
)

// OTLPLogsConfig is the per-sink OTLP wiring. Endpoint/protocol are
// per-sink so operators can ship audit events to a SIEM-specific OTLP
// collector that is *different* from the global telemetry exporter (which
// remains for traces and metrics).
//
// Unlike the legacy code path, this sink does not auto-inject any
// vendor-specific authentication header (e.g. Splunk's X-SF-Token).
// Operators must declare every header explicitly via the Headers map,
// using ${ENV_VAR} references for secrets.
type OTLPLogsConfig struct {
	Name        string
	Endpoint    string
	Protocol    string // "grpc" (default) or "http"
	URLPath     string
	Headers     map[string]string
	Insecure    bool
	CACertPath  string
	BatchSizeMx int
	QueueSize   int
	IntervalMs  int
	TimeoutS    int
	Filter      SinkFilter

	// LoggerName is the OTel scope name attached to each LogRecord. It
	// surfaces in the receiver as `instrumentation_scope.name` and lets
	// operators route DefenseClaw audit events on a stable identifier.
	LoggerName string

	// Resource attributes attached to every LogRecord. Caller passes the
	// shared resource (service.name, service.version, …) so audit logs
	// correlate with traces and metrics produced by telemetry.Provider.
	Resource *resource.Resource
}

// OTLPLogsSink emits each audit event as an OTLP LogRecord. It owns its
// own LoggerProvider so it can target a different endpoint than the
// global telemetry exporter; this is the standard pattern for separating
// security-audit pipelines from application telemetry.
type OTLPLogsSink struct {
	cfg      OTLPLogsConfig
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

// NewOTLPLogsSink builds the sink and starts its batch processor.
func NewOTLPLogsSink(ctx context.Context, cfg OTLPLogsConfig) (*OTLPLogsSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp_logs: endpoint is required")
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "grpc"
	}
	if cfg.BatchSizeMx <= 0 {
		cfg.BatchSizeMx = 512
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 2048
	}
	if cfg.IntervalMs <= 0 {
		cfg.IntervalMs = 5000
	}
	if cfg.TimeoutS <= 0 {
		cfg.TimeoutS = 10
	}
	if cfg.LoggerName == "" {
		cfg.LoggerName = "defenseclaw.audit"
	}

	exporter, err := buildLogExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otlp_logs: build exporter: %w", err)
	}

	processor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithMaxQueueSize(cfg.QueueSize),
		sdklog.WithExportMaxBatchSize(cfg.BatchSizeMx),
		sdklog.WithExportInterval(time.Duration(cfg.IntervalMs)*time.Millisecond),
	)

	opts := []sdklog.LoggerProviderOption{sdklog.WithProcessor(processor)}
	if cfg.Resource != nil {
		opts = append(opts, sdklog.WithResource(cfg.Resource))
	}
	provider := sdklog.NewLoggerProvider(opts...)

	return &OTLPLogsSink{
		cfg:      cfg,
		provider: provider,
		logger:   provider.Logger(cfg.LoggerName),
	}, nil
}

func (s *OTLPLogsSink) Name() string { return s.cfg.Name }
func (s *OTLPLogsSink) Kind() string { return "otlp_logs" }

func (s *OTLPLogsSink) Forward(ctx context.Context, e Event) error {
	if !s.cfg.Filter.Matches(e) {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	record := otellog.Record{}
	record.SetTimestamp(e.Timestamp)
	record.SetObservedTimestamp(time.Now())
	record.SetSeverityText(e.Severity)
	record.SetSeverity(severityToOTel(e.Severity))
	// Body is the canonical machine-readable payload — JSON-encode the
	// structured map (or fall back to the free-form details string) so a
	// receiver can route on body fields without parsing the resource.
	record.SetBody(otellog.StringValue(buildBody(e)))

	record.AddAttributes(
		otellog.String("audit.id", e.ID),
		otellog.String("audit.action", e.Action),
		otellog.String("audit.target", e.Target),
		otellog.String("audit.actor", e.Actor),
		otellog.String("audit.severity", e.Severity),
		otellog.String("audit.run_id", e.RunID),
		otellog.String("audit.trace_id", e.TraceID),
		otellog.String("audit.request_id", e.RequestID),
	)
	if e.Details != "" {
		record.AddAttributes(otellog.String("audit.details", e.Details))
	}
	// Extended correlation fields — only added when non-empty so
	// downstream query layers (Grafana/OTel Cloud) don't get a flood
	// of empty attribute rows on events that predate the v6 contract.
	if e.SessionID != "" {
		record.AddAttributes(otellog.String("audit.session_id", e.SessionID))
	}
	if e.AgentName != "" {
		record.AddAttributes(otellog.String("audit.agent_name", e.AgentName))
	}
	if e.AgentInstanceID != "" {
		record.AddAttributes(otellog.String("audit.agent_instance_id", e.AgentInstanceID))
	}
	if e.PolicyID != "" {
		record.AddAttributes(otellog.String("audit.policy_id", e.PolicyID))
	}
	if e.DestinationApp != "" {
		record.AddAttributes(otellog.String("audit.destination_app", e.DestinationApp))
	}
	if e.ToolName != "" {
		record.AddAttributes(otellog.String("audit.tool_name", e.ToolName))
	}
	if e.ToolID != "" {
		record.AddAttributes(otellog.String("audit.tool_id", e.ToolID))
	}

	s.logger.Emit(ctx, record)
	return nil
}

func (s *OTLPLogsSink) Flush(ctx context.Context) error {
	if s.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.provider.ForceFlush(ctx)
}

func (s *OTLPLogsSink) Close() error {
	if s.provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.provider.Shutdown(ctx)
}

func buildLogExporter(ctx context.Context, cfg OTLPLogsConfig) (sdklog.Exporter, error) {
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = expandEnv(v)
	}

	if cfg.Protocol == "http" {
		opts := []loghttp.Option{
			loghttp.WithHeaders(headers),
			loghttp.WithTimeout(time.Duration(cfg.TimeoutS) * time.Second),
		}
		if host, path, insecure, ok := splitEndpointURL(cfg.Endpoint); ok {
			opts = append(opts, loghttp.WithEndpoint(host))
			if insecure {
				opts = append(opts, loghttp.WithInsecure())
			}
			if cfg.URLPath == "" && path != "" && path != "/" {
				opts = append(opts, loghttp.WithURLPath(path))
			}
		} else {
			opts = append(opts, loghttp.WithEndpoint(cfg.Endpoint))
		}
		if cfg.URLPath != "" {
			opts = append(opts, loghttp.WithURLPath(cfg.URLPath))
		}
		if cfg.Insecure {
			opts = append(opts, loghttp.WithInsecure())
		}
		if cfg.CACertPath != "" {
			tlsCfg, err := loadTLSConfig(cfg.CACertPath)
			if err != nil {
				return nil, err
			}
			opts = append(opts, loghttp.WithTLSClientConfig(tlsCfg))
		}
		return loghttp.New(ctx, opts...)
	}

	opts := []loggrpc.Option{
		loggrpc.WithHeaders(headers),
		loggrpc.WithTimeout(time.Duration(cfg.TimeoutS) * time.Second),
	}
	if endpointLooksLikeURL(cfg.Endpoint) {
		opts = append(opts, loggrpc.WithEndpointURL(cfg.Endpoint))
	} else {
		opts = append(opts, loggrpc.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, loggrpc.WithInsecure())
	} else if cfg.CACertPath != "" {
		tlsCfg, err := loadTLSConfig(cfg.CACertPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, loggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	}
	return loggrpc.New(ctx, opts...)
}

func loadTLSConfig(caCertPath string) (*tls.Config, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("otlp_logs: read CA cert %s: %w", caCertPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("otlp_logs: parse CA cert %s", caCertPath)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// severityToOTel maps DefenseClaw severity strings to OTel SeverityNumbers
// so receivers can apply standard filtering.
func severityToOTel(s string) otellog.Severity {
	switch severityRank(s) {
	case severityCritical:
		return otellog.SeverityFatal
	case severityHigh:
		return otellog.SeverityError
	case severityMedium:
		return otellog.SeverityWarn
	case severityLow:
		return otellog.SeverityInfo
	default:
		return otellog.SeverityInfo
	}
}

// buildBody serialises the structured payload (preferred) or falls back to
// the legacy free-form details string. Always returns valid JSON so OTLP
// receivers can route on body content.
func buildBody(e Event) string {
	if len(e.Structured) > 0 {
		if buf, err := json.Marshal(e.Structured); err == nil {
			return string(buf)
		}
	}
	if e.Details != "" {
		buf, _ := json.Marshal(map[string]string{
			"action":  e.Action,
			"target":  e.Target,
			"details": e.Details,
		})
		return string(buf)
	}
	buf, _ := json.Marshal(map[string]string{
		"action": e.Action,
		"target": e.Target,
	})
	return string(buf)
}

// endpointLooksLikeURL returns true when the configured endpoint carries a
// scheme (e.g. "http://host:4318/v1/logs"). Used to decide whether we should
// route via WithEndpointURL (which parses the full URL) or WithEndpoint
// (host:port only).
func endpointLooksLikeURL(endpoint string) bool {
	return strings.Contains(endpoint, "://")
}

// splitEndpointURL extracts host, path, and insecure (http scheme) from a
// URL-form endpoint. Returns ok=false for non-URL inputs so callers can fall
// back to treating the value as a bare host:port. Empty host is treated as
// a parse failure because OTLP exporters require a host to dial.
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
