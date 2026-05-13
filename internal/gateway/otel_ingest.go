// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package-internal OTLP-HTTP receiver. Hosts /v1/logs, /v1/metrics,
// and /v1/traces — the three signal endpoints the OTel HTTP exporter
// fans out to. Codex (via [otel.exporter.otlp-http]) and Claude Code
// (via OTEL_EXPORTER_OTLP_ENDPOINT) post structured telemetry here
// with a baked-in x-defenseclaw-token header so the gateway can
// authenticate the originating CLI process the same way the hook
// scripts do.
//
// This receiver is intentionally summary-oriented: we accept the body,
// attach the connector source and gateway tokens (already validated by
// tokenAuth middleware), normalize OTLP JSON/protobuf into the same
// summary shape, promote known GenAI session/token/duration fields,
// and persist via persistAuditEvent. Operators who want full raw OTel
// pipelines still run the gateway's downstream OTLP forwarder
// (separate, see internal/audit/sinks/otlp_logs.go).
//
// Threat model:
//   - All three endpoints are gated by tokenAuth + apiCSRFProtect
//     (the same chain as /api/v1/codex/hook). Unauthenticated POSTs
//     are rejected upstream of this handler.
//   - Body size is capped by maxBodyMiddleware (1 MiB). The OTLP
//     spec recommends batching; one MiB covers roughly 50-100 log
//     records or 500-1000 metric data points per batch.
//   - Payload parsing failures are audited as malformed and still
//     return OTLP success; retrying the same bad batch would only
//     create gateway load and noisier telemetry.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// otelIngestStats is what summarizeOTLPPayload returns alongside
// the human-readable summary. We keep it tiny on purpose — the
// counters we expose are low-cardinality (signal × source) so a
// noisy connector cannot explode the TSDB.
type otelIngestStats struct {
	// Records is the number of leaf records (logRecords / metrics
	// data points / spans) the summarizer extracted. 0 when the
	// envelope is well-formed but empty (which is rare but legal
	// per the OTLP spec — exporters flush empty batches).
	Records int64
	// Resources is the number of top-level resourceLogs / resourceMetrics
	// / resourceSpans entries. Useful for spotting batches that
	// span many services.
	Resources int64
}

// otelIngestSignal classifies which OTLP-HTTP path the request hit.
type otelIngestSignal string

const (
	otelSignalLogs    otelIngestSignal = "logs"
	otelSignalMetrics otelIngestSignal = "metrics"
	otelSignalTraces  otelIngestSignal = "traces"
)

// otelIngestSource is the connector that originated the OTel POST.
// We trust the x-defenseclaw-source header (which Setup() bakes in
// to the codex [otel] block and the Claude Code env block) but
// only AFTER tokenAuth has validated x-defenseclaw-token. The
// header is therefore self-asserted but tied to a verified
// credential — same trust model as Authorization-bearer flows.
const otelSourceHeader = "x-defenseclaw-source"

// otelIngestMaxBatchSummary caps the number of resource entries we
// summarize in an audit Details string. OTLP batches can carry
// hundreds of records; persisting all of them to SQLite Details
// (text column) would balloon the audit DB. The OTel forwarder sink
// keeps the full payload — this receiver intentionally summarizes.
const otelIngestMaxBatchSummary = 5

// handleOTLPLogs accepts OTLP-HTTP /v1/logs POSTs from CLI processes.
// Body may be OTLP-JSON (application/json) or OTLP protobuf
// (application/x-protobuf). Both forms are summarized structurally after
// protobuf is normalized to the OTLP-JSON field shape.
func (a *APIServer) handleOTLPLogs(w http.ResponseWriter, r *http.Request) {
	a.handleOTLPSignal(w, r, otelSignalLogs)
}

// handleOTLPMetrics accepts OTLP-HTTP /v1/metrics POSTs.
func (a *APIServer) handleOTLPMetrics(w http.ResponseWriter, r *http.Request) {
	a.handleOTLPSignal(w, r, otelSignalMetrics)
}

// handleOTLPTraces accepts OTLP-HTTP /v1/traces POSTs. Currently
// only Codex's native OTel exporter emits traces (Claude Code
// emits logs + metrics by default). We register the route anyway
// so a future Claude Code release that adds trace export Just
// Works without a gateway change.
func (a *APIServer) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	a.handleOTLPSignal(w, r, otelSignalTraces)
}

func (a *APIServer) handleOTLPPathToken(w http.ResponseWriter, r *http.Request) {
	_, source, ok := parseOTLPPathToken(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.Header.Get(otelSourceHeader)) == "" {
		r.Header.Set(otelSourceHeader, source)
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/v1/logs"):
		a.handleOTLPSignal(w, r, otelSignalLogs)
	case strings.HasSuffix(r.URL.Path, "/v1/metrics"):
		a.handleOTLPSignal(w, r, otelSignalMetrics)
	case strings.HasSuffix(r.URL.Path, "/v1/traces"):
		a.handleOTLPSignal(w, r, otelSignalTraces)
	default:
		http.NotFound(w, r)
	}
}

// handleOTLPSignal is the shared body for all three signal types.
// It validates the request shape, classifies the source, summarizes
// the payload into an audit event, and returns 200 with the
// canonical OTLP empty-success body so the exporter doesn't retry.
//
// The OTLP spec defines the success response as an empty
// ExportPartialSuccess message; "{}" is the JSON form. Returning a
// non-empty body triggers retries on some exporter implementations.
func (a *APIServer) handleOTLPSignal(w http.ResponseWriter, r *http.Request, signal otelIngestSignal) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if !isOTLPContentType(contentType) {
		// Be explicit about why we rejected so the exporter logs
		// surface the right error.
		w.Header().Set("Accept", "application/json, application/x-protobuf")
		http.Error(w,
			fmt.Sprintf("unsupported content-type %q (defenseclaw OTLP receiver accepts application/json or application/x-protobuf)", contentType),
			http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	source := strings.ToLower(strings.TrimSpace(r.Header.Get(otelSourceHeader)))
	if source == "" {
		// Fall back to "unknown" rather than rejecting — older
		// codex/claude releases that didn't bake the header still
		// produce useful telemetry, and tokenAuth has already
		// validated the credential.
		source = "unknown"
	}
	source = normalizeConnectorTelemetrySource(source)
	ctx := r.Context()
	if id := agentIdentityForOTLPSource(source); !id.IsZero() {
		ctx = ContextWithAgentIdentity(ctx, id)
	}

	bodyBytes := int64(len(body))
	summaryBody, payloadFormat, normalizeErr := normalizeOTLPIngestBody(body, signal, contentType)
	if normalizeErr != nil {
		details := fmt.Sprintf("malformed OTLP-%s payload: %v (size=%d bytes)", payloadFormat, normalizeErr, len(body))
		details = a.appendRawOTLPDetails(details, source, signal, body)
		ev := audit.Event{
			Timestamp: time.Now().UTC(),
			Action:    string(audit.ActionOTelIngestMalformed),
			Target:    fmt.Sprintf("otlp:%s", signal),
			Actor:     source,
			Details:   details,
			Severity:  "WARN",
			AgentName: source,
		}
		_ = persistAuditEvent(a.logger, a.store, ev)
		a.otel.RecordOTelIngest(ctx, string(signal), source, "malformed", 0, bodyBytes)
		a.otel.EmitConnectorTelemetryLog(ctx, string(signal), source, "malformed", 0, bodyBytes, details)
		writeOTLPSuccess(w)
		return
	}

	sessionID := extractOTLPSessionID(summaryBody, signal)
	if sessionID != "" {
		ctx = ContextWithSessionID(ctx, sessionID)
		enrichHTTPSpanFromContext(ctx)
		enrichOTLPIngestSpan(ctx, sessionID)
	}
	summary, stats, parseErr := summarizeOTLPPayload(summaryBody, signal)
	if parseErr != nil {
		// We log the parse failure but still 200 — the exporter
		// already paid the network round-trip and retrying won't
		// help (the body is malformed). Audit + meter + emit a
		// WARN log so dashboards / alerts surface the drift
		// without the exporter retrying.
		details := fmt.Sprintf("malformed OTLP-%s normalized payload: %v (size=%d bytes)", payloadFormat, parseErr, len(body))
		details = a.appendRawOTLPDetails(details, source, signal, body)
		ev := audit.Event{
			Timestamp: time.Now().UTC(),
			Action:    string(audit.ActionOTelIngestMalformed),
			Target:    fmt.Sprintf("otlp:%s", signal),
			Actor:     source,
			Details:   details,
			Severity:  "WARN",
			AgentName: source,
			SessionID: sessionID,
		}
		_ = persistAuditEvent(a.logger, a.store, ev)
		// Record metrics + emit OTel log for the malformed branch.
		// We pass records=0 (we couldn't extract any) but keep
		// bodyBytes so volume dashboards still see the request.
		a.otel.RecordOTelIngest(ctx, string(signal), source, "malformed", 0, bodyBytes)
		a.otel.EmitConnectorTelemetryLog(ctx, string(signal), source, "malformed", 0, bodyBytes,
			a.appendRawOTLPDetails(fmt.Sprintf("malformed OTLP-%s normalized payload: %v", payloadFormat, parseErr), source, signal, body))
		writeOTLPSuccess(w)
		return
	}
	summary = decorateOTLPIngestSummary(summary, payloadFormat, len(body), len(summaryBody))
	summary = a.appendRawOTLPDetails(summary, source, signal, body)

	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    otelIngestActionForSignal(signal),
		Target:    fmt.Sprintf("otlp:%s", signal),
		Actor:     source,
		Details:   summary,
		Severity:  "INFO",
		AgentName: source,
		SessionID: sessionID,
	}
	if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
		// Best-effort: failing to persist must NOT cause the
		// exporter to retry — telemetry storms during DB outages
		// are worse than the lost batch. Log to stderr in the
		// usual gateway pattern and 200.
		fmt.Fprintf(otelIngestLogSink(), "[otel-ingest] persist failed (signal=%s source=%s): %v\n", signal, source, err)
	}

	// Record metrics + emit OTel log on the happy path. The OTel
	// log routes through the gateway's own logger provider so the
	// local-observability-stack's Loki receives codex/claudecode
	// telemetry directly — no extra audit OTLP sink needed.
	a.otel.RecordOTelIngest(ctx, string(signal), source, "ok", stats.Records, bodyBytes)
	tokenUsage := extractOTLPTokenUsage(summaryBody, signal, source)
	for _, usage := range tokenUsage {
		a.otel.RecordLLMTokenUsage(ctx, usage.operationName, usage.providerName, usage.model, usage.agentName, SharedAgentRegistry().AgentID(), usage.tokenType, usage.tokens)
	}
	durations := extractOTLPOperationDurations(summaryBody, signal, source)
	for _, duration := range durations {
		a.otel.RecordLLMDuration(ctx, duration.operationName, duration.providerName, duration.model, duration.agentName, SharedAgentRegistry().AgentID(), duration.durationSeconds)
	}
	if signal == otelSignalMetrics && source == "openclaw" {
		a.persistOTLPDashboardMetricAuditEvents(source, sessionID, extractOTLPMetricDashboardValues(summaryBody, source))
	} else {
		a.persistOTLPUsageMetricAuditEvents(source, sessionID, tokenUsage, durations)
	}
	a.otel.EmitConnectorTelemetryLog(ctx, string(signal), source, "ok", stats.Records, bodyBytes, summary)

	writeOTLPSuccess(w)
}

func normalizeOTLPIngestBody(body []byte, signal otelIngestSignal, contentType string) ([]byte, string, error) {
	if !isOTLPProtobufContentType(contentType) {
		return body, "json", nil
	}

	var msg proto.Message
	switch signal {
	case otelSignalLogs:
		msg = &collectorlogspb.ExportLogsServiceRequest{}
	case otelSignalMetrics:
		msg = &collectormetricspb.ExportMetricsServiceRequest{}
	case otelSignalTraces:
		msg = &collectortracepb.ExportTraceServiceRequest{}
	default:
		return nil, "protobuf", fmt.Errorf("unknown OTLP signal %q", signal)
	}
	if err := proto.Unmarshal(body, msg); err != nil {
		return nil, "protobuf", err
	}
	normalized, err := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}.Marshal(msg)
	if err != nil {
		return nil, "protobuf", err
	}
	return normalized, "protobuf", nil
}

func decorateOTLPIngestSummary(summary, payloadFormat string, wireBytes, normalizedBytes int) string {
	if payloadFormat != "protobuf" {
		return summary
	}
	return fmt.Sprintf("format=protobuf wire_size=%d bytes normalized_json_size=%d bytes %s", wireBytes, normalizedBytes, summary)
}

func agentIdentityForOTLPSource(source string) AgentIdentity {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" || source == "unknown" {
		return AgentIdentity{}
	}
	id := AgentIdentity{
		AgentName: source,
		AgentType: source,
	}
	if reg := SharedAgentRegistry(); reg != nil {
		id.AgentID = reg.AgentID()
		if name := reg.AgentName(); name != "" {
			id.AgentName = name
		}
	}
	return id
}

func normalizeConnectorTelemetrySource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "openclaw", "zeptoclaw", "claudecode", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot":
		return strings.ToLower(strings.TrimSpace(source))
	case "claude-code", "claude_code":
		return "claudecode"
	case "gemini-cli", "gemini_cli", "gemini":
		return "geminicli"
	default:
		return "unknown"
	}
}

func enrichOTLPIngestSpan(ctx context.Context, sessionID string) {
	if sessionID == "" {
		return
	}
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(attribute.String("gen_ai.conversation.id", sessionID))
}

func extractOTLPSessionID(body []byte, signal otelIngestSignal) string {
	if len(body) == 0 {
		return ""
	}
	switch signal {
	case otelSignalLogs:
		return extractOTLPLogSessionID(body)
	default:
		return ""
	}
}

func extractOTLPLogSessionID(body []byte) string {
	var envelope struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}

	for _, resource := range envelope.ResourceLogs {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		if sessionID := otlpSessionID(resourceAttrs); sessionID != "" {
			return sessionID
		}
		for _, scope := range resource.ScopeLogs {
			for _, rec := range scope.LogRecords {
				attrs := otlpAttributesToMap(rec.Attributes)
				for k, v := range resourceAttrs {
					if _, exists := attrs[k]; !exists {
						attrs[k] = v
					}
				}
				if sessionID := otlpSessionID(attrs); sessionID != "" {
					return sessionID
				}
			}
		}
	}
	return ""
}

func otlpSessionID(attrs map[string]interface{}) string {
	return firstNonEmpty(
		otlpString(attrs, "session.id"),
		otlpString(attrs, "session_id"),
		otlpString(attrs, "gen_ai.conversation.id"),
		otlpString(attrs, "conversation.id"),
	)
}

type otelTokenUsage struct {
	operationName string
	providerName  string
	model         string
	agentName     string
	tokenType     string
	tokens        int64
}

type otelLLMDuration struct {
	operationName   string
	providerName    string
	model           string
	agentName       string
	durationSeconds float64
}

type otelDashboardMetric struct {
	metricName   string
	value        float64
	unit         string
	provider     string
	model        string
	operation    string
	tokenType    string
	channel      string
	component    string
	temporality  string
	sourceSignal string
	gatewayHost  string
}

// extractOTLPTokenUsage promotes connector-native OTLP log fields into
// DefenseClaw's canonical GenAI token histogram. Codex emits token usage
// on log records, and Claude Code emits its own claude_code.token.usage
// counter instead of the GenAI semconv histogram:
//
//	event.name="codex.sse_event"
//	event.kind="response.completed"
//	input_token_count / output_token_count / cached_token_count / ...
//	claude_code.token.usage{type=input|output|cacheRead|cacheCreation,model=...}
//
// The gateway still keeps the raw OTLP receiver small; this extraction
// is deliberately narrow and low-cardinality so dashboards get token
// spend without storing raw prompts or replaying arbitrary OTLP metrics.
func extractOTLPTokenUsage(body []byte, signal otelIngestSignal, source string) []otelTokenUsage {
	if len(body) == 0 {
		return nil
	}
	switch signal {
	case otelSignalLogs:
		return extractOTLPLogTokenUsage(body, source)
	case otelSignalMetrics:
		return extractOTLPMetricTokenUsage(body, source)
	default:
		return nil
	}
}

func extractOTLPLogTokenUsage(body []byte, source string) []otelTokenUsage {
	var envelope struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	var out []otelTokenUsage
	for _, resource := range envelope.ResourceLogs {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		serviceName := otlpString(resourceAttrs, "service.name")
		for _, scope := range resource.ScopeLogs {
			for _, rec := range scope.LogRecords {
				attrs := otlpAttributesToMap(rec.Attributes)
				eventName := otlpString(attrs, "event.name")
				eventKind := otlpString(attrs, "event.kind")

				inputTokens := otlpInt(attrs,
					"input_token_count",
					"input_tokens",
					"prompt_token_count",
					"prompt_tokens",
					"gen_ai.usage.input_tokens",
					"gen_ai.usage.prompt_tokens",
					"gen_ai.usage.input",
					"gen_ai.usage.prompt",
					"codex.turn.token_usage.input_tokens",
					"codex.turn.token_usage.prompt_tokens",
					"usage.input_tokens",
					"usage.prompt_tokens",
					"llm.usage.input_tokens",
					"llm.usage.prompt_tokens",
				)
				outputTokens := otlpInt(attrs,
					"output_token_count",
					"output_tokens",
					"completion_token_count",
					"completion_tokens",
					"generated_token_count",
					"generated_tokens",
					"gen_ai.usage.output_tokens",
					"gen_ai.usage.completion_tokens",
					"gen_ai.usage.output",
					"gen_ai.usage.completion",
					"codex.turn.token_usage.output_tokens",
					"codex.turn.token_usage.completion_tokens",
					"usage.output_tokens",
					"usage.completion_tokens",
					"llm.usage.output_tokens",
					"llm.usage.completion_tokens",
					"response.output_tokens",
					"response.completion_tokens",
				)
				if inputTokens <= 0 && outputTokens <= 0 {
					continue
				}

				// For Codex, only response.completed carries complete
				// per-response token counts. This avoids counting partial
				// or diagnostic events that happen to include token-ish
				// fields in future releases.
				if eventName == "codex.sse_event" && eventKind != "response.completed" {
					continue
				}

				agentName := source
				if agentName == "" || agentName == "unknown" {
					agentName = firstNonEmpty(
						otlpString(attrs, "gen_ai.agent.name"),
						serviceName,
						"unknown",
					)
				}
				out = append(out, otelTokenUsage{
					operationName: firstNonEmpty(otlpString(attrs, "gen_ai.operation.name"), "chat"),
					providerName:  firstNonEmpty(otlpString(attrs, "gen_ai.provider.name"), source, serviceName, "unknown"),
					model: firstNonEmpty(
						otlpString(attrs, "gen_ai.response.model"),
						otlpString(attrs, "gen_ai.request.model"),
						otlpString(attrs, "model"),
						"unknown",
					),
					agentName: agentName,
					tokenType: "input",
					tokens:    inputTokens,
				})
				out = append(out, otelTokenUsage{
					operationName: firstNonEmpty(otlpString(attrs, "gen_ai.operation.name"), "chat"),
					providerName:  firstNonEmpty(otlpString(attrs, "gen_ai.provider.name"), source, serviceName, "unknown"),
					model: firstNonEmpty(
						otlpString(attrs, "gen_ai.response.model"),
						otlpString(attrs, "gen_ai.request.model"),
						otlpString(attrs, "model"),
						"unknown",
					),
					agentName: agentName,
					tokenType: "output",
					tokens:    outputTokens,
				})
			}
		}
	}
	return out
}

func extractOTLPMetricTokenUsage(body []byte, source string) []otelTokenUsage {
	var envelope struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string              `json:"name"`
					Unit      string              `json:"unit"`
					Sum       otlpMetricPoints    `json:"sum"`
					Gauge     otlpMetricPoints    `json:"gauge"`
					Histogram otlpHistogramPoints `json:"histogram"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	var out []otelTokenUsage
	for _, resource := range envelope.ResourceMetrics {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		serviceName := otlpString(resourceAttrs, "service.name")
		for _, scope := range resource.ScopeMetrics {
			for _, metric := range scope.Metrics {
				if metric.Name != "claude_code.token.usage" && metric.Name != "openclaw.tokens" {
					continue
				}
				points := metric.Sum.DataPoints
				if len(points) == 0 {
					points = metric.Gauge.DataPoints
				}
				for _, point := range points {
					attrs := otlpAttributesToMap(point.Attributes)
					tokenType := normalizeOTLPTokenType(firstNonEmpty(
						otlpString(attrs, "type"),
						otlpString(attrs, "openclaw.token"),
					))
					tokens := otlpDataPointInt(point.AsInt, point.AsDouble)
					if tokenType == "" || tokens <= 0 {
						continue
					}
					agentName := source
					if agentName == "" || agentName == "unknown" {
						agentName = firstNonEmpty(serviceName, "unknown")
					}
					out = append(out, otelTokenUsage{
						operationName: firstNonEmpty(openclawMetricOperationName(metric.Name, attrs), "chat"),
						providerName: firstNonEmpty(
							otlpString(attrs, "openclaw.provider"),
							otlpString(attrs, "gen_ai.provider.name"),
							source,
							serviceName,
							"claudecode",
						),
						model: firstNonEmpty(
							otlpString(attrs, "openclaw.model"),
							otlpString(attrs, "gen_ai.response.model"),
							otlpString(attrs, "gen_ai.request.model"),
							otlpString(attrs, "model"),
							"unknown",
						),
						agentName: agentName,
						tokenType: tokenType,
						tokens:    tokens,
					})
				}
			}
		}
	}
	return out
}

func extractOTLPOperationDurations(body []byte, signal otelIngestSignal, source string) []otelLLMDuration {
	if len(body) == 0 {
		return nil
	}
	switch signal {
	case otelSignalLogs:
		return extractOTLPLogDurations(body, source)
	case otelSignalMetrics:
		return extractOTLPMetricDurations(body, source)
	case otelSignalTraces:
		return extractOTLPTraceDurations(body, source)
	default:
		return nil
	}
}

func extractOTLPLogDurations(body []byte, source string) []otelLLMDuration {
	var envelope struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}
	var out []otelLLMDuration
	for _, resource := range envelope.ResourceLogs {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		for _, scope := range resource.ScopeLogs {
			for _, rec := range scope.LogRecords {
				attrs := otlpAttributesToMap(rec.Attributes)
				seconds := otlpDurationSeconds(attrs)
				if seconds <= 0 {
					continue
				}
				out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, seconds, "chat"))
			}
		}
	}
	return out
}

func extractOTLPMetricDurations(body []byte, source string) []otelLLMDuration {
	var envelope struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string              `json:"name"`
					Unit      string              `json:"unit"`
					Sum       otlpMetricPoints    `json:"sum"`
					Gauge     otlpMetricPoints    `json:"gauge"`
					Histogram otlpHistogramPoints `json:"histogram"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}
	var out []otelLLMDuration
	for _, resource := range envelope.ResourceMetrics {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		for _, scope := range resource.ScopeMetrics {
			for _, metric := range scope.Metrics {
				if !isLLMDurationMetric(metric.Name) {
					continue
				}
				for _, point := range metric.Histogram.DataPoints {
					count := parseOTLPNumber(point.Count)
					sum := parseOTLPNumberFloat(point.Sum)
					if count <= 0 || sum <= 0 {
						continue
					}
					attrs := otlpAttributesToMap(point.Attributes)
					out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, normalizeDurationByUnit(sum/float64(count), metric.Unit), openclawMetricOperationName(metric.Name, attrs)))
				}
				for _, point := range metric.Gauge.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					seconds := otlpMetricPointDurationSeconds(point, metric.Unit)
					if seconds > 0 {
						out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, seconds, openclawMetricOperationName(metric.Name, attrs)))
					}
				}
				for _, point := range metric.Sum.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					seconds := otlpMetricPointDurationSeconds(point, metric.Unit)
					if seconds > 0 {
						out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, seconds, openclawMetricOperationName(metric.Name, attrs)))
					}
				}
			}
		}
	}
	return out
}

func extractOTLPTraceDurations(body []byte, source string) []otelLLMDuration {
	var envelope struct {
		ResourceSpans []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeSpans []struct {
				Spans []struct {
					Name              string          `json:"name"`
					Attributes        []otlpAttribute `json:"attributes"`
					StartTimeUnixNano json.RawMessage `json:"startTimeUnixNano"`
					EndTimeUnixNano   json.RawMessage `json:"endTimeUnixNano"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}
	var out []otelLLMDuration
	for _, resource := range envelope.ResourceSpans {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		for _, scope := range resource.ScopeSpans {
			for _, span := range scope.Spans {
				attrs := otlpAttributesToMap(span.Attributes)
				if !spanLooksLikeLLMOperation(span.Name, attrs) {
					continue
				}
				start := parseOTLPNumber(span.StartTimeUnixNano)
				end := parseOTLPNumber(span.EndTimeUnixNano)
				if start <= 0 || end <= start {
					continue
				}
				out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, float64(end-start)/1e9, span.Name))
			}
		}
	}
	return out
}

type otlpMetricPoints struct {
	AggregationTemporality string                `json:"aggregationTemporality"`
	DataPoints             []otlpMetricDataPoint `json:"dataPoints"`
}

type otlpMetricDataPoint struct {
	Attributes []otlpAttribute `json:"attributes"`
	AsInt      json.RawMessage `json:"asInt"`
	AsDouble   json.RawMessage `json:"asDouble"`
}

type otlpHistogramPoints struct {
	DataPoints []otlpHistogramDataPoint `json:"dataPoints"`
}

type otlpHistogramDataPoint struct {
	Attributes []otlpAttribute `json:"attributes"`
	Sum        json.RawMessage `json:"sum"`
	Count      json.RawMessage `json:"count"`
}

type otlpAttribute struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

func otlpAttributesToMap(attrs []otlpAttribute) map[string]interface{} {
	out := make(map[string]interface{}, len(attrs))
	for _, attr := range attrs {
		if attr.Key == "" {
			continue
		}
		out[attr.Key] = decodeOTLPAnyValue(attr.Value)
	}
	return out
}

func decodeOTLPAnyValue(raw json.RawMessage) interface{} {
	var v struct {
		StringValue *string      `json:"stringValue"`
		IntValue    *json.Number `json:"intValue"`
		DoubleValue *float64     `json:"doubleValue"`
		BoolValue   *bool        `json:"boolValue"`
		KvListValue *struct {
			Values []otlpAttribute `json:"values"`
		} `json:"kvlistValue"`
		ArrayValue *struct {
			Values []json.RawMessage `json:"values"`
		} `json:"arrayValue"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != nil:
		if i, err := v.IntValue.Int64(); err == nil {
			return i
		}
		return v.IntValue.String()
	case v.DoubleValue != nil:
		return *v.DoubleValue
	case v.BoolValue != nil:
		return *v.BoolValue
	case v.KvListValue != nil:
		return otlpAttributesToMap(v.KvListValue.Values)
	case v.ArrayValue != nil:
		out := make([]interface{}, 0, len(v.ArrayValue.Values))
		for _, item := range v.ArrayValue.Values {
			out = append(out, decodeOTLPAnyValue(item))
		}
		return out
	default:
		return nil
	}
}

func otlpString(attrs map[string]interface{}, key string) string {
	v, ok := otlpLookup(attrs, key)
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func otlpInt(attrs map[string]interface{}, keys ...string) int64 {
	for _, key := range keys {
		v, ok := otlpLookup(attrs, key)
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case int64:
			return x
		case float64:
			return int64(x)
		case string:
			if i, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil {
				return i
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
				return int64(f)
			}
		}
	}
	return 0
}

func otlpFloat(attrs map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		v, ok := otlpLookup(attrs, key)
		if !ok || v == nil {
			continue
		}
		switch x := v.(type) {
		case int64:
			return float64(x)
		case float64:
			return x
		case json.Number:
			if f, err := strconv.ParseFloat(x.String(), 64); err == nil {
				return f
			}
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
				return f
			}
		}
	}
	return 0
}

func otlpLookup(attrs map[string]interface{}, key string) (interface{}, bool) {
	if attrs == nil || key == "" {
		return nil, false
	}
	if v, ok := attrs[key]; ok {
		return v, true
	}
	parts := strings.Split(key, ".")
	for prefixLen := len(parts) - 1; prefixLen >= 1; prefixLen-- {
		prefix := strings.Join(parts[:prefixLen], ".")
		v, ok := attrs[prefix]
		if !ok {
			continue
		}
		if found, ok := otlpTraverse(v, parts[prefixLen:]); ok {
			return found, true
		}
	}
	return nil, false
}

func otlpTraverse(v interface{}, parts []string) (interface{}, bool) {
	cur := v
	for _, part := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func otlpDataPointInt(rawInt, rawDouble json.RawMessage) int64 {
	if len(rawInt) > 0 && string(rawInt) != "null" {
		if n := parseOTLPNumber(rawInt); n > 0 {
			return n
		}
	}
	if len(rawDouble) > 0 && string(rawDouble) != "null" {
		return parseOTLPNumber(rawDouble)
	}
	return 0
}

func otlpDataPointFloat(rawInt, rawDouble json.RawMessage) float64 {
	if len(rawDouble) > 0 && string(rawDouble) != "null" {
		return parseOTLPNumberFloat(rawDouble)
	}
	if len(rawInt) > 0 && string(rawInt) != "null" {
		return parseOTLPNumberFloat(rawInt)
	}
	return 0
}

func parseOTLPNumber(raw json.RawMessage) int64 {
	var asNumber json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&asNumber); err == nil {
		if i, intErr := asNumber.Int64(); intErr == nil {
			return i
		}
		if f, floatErr := strconv.ParseFloat(asNumber.String(), 64); floatErr == nil {
			return int64(f)
		}
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		asString = strings.TrimSpace(asString)
		if i, intErr := strconv.ParseInt(asString, 10, 64); intErr == nil {
			return i
		}
		if f, floatErr := strconv.ParseFloat(asString, 64); floatErr == nil {
			return int64(f)
		}
	}
	return 0
}

func parseOTLPNumberFloat(raw json.RawMessage) float64 {
	if len(raw) == 0 || string(raw) == "null" {
		return 0
	}
	var asNumber json.Number
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&asNumber); err == nil {
		if f, err := strconv.ParseFloat(asNumber.String(), 64); err == nil {
			return f
		}
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		if f, err := strconv.ParseFloat(strings.TrimSpace(asString), 64); err == nil {
			return f
		}
	}
	return 0
}

func otlpDurationSeconds(attrs map[string]interface{}) float64 {
	if seconds := otlpFloat(attrs,
		"gen_ai.client.operation.duration",
		"gen_ai.operation.duration",
		"duration_seconds",
		"duration_s",
		"duration",
		"elapsed_seconds",
		"elapsed_s",
		"elapsed",
		"latency_seconds",
		"latency_s",
		"latency",
		"response.duration",
		"codex.turn.duration_seconds",
	); seconds > 0 {
		return seconds
	}
	if millis := otlpFloat(attrs,
		"duration_ms",
		"duration_milliseconds",
		"elapsed_ms",
		"latency_ms",
		"response.duration_ms",
		"codex.turn.duration_ms",
		"gen_ai.client.operation.duration_ms",
		"gen_ai.operation.duration_ms",
	); millis > 0 {
		return millis / 1000
	}
	if nanos := otlpFloat(attrs,
		"duration_ns",
		"duration_nanos",
		"elapsed_ns",
		"latency_ns",
		"gen_ai.client.operation.duration_ns",
		"gen_ai.operation.duration_ns",
	); nanos > 0 {
		return nanos / 1e9
	}
	return 0
}

func otlpMetricPointDurationSeconds(point otlpMetricDataPoint, unit string) float64 {
	if len(point.AsDouble) > 0 && string(point.AsDouble) != "null" {
		return normalizeDurationByUnit(parseOTLPNumberFloat(point.AsDouble), unit)
	}
	if len(point.AsInt) > 0 && string(point.AsInt) != "null" {
		return normalizeDurationByUnit(parseOTLPNumberFloat(point.AsInt), unit)
	}
	return 0
}

func normalizeDurationByUnit(value float64, unit string) float64 {
	if value <= 0 {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "ms", "millisecond", "milliseconds":
		return value / 1000
	case "us", "microsecond", "microseconds":
		return value / 1e6
	case "ns", "nanosecond", "nanoseconds":
		return value / 1e9
	default:
		return value
	}
}

func isLLMDurationMetric(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "gen_ai.client.operation.duration", "gen_ai.operation.duration", "llm.operation.duration", "claude_code.operation.duration", "codex.operation.duration", "openclaw.run.duration_ms":
		return true
	default:
		return strings.Contains(name, "operation.duration") && (strings.Contains(name, "gen_ai") || strings.Contains(name, "llm") || strings.Contains(name, "codex") || strings.Contains(name, "claude") || strings.Contains(name, "openclaw"))
	}
}

func spanLooksLikeLLMOperation(name string, attrs map[string]interface{}) bool {
	if otlpString(attrs, "gen_ai.operation.name") != "" ||
		otlpString(attrs, "gen_ai.request.model") != "" ||
		otlpString(attrs, "gen_ai.response.model") != "" ||
		otlpString(attrs, "model") != "" {
		return true
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "gen_ai") ||
		strings.Contains(name, "llm") ||
		strings.Contains(name, "chat") ||
		strings.Contains(name, "response") ||
		strings.Contains(name, "codex.run")
}

func otelDurationFromAttrs(attrs, resourceAttrs map[string]interface{}, source string, seconds float64, fallbackOperation string) otelLLMDuration {
	serviceName := otlpString(resourceAttrs, "service.name")
	agentName := source
	if agentName == "" || agentName == "unknown" {
		agentName = firstNonEmpty(otlpString(attrs, "gen_ai.agent.name"), serviceName, "unknown")
	}
	return otelLLMDuration{
		operationName: firstNonEmpty(
			otlpString(attrs, "openclaw.operation"),
			otlpString(attrs, "gen_ai.operation.name"),
			fallbackOperation,
			"chat",
		),
		providerName: firstNonEmpty(
			otlpString(attrs, "openclaw.provider"),
			otlpString(attrs, "gen_ai.provider.name"),
			source,
			serviceName,
			"unknown",
		),
		model: firstNonEmpty(
			otlpString(attrs, "openclaw.model"),
			otlpString(attrs, "gen_ai.response.model"),
			otlpString(attrs, "gen_ai.request.model"),
			otlpString(attrs, "model"),
			"unknown",
		),
		agentName:       agentName,
		durationSeconds: seconds,
	}
}

func normalizeOTLPTokenType(tokenType string) string {
	switch strings.TrimSpace(tokenType) {
	case "input", "output", "cacheRead", "cacheCreation", "cache_read", "cache_write", "prompt", "total":
		return strings.TrimSpace(tokenType)
	default:
		return ""
	}
}

func extractOTLPMetricDashboardValues(body []byte, source string) []otelDashboardMetric {
	var envelope struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []struct {
					Name      string              `json:"name"`
					Unit      string              `json:"unit"`
					Sum       otlpMetricPoints    `json:"sum"`
					Gauge     otlpMetricPoints    `json:"gauge"`
					Histogram otlpHistogramPoints `json:"histogram"`
				} `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	var out []otelDashboardMetric
	for _, resource := range envelope.ResourceMetrics {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		for _, scope := range resource.ScopeMetrics {
			for _, metric := range scope.Metrics {
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(metric.Name)), "openclaw.") {
					continue
				}
				temporality := firstNonEmpty(metric.Sum.AggregationTemporality, "unknown")
				for _, point := range metric.Sum.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					if dashboardMetric, ok := openclawDashboardMetricFromAttrs(metric.Name, metric.Unit, otlpDataPointFloat(point.AsInt, point.AsDouble), attrs, resourceAttrs, source, temporality); ok {
						out = append(out, dashboardMetric)
					}
				}
				for _, point := range metric.Gauge.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					if dashboardMetric, ok := openclawDashboardMetricFromAttrs(metric.Name, metric.Unit, otlpDataPointFloat(point.AsInt, point.AsDouble), attrs, resourceAttrs, source, "gauge"); ok {
						out = append(out, dashboardMetric)
					}
				}
				for _, point := range metric.Histogram.DataPoints {
					count := parseOTLPNumber(point.Count)
					sum := parseOTLPNumberFloat(point.Sum)
					if count <= 0 || sum <= 0 {
						continue
					}
					attrs := otlpAttributesToMap(point.Attributes)
					if dashboardMetric, ok := openclawDashboardMetricFromAttrs(metric.Name, metric.Unit, sum/float64(count), attrs, resourceAttrs, source, "histogram_avg"); ok {
						out = append(out, dashboardMetric)
					}
				}
			}
		}
	}
	return out
}

func openclawDashboardMetricFromAttrs(name, unit string, value float64, attrs, resourceAttrs map[string]interface{}, source, temporality string) (otelDashboardMetric, bool) {
	if value <= 0 {
		return otelDashboardMetric{}, false
	}
	tokenType := normalizeOTLPTokenType(otlpString(attrs, "openclaw.token"))
	metricName := strings.TrimSpace(name)
	if metricName == "openclaw.tokens" {
		if tokenType == "" {
			return otelDashboardMetric{}, false
		}
		if tokenType != "total" {
			metricName = "openclaw.tokens." + tokenType
		}
	}
	serviceName := otlpString(resourceAttrs, "service.name")
	return otelDashboardMetric{
		metricName: metricName,
		value:      value,
		unit:       openclawDashboardMetricUnit(metricName, unit),
		provider: firstNonEmpty(
			otlpString(attrs, "openclaw.provider"),
			otlpString(attrs, "gen_ai.provider.name"),
			source,
			serviceName,
			"unknown",
		),
		model: firstNonEmpty(
			otlpString(attrs, "openclaw.model"),
			otlpString(attrs, "gen_ai.response.model"),
			otlpString(attrs, "gen_ai.request.model"),
			otlpString(attrs, "model"),
			"unknown",
		),
		operation:   openclawMetricOperationName(name, attrs),
		tokenType:   tokenType,
		channel:     firstNonEmpty(otlpString(attrs, "openclaw.channel"), "unknown"),
		component:   firstNonEmpty(otlpString(attrs, "openclaw.lane"), otlpString(attrs, "openclaw.source"), otlpString(attrs, "openclaw.webhook"), otlpString(attrs, "openclaw.state"), source, "unknown"),
		temporality: temporality,
	}, true
}

func openclawDashboardMetricUnit(metricName, unit string) string {
	defaultUnit := openclawMetricDefaultUnit(metricName)
	if strings.TrimSpace(unit) == "" || strings.TrimSpace(unit) == "1" {
		return defaultUnit
	}
	return strings.TrimSpace(unit)
}

func openclawMetricDefaultUnit(metricName string) string {
	switch metricName {
	case "openclaw.tokens":
		return "tokens"
	case "openclaw.cost.usd":
		return "usd"
	}
	if strings.HasPrefix(metricName, "openclaw.tokens.") {
		return "tokens"
	}
	if strings.HasSuffix(metricName, "_ms") || strings.HasSuffix(metricName, ".duration_ms") {
		return "ms"
	}
	return "1"
}

func openclawMetricOperationName(metricName string, attrs map[string]interface{}) string {
	if op := firstNonEmpty(otlpString(attrs, "openclaw.operation"), otlpString(attrs, "gen_ai.operation.name")); op != "" {
		return op
	}
	switch strings.TrimSpace(metricName) {
	case "openclaw.tokens", "openclaw.cost.usd", "openclaw.run.duration_ms", "openclaw.context.tokens":
		return "chat"
	case "openclaw.queue.depth", "openclaw.queue.wait_ms", "openclaw.queue.lane.enqueue", "openclaw.queue.lane.dequeue":
		return "queue"
	case "openclaw.message.queued", "openclaw.message.processed", "openclaw.message.duration_ms":
		return "message"
	case "openclaw.webhook.received", "openclaw.webhook.error", "openclaw.webhook.duration_ms":
		return "webhook"
	case "openclaw.session.state", "openclaw.session.stuck", "openclaw.session.stuck_age_ms":
		return "session"
	case "openclaw.run.attempt":
		return "run"
	default:
		return "openclaw"
	}
}

func (a *APIServer) persistOTLPUsageMetricAuditEvents(source, sessionID string, usages []otelTokenUsage, durations []otelLLMDuration) {
	for _, usage := range usages {
		if usage.tokens <= 0 {
			continue
		}
		metric := map[string]any{
			"metric_name":    "openclaw.tokens",
			"metric_value":   usage.tokens,
			"unit":           "tokens",
			"provider":       otelAuditLabel(usage.providerName, source),
			"model":          otelAuditLabel(usage.model, "unknown"),
			"operation":      otelAuditLabel(usage.operationName, "chat"),
			"token_type":     otelAuditLabel(usage.tokenType, "unknown"),
			"connector":      otelAuditLabel(source, "unknown"),
			"source_signal":  "otlp",
			"dashboard_hint": "model_usage",
		}
		details := fmt.Sprintf(
			"metric_name=openclaw.tokens metric_value=%d unit=tokens provider=%s model=%s operation=%s token_type=%s connector=%s",
			usage.tokens,
			metric["provider"],
			metric["model"],
			metric["operation"],
			metric["token_type"],
			metric["connector"],
		)
		ev := audit.Event{
			Timestamp:  time.Now().UTC(),
			Action:     string(audit.ActionOTelIngestMetrics),
			Target:     "otlp:metrics:usage",
			Actor:      source,
			Details:    details,
			Severity:   "INFO",
			AgentName:  firstNonEmpty(usage.agentName, source),
			SessionID:  sessionID,
			Structured: metric,
		}
		if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
			fmt.Fprintf(otelIngestLogSink(), "[otel-ingest] usage metric persist failed (source=%s metric=openclaw.tokens): %v\n", source, err)
		}
	}

	for _, duration := range durations {
		if duration.durationSeconds <= 0 {
			continue
		}
		durationMS := duration.durationSeconds * 1000
		metric := map[string]any{
			"metric_name":    "openclaw.run.duration_ms",
			"metric_value":   durationMS,
			"unit":           "ms",
			"provider":       otelAuditLabel(duration.providerName, source),
			"model":          otelAuditLabel(duration.model, "unknown"),
			"operation":      otelAuditLabel(duration.operationName, "chat"),
			"connector":      otelAuditLabel(source, "unknown"),
			"source_signal":  "otlp",
			"dashboard_hint": "model_usage",
		}
		details := fmt.Sprintf(
			"metric_name=openclaw.run.duration_ms metric_value=%.3f unit=ms provider=%s model=%s operation=%s connector=%s",
			durationMS,
			metric["provider"],
			metric["model"],
			metric["operation"],
			metric["connector"],
		)
		ev := audit.Event{
			Timestamp:  time.Now().UTC(),
			Action:     string(audit.ActionOTelIngestMetrics),
			Target:     "otlp:metrics:duration",
			Actor:      source,
			Details:    details,
			Severity:   "INFO",
			AgentName:  firstNonEmpty(duration.agentName, source),
			SessionID:  sessionID,
			Structured: metric,
		}
		if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
			fmt.Fprintf(otelIngestLogSink(), "[otel-ingest] usage metric persist failed (source=%s metric=openclaw.run.duration_ms): %v\n", source, err)
		}
	}
}

func (a *APIServer) persistOTLPDashboardMetricAuditEvents(source, sessionID string, metrics []otelDashboardMetric) {
	persistDashboardMetricAuditEvents(a.logger, a.store, source, sessionID, "otlp:metrics:openclaw", metrics)
}

func persistDashboardMetricAuditEvents(logger *audit.Logger, store *audit.Store, source, sessionID, target string, metrics []otelDashboardMetric) {
	for _, m := range metrics {
		if m.metricName == "" || m.value <= 0 {
			continue
		}
		structured := map[string]any{
			"metric_name":    otelAuditLabel(m.metricName, "unknown"),
			"metric_value":   m.value,
			"unit":           otelAuditLabel(m.unit, "1"),
			"provider":       otelAuditLabel(m.provider, source),
			"model":          otelAuditLabel(m.model, "unknown"),
			"operation":      otelAuditLabel(m.operation, "openclaw"),
			"connector":      otelAuditLabel(source, "unknown"),
			"component":      otelAuditLabel(m.component, source),
			"channel":        otelAuditLabel(m.channel, "unknown"),
			"temporality":    otelAuditLabel(m.temporality, "unknown"),
			"source_signal":  otelAuditLabel(firstNonEmpty(m.sourceSignal, "otlp"), "otlp"),
			"dashboard_hint": "openclaw_metric",
		}
		if m.tokenType != "" {
			structured["token_type"] = otelAuditLabel(m.tokenType, "unknown")
		}
		if m.gatewayHost != "" {
			structured["gateway_host"] = otelAuditLabel(m.gatewayHost, "unknown")
		}
		if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
			structured["collector_host"] = otelAuditLabel(host, "unknown")
		}
		details := fmt.Sprintf(
			"metric_name=%s metric_value=%.6f unit=%s provider=%s model=%s operation=%s component=%s channel=%s temporality=%s connector=%s",
			structured["metric_name"],
			m.value,
			structured["unit"],
			structured["provider"],
			structured["model"],
			structured["operation"],
			structured["component"],
			structured["channel"],
			structured["temporality"],
			structured["connector"],
		)
		if m.tokenType != "" {
			details += fmt.Sprintf(" token_type=%s", structured["token_type"])
		}
		ev := audit.Event{
			Timestamp:  time.Now().UTC(),
			Action:     string(audit.ActionOTelIngestMetrics),
			Target:     target,
			Actor:      source,
			Details:    details,
			Severity:   "INFO",
			AgentName:  source,
			SessionID:  sessionID,
			Structured: structured,
		}
		if err := persistAuditEvent(logger, store, ev); err != nil {
			fmt.Fprintf(otelIngestLogSink(), "[otel-ingest] dashboard metric persist failed (source=%s metric=%s): %v\n", source, m.metricName, err)
		}
	}
}

func otelAuditLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = strings.TrimSpace(fallback)
	}
	if value == "" {
		value = "unknown"
	}
	var b strings.Builder
	b.Grow(len(value))
	lastDash := false
	for i := 0; i < len(value) && b.Len() < 128; i++ {
		c := value[i]
		allowed := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '.' || c == ':' || c == '/'
		if allowed {
			b.WriteByte(c)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// otelIngestActionForSignal maps the inbound signal to the typed
// audit action constant. Keeping the mapping tight here (rather
// than fmt.Sprintf into the action column) makes the static check
// in scripts/check_audit_actions.py fail loud when a new signal
// gets added without a matching constant.
func otelIngestActionForSignal(signal otelIngestSignal) string {
	switch signal {
	case otelSignalLogs:
		return string(audit.ActionOTelIngestLogs)
	case otelSignalMetrics:
		return string(audit.ActionOTelIngestMetrics)
	case otelSignalTraces:
		return string(audit.ActionOTelIngestTraces)
	default:
		// Should be unreachable — handleOTLPSignal only ever calls
		// us with one of the three constants above. Fall back to
		// the malformed marker so an out-of-band caller can't
		// smuggle a new action key into the audit DB.
		return string(audit.ActionOTelIngestMalformed)
	}
}

// isOTLPJSONContentType returns true if the request Content-Type
// indicates OTLP-JSON. Accepts application/json with optional
// charset / "; encoding=otlp-json" parameters.
func isOTLPJSONContentType(ct string) bool {
	return normalizedContentType(ct) == "application/json"
}

func isOTLPProtobufContentType(ct string) bool {
	return normalizedContentType(ct) == "application/x-protobuf"
}

func isOTLPContentType(ct string) bool {
	ct = normalizedContentType(ct)
	return ct == "application/json" || ct == "application/x-protobuf"
}

func normalizedContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return ""
	}
	// Strip parameters (anything after ;).
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

func parseOTLPPathToken(path string) (token string, source string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 5 || parts[0] != "otlp" || parts[3] != "v1" {
		return "", "", false
	}
	switch parts[4] {
	case "logs", "metrics", "traces":
	default:
		return "", "", false
	}
	source = normalizeConnectorTelemetrySource(parts[1])
	token = strings.TrimSpace(parts[2])
	if decoded, err := url.PathUnescape(token); err == nil {
		token = decoded
	}
	if source == "" || token == "" {
		return "", "", false
	}
	return token, source, true
}

func isOTLPEndpointPath(path string) bool {
	switch path {
	case "/v1/logs", "/v1/metrics", "/v1/traces":
		return true
	default:
		_, _, ok := parseOTLPPathToken(path)
		return ok
	}
}

// sanitizeRouteForTelemetry returns a fixed-cardinality route label safe for
// OTel metrics / span attributes. The path-token OTLP endpoint embeds the
// gateway bearer token as a URL segment, so we MUST never let that segment
// reach an exporter (it would leak the master credential to whatever
// observability backend is configured). For path-token URLs we collapse the
// token segment to "_token_"; everything else is passed through unchanged.
//
// SECURITY: do not bypass this for any route that participates in the OTel
// pipeline. See parseOTLPPathToken for the URL shape and tokenAuth for the
// auth contract that justifies allowing the token in the URL at all.
func sanitizeRouteForTelemetry(path string) string {
	_, source, ok := parseOTLPPathToken(path)
	if !ok {
		return path
	}
	// Recover the trailing signal segment (logs|metrics|traces). parseOTLPPathToken
	// has already validated the shape so the split is safe.
	parts := strings.Split(strings.Trim(path, "/"), "/")
	signal := parts[len(parts)-1]
	return "/otlp/" + source + "/_token_/v1/" + signal
}

// writeOTLPSuccess writes the canonical empty-success OTLP-HTTP
// response body. We use {} (the JSON form of ExportPartialSuccess
// with no rejected_log_records) so OTel SDKs treat the request as
// fully accepted and do NOT retry.
func writeOTLPSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// summarizeOTLPPayload extracts a one-line summary from an OTLP-JSON
// body for audit logging. Different signal types have different
// envelope shapes:
//
//   - logs:    { "resourceLogs":    [{ scopeLogs: [{ logRecords: [...] }] }] }
//   - metrics: { "resourceMetrics": [{ scopeMetrics: [{ metrics: [...] }] }] }
//   - traces:  { "resourceSpans":   [{ scopeSpans: [{ spans: [...] }] }] }
//
// We count the leaf records (logRecords / metrics / spans) and the
// number of distinct service.name resource attributes. That's enough
// for the audit row to answer "how much telemetry from which service
// in which batch" without forcing SQLite to grow per-record.
func summarizeOTLPPayload(body []byte, signal otelIngestSignal) (string, otelIngestStats, error) {
	if len(body) == 0 {
		return "", otelIngestStats{}, errors.New("empty body")
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", otelIngestStats{}, fmt.Errorf("unmarshal envelope: %w", err)
	}

	var resourceKey, scopeKey, leafKey string
	switch signal {
	case otelSignalLogs:
		resourceKey, scopeKey, leafKey = "resourceLogs", "scopeLogs", "logRecords"
	case otelSignalMetrics:
		resourceKey, scopeKey, leafKey = "resourceMetrics", "scopeMetrics", "metrics"
	case otelSignalTraces:
		resourceKey, scopeKey, leafKey = "resourceSpans", "scopeSpans", "spans"
	default:
		return "", otelIngestStats{}, fmt.Errorf("unknown signal: %s", signal)
	}

	resourceRaw, ok := envelope[resourceKey]
	if !ok {
		return fmt.Sprintf("size=%d bytes, no %s entries", len(body), resourceKey), otelIngestStats{}, nil
	}

	var resources []map[string]json.RawMessage
	if err := json.Unmarshal(resourceRaw, &resources); err != nil {
		return "", otelIngestStats{}, fmt.Errorf("unmarshal %s: %w", resourceKey, err)
	}

	var totalLeaf int
	services := make(map[string]int)

	for _, res := range resources {
		// Pull the resource.attributes service.name for grouping.
		if attrsRaw, ok := res["resource"]; ok {
			if name := extractServiceName(attrsRaw); name != "" {
				services[name]++
			}
		}
		scopesRaw, ok := res[scopeKey]
		if !ok {
			continue
		}
		var scopes []map[string]json.RawMessage
		if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
			continue
		}
		for _, sc := range scopes {
			leafRaw, ok := sc[leafKey]
			if !ok {
				continue
			}
			var leaves []json.RawMessage
			if err := json.Unmarshal(leafRaw, &leaves); err != nil {
				continue
			}
			totalLeaf += len(leaves)
		}
	}

	parts := []string{
		fmt.Sprintf("signal=%s", signal),
		fmt.Sprintf("size=%d bytes", len(body)),
		fmt.Sprintf("resources=%d", len(resources)),
		fmt.Sprintf("%s=%d", leafKey, totalLeaf),
	}
	if len(services) > 0 {
		// Cap the number of services we surface so a noisy batch
		// doesn't blow up the Details column. The OTLP spec allows
		// arbitrary cardinality.
		shown := 0
		var svcParts []string
		for name, count := range services {
			if shown >= otelIngestMaxBatchSummary {
				svcParts = append(svcParts, fmt.Sprintf("...+%d more", len(services)-shown))
				break
			}
			svcParts = append(svcParts, fmt.Sprintf("%s=%d", name, count))
			shown++
		}
		parts = append(parts, fmt.Sprintf("services=[%s]", strings.Join(svcParts, ",")))
	}
	stats := otelIngestStats{
		Records:   int64(totalLeaf),
		Resources: int64(len(resources)),
	}
	return strings.Join(parts, " "), stats, nil
}

// extractServiceName pulls service.name out of an OTLP resource block.
// The OTLP-JSON shape is:
//
//	{ "attributes": [{ "key": "service.name", "value": { "stringValue": "codex" } }] }
//
// Returns empty if the attribute is absent or malformed; callers
// treat that as "unknown service" and don't fail the whole batch.
func extractServiceName(resourceRaw json.RawMessage) string {
	var resource struct {
		Attributes []struct {
			Key   string `json:"key"`
			Value struct {
				StringValue string `json:"stringValue"`
			} `json:"value"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(resourceRaw, &resource); err != nil {
		return ""
	}
	for _, a := range resource.Attributes {
		if a.Key == "service.name" {
			return a.Value.StringValue
		}
	}
	return ""
}

// codexNotifyPayload mirrors the documented codex notify JSON shape
// (https://developers.openai.com/codex/config-advanced). We capture
// the fields the SIEM rollup and session correlation need (type,
// thread-id, turn-id, model, status)
// and intentionally do not persist unknown fields verbatim. The schema
// is deliberately permissive: codex bumps the notify shape across
// releases and we never want schema drift to make the gateway 400 a
// real event.
type codexNotifyPayload struct {
	Type     string `json:"type"`
	ThreadID string `json:"thread-id,omitempty"`
	TurnID   string `json:"turn-id,omitempty"`
	Model    string `json:"model,omitempty"`
	Status   string `json:"status,omitempty"`
}

// handleCodexNotify accepts agent-turn-complete events from the
// notify-bridge.sh shim that the codex connector installs in
// Setup(). The bridge POSTs the raw JSON arg codex passes it.
//
// We:
//  1. Validate Content-Type (application/json) — the bridge sets
//     this explicitly so a non-JSON body is a real error.
//  2. Parse a permissive subset (codexNotifyPayload). Unknown fields
//     are summarized by length + hash rather than stored raw.
//  3. Persist as an INFO audit event with action="codex.notify.<type>"
//     and Actor="codex" so the SIEM rollup can group by turn.
//
// Failures are logged but always return 200 so the bridge doesn't
// retry — codex's turn-complete is a fire-and-forget telemetry
// signal, not a control plane action.
func (a *APIServer) handleCodexNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isOTLPJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w,
			"unsupported content-type (codex notify accepts application/json only)",
			http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var p codexNotifyPayload
	parseErr := json.Unmarshal(body, &p)

	action := string(audit.ActionCodexNotify)
	severity := "INFO"
	result := "ok"
	var kind string
	if parseErr != nil {
		// Persist a malformed marker so operators can investigate
		// codex schema drift without losing the event.
		action = string(audit.ActionCodexNotifyMalformed)
		severity = "WARN"
		result = "malformed"
		kind = "malformed"
	} else if p.Type != "" {
		kind = sanitizeNotifyType(p.Type)
		action = "codex.notify." + kind
	} else {
		kind = "" // body parsed but no `type` field — keep audit Action == "codex.notify"
	}

	details := codexNotifyAuditDetails(p, body, kind, result, parseErr)
	sessionID := codexNotifySessionID(p)

	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "codex.session",
		Actor:     "codex",
		Details:   details,
		Severity:  severity,
		AgentName: "codex",
		SessionID: sessionID,
	}
	if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
		fmt.Fprintf(otelIngestLogSink(), "[codex-notify] persist failed: %v\n", err)
	}

	// Surface the same event as a Prometheus counter and an OTel log
	// record so the local-stack dashboards see codex turn-completes
	// without configuring an audit OTLP sink. Cardinality is bounded
	// by sanitizeNotifyType (max 64 chars, [a-z0-9._-]) for both kind
	// and status — the wire format calls status a free-form string
	// but the only legitimate values are short, ASCII tokens; without
	// sanitization a hostile / verbose client could blow up the
	// `codex_notify_status` series.
	statusLabel := sanitizeNotifyType(p.Status)
	ctx := ContextWithSessionID(r.Context(), sessionID)
	enrichHTTPSpanFromContext(ctx)
	enrichCodexNotifySpan(ctx, p, kind, result)
	a.otel.RecordCodexNotify(ctx, kind, statusLabel, result)
	a.otel.EmitCodexNotifyLog(ctx, kind, statusLabel, result, p.TurnID, p.Model)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

func codexNotifySessionID(p codexNotifyPayload) string {
	if p.ThreadID != "" {
		return p.ThreadID
	}
	return p.TurnID
}

func enrichCodexNotifySpan(ctx context.Context, p codexNotifyPayload, kind, result string) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	sessionID := codexNotifySessionID(p)
	if sessionID != "" {
		span.SetAttributes(attribute.String("gen_ai.conversation.id", sessionID))
	}
	span.SetAttributes(
		attribute.String("defenseclaw.connector.source", "codex"),
		attribute.String("defenseclaw.connector.signal", "notify"),
	)
	span.SetAttributes(attribute.String("gen_ai.agent.name", "codex"))
	if p.TurnID != "" {
		span.SetAttributes(attribute.String("defenseclaw.codex.notify.turn_id", p.TurnID))
	}
	if kind != "" {
		span.SetAttributes(attribute.String("defenseclaw.codex.notify.type", kind))
	}
	if result != "" {
		span.SetAttributes(
			attribute.String("defenseclaw.connector.result", result),
			attribute.String("defenseclaw.codex.notify.result", result),
		)
	}
	if p.Status != "" {
		span.SetAttributes(attribute.String("defenseclaw.codex.notify.status", p.Status))
	}
	if p.Model != "" {
		span.SetAttributes(attribute.String("gen_ai.response.model", p.Model))
	}
}

func codexNotifyAuditDetails(p codexNotifyPayload, body []byte, kind, result string, parseErr error) string {
	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])
	parts := []string{
		"type=" + kind,
		"result=" + result,
		fmt.Sprintf("body_len=%d", len(body)),
		"body_sha256_prefix=" + sumHex[:16],
	}
	if p.ThreadID != "" {
		parts = append(parts, "thread_id="+redaction.ForSinkEntity(p.ThreadID))
	}
	if p.TurnID != "" {
		parts = append(parts, "turn_id="+redaction.ForSinkEntity(p.TurnID))
	}
	if p.Model != "" {
		parts = append(parts, "model="+redaction.ForSinkEntity(p.Model))
	}
	if p.Status != "" {
		parts = append(parts, "status="+redaction.ForSinkEntity(p.Status))
	}
	if parseErr != nil {
		parts = append(parts, "parse_error="+redaction.ForSinkReason(parseErr.Error()))
	}
	return appendRawTelemetryDetails(strings.Join(parts, " "), "raw_body", body)
}

// sanitizeNotifyType strips characters unsafe for an audit Action
// column. The codex notify "type" field today is a constrained
// vocabulary (agent-turn-complete, etc.) but we sanitize defensively
// so a future malformed/hostile payload can't smuggle action.* keys.
// Keeps lowercase letters, digits, dashes and underscores.
func sanitizeNotifyType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < 64; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// otelIngestLogSink is a thin wrapper so tests can swap stderr.
// We intentionally don't expose a setter today — the indirection
// is enough to let a future test use io.Discard via build tags.
func otelIngestLogSink() io.Writer {
	// stderr is the gateway's standard log channel; persistAuditEvent
	// failures are rare and the operator already monitors stderr
	// for sidecar startup and policy reloads.
	return os.Stderr
}
