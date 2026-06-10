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
	// ("Scoped OTLP path-token source can be
	// spoofed with x-defenseclaw-source"): the path-token route
	// authenticates a *specific* connector source via the URL, so
	// the authenticated source is the one parsed from the path.
	// The previous implementation only filled the header when it
	// was empty, which let a loopback caller present the geminicli
	// path token while setting `x-defenseclaw-source: codex` and
	// have telemetry attributed to codex. Always overwrite so the
	// audited Actor / AgentName / metrics labels match the
	// authenticated path source.
	r.Header.Set(otelSourceHeader, source)
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
	if id := agentIdentityForOTLPSource(source); id != (AgentIdentity{}) {
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
			Connector: source,
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
		// follow-up: when session_id arrives in the OTLP body
		// (after auth has already happened), the request envelope was
		// promoted with no session_id. Re-promote now so persisted
		// events carry both session_id AND a stable agent_instance_id
		// — otherwise downstream joins on (session_id, instance_id)
		// fail because instance_id is empty.
		ctx = PromoteSessionIfAuthenticated(ctx)
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
			Connector: source,
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
		Connector: source,
	}
	if signal == otelSignalLogs {
		if events := otlpLogRecordsForSplunkHEC(body, source, ev.Timestamp); len(events) > 0 {
			ev.Structured = map[string]any{
				"_splunk_hec_events": events,
			}
		}
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
	for _, usage := range extractOTLPTokenUsage(summaryBody, signal, source) {
		a.otel.RecordLLMTokenUsage(ctx, usage.operationName, usage.providerName, usage.model, usage.agentName, SharedAgentRegistry().AgentID(), SessionIDFromContext(ctx), usage.tokenType, usage.tokens)
	}
	for _, duration := range extractOTLPOperationDurations(summaryBody, signal, source) {
		a.otel.RecordLLMDuration(ctx, duration.operationName, duration.providerName, duration.model, duration.agentName, SharedAgentRegistry().AgentID(), duration.durationSeconds)
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

func otlpLogRecordsForSplunkHEC(body []byte, source string, receivedAt time.Time) []map[string]any {
	var envelope struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					TimeUnixNano         json.RawMessage `json:"timeUnixNano"`
					ObservedTimeUnixNano json.RawMessage `json:"observedTimeUnixNano"`
					SeverityNumber       int             `json:"severityNumber"`
					SeverityText         string          `json:"severityText"`
					Body                 json.RawMessage `json:"body"`
					Attributes           []otlpAttribute `json:"attributes"`
					TraceID              string          `json:"traceId"`
					SpanID               string          `json:"spanId"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	events := []map[string]any{}
	for _, resourceLog := range envelope.ResourceLogs {
		resourceAttrs := otlpAttributesToMap(resourceLog.Resource.Attributes)
		for _, scopeLog := range resourceLog.ScopeLogs {
			for _, rec := range scopeLog.LogRecords {
				recordAttrs := otlpAttributesToMap(rec.Attributes)
				mergedAttrs := make(map[string]interface{}, len(resourceAttrs)+len(recordAttrs))
				for k, v := range resourceAttrs {
					mergedAttrs[k] = v
				}
				for k, v := range recordAttrs {
					mergedAttrs[k] = v
				}
				eventTime := otlpLogRecordTime(rec.TimeUnixNano, rec.ObservedTimeUnixNano, receivedAt)
				event := map[string]any{
					"signal_family":      "log",
					"timestamp":          eventTime.UTC().Format(time.RFC3339Nano),
					"observed_timestamp": otlpNanosISO(rec.ObservedTimeUnixNano),
					"severity":           firstNonEmpty(rec.SeverityText, "INFO"),
					"severity_text":      rec.SeverityText,
					"severity_number":    rec.SeverityNumber,
					"body":               decodeOTLPAnyValue(rec.Body),
					"trace_id":           rec.TraceID,
					"span_id":            rec.SpanID,
					"resource":           resourceAttrs,
					"attributes":         recordAttrs,
					"source":             "otel",
					"source_system":      "defenseclaw",
					"event_name":         otlpString(mergedAttrs, "event.name"),
					"action":             firstNonEmpty(otlpString(mergedAttrs, "action"), otlpString(mergedAttrs, "event.name")),
					"run_id":             otlpString(mergedAttrs, "run_id"),
					"session_id":         otlpSessionID(mergedAttrs),
					"request_id":         otlpString(mergedAttrs, "request_id"),
					"agent_name":         firstNonEmpty(otlpString(mergedAttrs, "gen_ai.agent.name"), source),
					"agent_type":         otlpString(mergedAttrs, "gen_ai.agent.type"),
					"tool_name":          firstNonEmpty(otlpString(mergedAttrs, "tool_name"), otlpString(mergedAttrs, "gen_ai.tool.name")),
					"destination_app":    firstNonEmpty(otlpString(mergedAttrs, "destination_app"), otlpString(mergedAttrs, "defenseclaw.destination_app")),
					"provider_name":      firstNonEmpty(otlpString(mergedAttrs, "gen_ai.provider.name"), source),
					"request_model":      firstNonEmpty(otlpString(mergedAttrs, "gen_ai.request.model"), otlpString(mergedAttrs, "model")),
					"response_model":     otlpString(mergedAttrs, "gen_ai.response.model"),
				}
				events = append(events, map[string]any{
					"time":       float64(eventTime.Unix()) + float64(eventTime.Nanosecond())/1e9,
					"host":       firstNonEmpty(otlpString(resourceAttrs, "host.name"), "defenseclaw-local"),
					"source":     "otel",
					"sourcetype": "otel:log",
					"event":      event,
				})
			}
		}
	}
	return events
}

func otlpLogRecordTime(timeRaw, observedRaw json.RawMessage, fallback time.Time) time.Time {
	if t, ok := otlpNanosTime(timeRaw); ok && !t.IsZero() {
		return t
	}
	if t, ok := otlpNanosTime(observedRaw); ok && !t.IsZero() {
		return t
	}
	return fallback
}

func otlpNanosISO(raw json.RawMessage) string {
	t, ok := otlpNanosTime(raw)
	if !ok || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func otlpNanosTime(raw json.RawMessage) (time.Time, bool) {
	nanos := parseOTLPNumber(raw)
	if nanos <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, nanos).UTC(), true
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
	case "openclaw", "zeptoclaw", "claudecode", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot", "scout", "openhands", "antigravity":
		return strings.ToLower(strings.TrimSpace(source))
	case "claude-code", "claude_code":
		return "claudecode"
	case "gemini-cli", "gemini_cli", "gemini":
		return "geminicli"
	case "agy":
		return "antigravity"
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
				if metric.Name != "claude_code.token.usage" {
					continue
				}
				points := metric.Sum.DataPoints
				if len(points) == 0 {
					points = metric.Gauge.DataPoints
				}
				for _, point := range points {
					attrs := otlpAttributesToMap(point.Attributes)
					tokenType := normalizeClaudeCodeTokenType(otlpString(attrs, "type"))
					tokens := otlpDataPointInt(point.AsInt, point.AsDouble)
					if tokenType == "" || tokens <= 0 {
						continue
					}
					agentName := source
					if agentName == "" || agentName == "unknown" {
						agentName = firstNonEmpty(serviceName, "claudecode")
					}
					out = append(out, otelTokenUsage{
						operationName: "chat",
						providerName:  firstNonEmpty(source, serviceName, "claudecode"),
						model:         firstNonEmpty(otlpString(attrs, "model"), "unknown"),
						agentName:     agentName,
						tokenType:     tokenType,
						tokens:        tokens,
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
					out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, normalizeDurationByUnit(sum/float64(count), metric.Unit), "chat"))
				}
				for _, point := range metric.Gauge.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					seconds := otlpMetricPointDurationSeconds(point, metric.Unit)
					if seconds > 0 {
						out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, seconds, "chat"))
					}
				}
				for _, point := range metric.Sum.DataPoints {
					attrs := otlpAttributesToMap(point.Attributes)
					seconds := otlpMetricPointDurationSeconds(point, metric.Unit)
					if seconds > 0 {
						out = append(out, otelDurationFromAttrs(attrs, resourceAttrs, source, seconds, "chat"))
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
	DataPoints []otlpMetricDataPoint `json:"dataPoints"`
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
	return otlpAttributesToMapDepth(attrs, 0)
}

const maxOTLPAnyValueDepth = 16

func otlpAttributesToMapDepth(attrs []otlpAttribute, depth int) map[string]interface{} {
	out := make(map[string]interface{}, len(attrs))
	for _, attr := range attrs {
		if attr.Key == "" {
			continue
		}
		out[attr.Key] = decodeOTLPAnyValueDepth(attr.Value, depth+1)
	}
	return out
}

func decodeOTLPAnyValue(raw json.RawMessage) interface{} {
	return decodeOTLPAnyValueDepth(raw, 0)
}

func decodeOTLPAnyValueDepth(raw json.RawMessage, depth int) interface{} {
	if depth > maxOTLPAnyValueDepth {
		return nil
	}
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
		return otlpAttributesToMapDepth(v.KvListValue.Values, depth+1)
	case v.ArrayValue != nil:
		out := make([]interface{}, 0, len(v.ArrayValue.Values))
		for _, item := range v.ArrayValue.Values {
			out = append(out, decodeOTLPAnyValueDepth(item, depth+1))
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
	case "gen_ai.client.operation.duration", "gen_ai.operation.duration", "llm.operation.duration", "claude_code.operation.duration", "codex.operation.duration":
		return true
	default:
		return strings.Contains(name, "operation.duration") && (strings.Contains(name, "gen_ai") || strings.Contains(name, "llm") || strings.Contains(name, "codex") || strings.Contains(name, "claude"))
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
			otlpString(attrs, "gen_ai.operation.name"),
			fallbackOperation,
			"chat",
		),
		providerName: firstNonEmpty(otlpString(attrs, "gen_ai.provider.name"), source, serviceName, "unknown"),
		model: firstNonEmpty(
			otlpString(attrs, "gen_ai.response.model"),
			otlpString(attrs, "gen_ai.request.model"),
			otlpString(attrs, "model"),
			"unknown",
		),
		agentName:       agentName,
		durationSeconds: seconds,
	}
}

func normalizeClaudeCodeTokenType(tokenType string) string {
	switch strings.TrimSpace(tokenType) {
	case "input", "output", "cacheRead", "cacheCreation":
		return strings.TrimSpace(tokenType)
	default:
		return ""
	}
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

const codexNotifyTurnCompleteSource = "codex.notify.agent-turn-complete"

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
//  4. For agent-turn-complete, emit first-class llm_prompt /
//     llm_response events from the semantic notify fields.
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
	var payload map[string]any
	if parseErr == nil {
		payload = normalizeCodexNotifyPayloadAliases(&p, body)
	}

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
	ctx := ContextWithSessionID(r.Context(), sessionID)

	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "codex.session",
		Actor:     "codex",
		Details:   details,
		Severity:  severity,
		AgentName: "codex",
		SessionID: sessionID,
		Connector: "codex",
	}
	if err := persistAuditEventCtx(r.Context(), a.logger, a.store, ev); err != nil {
		fmt.Fprintf(otelIngestLogSink(), "[codex-notify] persist failed: %v\n", err)
	}
	if parseErr == nil && kind == "agent-turn-complete" {
		a.emitCodexNotifyTurnCompleteLLMEvents(ctx, r, p, payload)
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
	// by sanitizeNotifyType (max 64 chars, [a-z0-9._-]).
	enrichHTTPSpanFromContext(ctx)
	enrichCodexNotifySpan(ctx, p, kind, result)
	a.otel.RecordCodexNotify(ctx, kind, statusLabel, result)
	a.otel.EmitCodexNotifyLog(ctx, kind, statusLabel, result, p.TurnID, p.Model)

	// Fold the notify event into the unified hook collector as a
	// synthetic Stop event. The native codex CLI emits
	// "agent-turn-complete" notifications outside the PreToolUse /
	// PostToolUse stream, so without this fold the unified hook
	// collector would have no visibility into them — breaking the
	// "every connector emits the same hook metric set" invariant
	// that downstream dashboards (defenseclaw.connector.hook.*) rely
	// on for codex.
	//
	// The synthetic translation runs only when the parse succeeded
	// (parseErr == nil) — a malformed payload should not invent a
	// Stop event; the existing audit + metric path already captured
	// the malformed marker above.
	//
	// handleAgentHookSynthetic emits a separate audit row under
	// audit.ActionConnectorHookSynthetic so the canonical
	// `codex.notify.<sanitized-type>` row count (one per inbound
	// notify) is preserved — see the function godoc and
	// TestCodexNotify_PersistsDynamicSuffixAction.
	if parseErr == nil {
		synthetic := codexNotifyToAgentHookRequest(p, body)
		a.handleAgentHookSynthetic(ctx, "codex", synthetic, body)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// codexNotifyToAgentHookRequest translates a codexNotifyPayload into
// a generic agentHookRequest carrying a synthetic HookEventName=Stop.
// The translation preserves the codex notify fields in
// req.Payload so a downstream consumer (hook profile evaluator,
// audit envelope renderer) can still recover the type / status /
// model values that the codex schema provides.
//
// PR 7 cleanup deletes codexNotifyPayload entirely once every
// downstream that reads Type / Status / Model has switched to
// pulling them out of req.Payload directly via firstString.
func codexNotifyToAgentHookRequest(p codexNotifyPayload, raw []byte) agentHookRequest {
	payload := map[string]interface{}{
		"hook_event_name": "Stop",
		"session_id":      codexNotifySessionID(p),
		"turn_id":         p.TurnID,
		"model":           p.Model,
		"agent_id":        "codex",
		"agent_type":      "codex",
		"codex_notify": map[string]interface{}{
			"type":   p.Type,
			"status": p.Status,
		},
		"raw_notify_body_len": len(raw),
	}
	return agentHookRequest{
		ConnectorName: "codex",
		HookEventName: "Stop",
		SessionID:     codexNotifySessionID(p),
		TurnID:        p.TurnID,
		AgentID:       "codex",
		AgentName:     "codex",
		AgentType:     "codex",
		ToolName:      "codex-notify",
		Direction:     "tool_result",
		Payload:       payload,
	}
}

func codexNotifySessionID(p codexNotifyPayload) string {
	if p.ThreadID != "" {
		return p.ThreadID
	}
	return p.TurnID
}

func normalizeCodexNotifyPayloadAliases(p *codexNotifyPayload, body []byte) map[string]any {
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil
	}
	if p == nil {
		return payload
	}
	if p.ThreadID == "" {
		p.ThreadID = codexNotifyString(payload, "thread-id", "thread_id", "threadID")
	}
	if p.TurnID == "" {
		p.TurnID = codexNotifyString(payload, "turn-id", "turn_id", "turnID")
	}
	if p.Model == "" {
		p.Model = codexNotifyString(payload, "model", "request_model", "response_model")
	}
	if p.Status == "" {
		p.Status = codexNotifyString(payload, "status")
	}
	return payload
}

func (a *APIServer) emitCodexNotifyTurnCompleteLLMEvents(ctx context.Context, r *http.Request, p codexNotifyPayload, payload map[string]any) {
	if len(payload) == 0 {
		return
	}
	sessionID := codexNotifySessionID(p)
	turnID := firstNonEmpty(codexNotifyString(payload, "turn-id", "turn_id", "turnID"), p.TurnID)
	if sessionID == "" && turnID == "" {
		return
	}
	if sessionID == "" {
		sessionID = turnID
	}
	model := firstNonEmpty(codexNotifyString(payload, "model", "request_model", "response_model"), p.Model)
	provider := inferSystem("", model)
	if provider == "unknown" {
		provider = "codex"
	}
	userID, userName := userFromHTTPRequest(r, nil)
	promptID := firstNonEmpty(
		a.lastHookPromptIDForTurn("codex", sessionID, turnID),
		a.lastHookPromptID("codex", sessionID),
		promptIDForTurn("codex", sessionID, turnID),
	)
	meta := llmEventMeta{
		Source:    codexNotifyTurnCompleteSource,
		Provider:  provider,
		Model:     model,
		SessionID: sessionID,
		TurnID:    turnID,
		PromptID:  promptID,
		AgentName: "codex",
		AgentType: "codex",
		UserID:    userID,
		UserName:  userName,
	}

	if prompt := codexNotifyPrompt(payload); prompt != "" {
		emittedPromptID := emitLLMPromptEvent(ctx, meta, prompt, nil)
		if emittedPromptID != "" {
			meta.PromptID = emittedPromptID
			a.rememberHookPromptID("codex", sessionID, turnID, emittedPromptID)
		}
	}
	if response := codexNotifyResponse(payload); response != "" {
		meta.ResponseID = stableLLMEventID("response", "codex", sessionID, turnID)
		emitLLMResponseEvent(ctx, meta, response, "", codexNotifyFinishReasons(payload))
	}
}

func codexNotifyPrompt(payload map[string]any) string {
	messages := codexNotifyStringSlice(payload, "input-messages", "input_messages", "prompts")
	for i := len(messages) - 1; i >= 0; i-- {
		if message := strings.TrimSpace(messages[i]); message != "" {
			return message
		}
	}
	return codexNotifyString(payload, "last-user-message", "last_user_message", "prompt", "prompt_content")
}

func codexNotifyResponse(payload map[string]any) string {
	return codexNotifyString(payload, "last-assistant-message", "last_assistant_message", "response", "response_content")
}

func codexNotifyFinishReasons(payload map[string]any) []string {
	reasons := codexNotifyStringSlice(payload, "finish-reasons", "finish_reasons", "gen_ai.response.finish_reasons")
	if len(reasons) > 0 {
		return reasons
	}
	if reason := codexNotifyString(payload, "finish-reason", "finish_reason"); reason != "" {
		return []string{reason}
	}
	return nil
}

func codexNotifyString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := payload[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case map[string]any:
			if text := codexNotifyString(value, "content", "text", "message"); text != "" {
				return text
			}
		}
	}
	return ""
}

func codexNotifyStringSlice(payload map[string]any, keys ...string) []string {
	for _, key := range keys {
		switch value := payload[key].(type) {
		case []any:
			out := make([]string, 0, len(value))
			for _, item := range value {
				switch v := item.(type) {
				case string:
					if strings.TrimSpace(v) != "" {
						out = append(out, strings.TrimSpace(v))
					}
				case map[string]any:
					if text := codexNotifyString(v, "content", "text", "message"); text != "" {
						out = append(out, text)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		case []string:
			out := make([]string, 0, len(value))
			for _, item := range value {
				if strings.TrimSpace(item) != "" {
					out = append(out, strings.TrimSpace(item))
				}
			}
			if len(out) > 0 {
				return out
			}
		case string:
			if strings.TrimSpace(value) != "" {
				return []string{strings.TrimSpace(value)}
			}
		}
	}
	return nil
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
	// p.Status and p.Model come straight off the wire from the codex
	// CLI and a hostile / malformed payload can plant CRLF (log
	// injection into operator terminals via span exporters), ANSI
	// escapes (terminal hijack), or arbitrarily long strings (span
	// storage DoS). Sanitize before stamping them on the span.
	//
	// `defenseclaw.codex.notify.status` mirrors the metric label
	// produced upstream by sanitizeNotifyType, so the span attribute
	// uses the same projection and stays correlatable.
	//
	// `gen_ai.response.model` is treated as identifying free-form text
	// (capped + control-char-stripped) instead of being collapsed to
	// the bounded NormalizeModelLabel family; spans are per-request so
	// preserving the full model name has no TSDB-cardinality cost.
	if statusAttr := sanitizeNotifyType(p.Status); p.Status != "" && statusAttr != "" {
		span.SetAttributes(attribute.String("defenseclaw.codex.notify.status", statusAttr))
	}
	if modelAttr := sanitizeCodexNotifySpanString(p.Model, 128); modelAttr != "" {
		span.SetAttributes(attribute.String("gen_ai.response.model", modelAttr))
	}
}

// sanitizeCodexNotifySpanString returns value with control / CR / LF /
// ANSI runes stripped and length capped at maxLen bytes, truncated on
// a UTF-8 rune boundary. Used for per-request span attributes (not
// metric labels) where preserving identifying detail matters more
// than collapsing to a bounded enum.
//
// Rune-boundary truncation is required because the OTLP wire format
// rejects span attributes that are not valid UTF-8; a naive
// byte-slice on a maxLen byte boundary can split a multi-byte rune
// mid-sequence and silently drop the entire span when the exporter
// validates. Walking back to the previous rune-start byte preserves
// the prefix that fits inside the cap.
//
// Empty input returns empty so callers can keep their `if x != ""`
// gating on whether to stamp the attribute at all.
func sanitizeCodexNotifySpanString(value string, maxLen int) string {
	if value == "" {
		return ""
	}
	cleaned := stripLogInjectionRunes(strings.TrimSpace(value))
	if cleaned == "" {
		return ""
	}
	if maxLen > 0 && len(cleaned) > maxLen {
		cleaned = truncateToRuneBoundary(cleaned, maxLen)
	}
	return cleaned
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
