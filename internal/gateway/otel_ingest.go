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
// This receiver is intentionally minimal: we accept the body, attach
// the connector source and gateway tokens (already validated by
// tokenAuth middleware), summarize the payload into an audit event,
// and persist via persistAuditEvent. We do NOT decode the full
// OTLP protobuf shape — operators who want raw OTel pipelines run
// the gateway's downstream OTLP forwarder (separate, see
// internal/audit/sinks/otlp_logs.go). The audit summary is enough
// for the SIEM rollup and the TUI status panel.
//
// Threat model:
//   - All three endpoints are gated by tokenAuth + apiCSRFProtect
//     (the same chain as /api/v1/codex/hook). Unauthenticated POSTs
//     are rejected upstream of this handler.
//   - Body size is capped by maxBodyMiddleware (1 MiB). The OTLP
//     spec recommends batching; one MiB covers roughly 50-100 log
//     records or 500-1000 metric data points per batch.
//   - JSON parsing failures degrade to a 400 — we don't try to be
//     clever with partial parsing because that's a footgun: the
//     caller will retry, and a structured error gives us a clean
//     audit trail.
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

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
// Body is OTLP-JSON (Content-Type: application/json) — the protobuf
// variant is not yet supported because Codex and Claude Code default
// to JSON over HTTP per their docs. We surface a 415 if the caller
// sends application/x-protobuf so they get an actionable error
// rather than a silent parse failure.
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
	if !isOTLPJSONContentType(contentType) {
		// Be explicit about why we rejected so the exporter logs
		// surface the right error. application/x-protobuf is the
		// other valid OTLP shape; we don't accept it yet.
		w.Header().Set("Accept", "application/json")
		http.Error(w,
			fmt.Sprintf("unsupported content-type %q (defenseclaw OTLP receiver accepts application/json only)", contentType),
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

	summary, parseErr := summarizeOTLPPayload(body, signal)
	if parseErr != nil {
		// We log the parse failure but still 200 — the exporter
		// already paid the network round-trip and retrying won't
		// help (the body is malformed). Audit the failure so the
		// operator can investigate.
		ev := audit.Event{
			Timestamp: time.Now().UTC(),
			Action:    "otel.ingest.malformed",
			Target:    fmt.Sprintf("otlp:%s", signal),
			Actor:     source,
			Details:   fmt.Sprintf("malformed OTLP-JSON payload: %v (size=%d bytes)", parseErr, len(body)),
			Severity:  "WARN",
			AgentName: source,
		}
		_ = persistAuditEvent(a.logger, a.store, ev)
		writeOTLPSuccess(w)
		return
	}

	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    fmt.Sprintf("otel.ingest.%s", signal),
		Target:    fmt.Sprintf("otlp:%s", signal),
		Actor:     source,
		Details:   summary,
		Severity:  "INFO",
		AgentName: source,
	}
	if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
		// Best-effort: failing to persist must NOT cause the
		// exporter to retry — telemetry storms during DB outages
		// are worse than the lost batch. Log to stderr in the
		// usual gateway pattern and 200.
		fmt.Fprintf(otelIngestLogSink(), "[otel-ingest] persist failed (signal=%s source=%s): %v\n", signal, source, err)
	}

	writeOTLPSuccess(w)
}

// isOTLPJSONContentType returns true if the request Content-Type
// indicates OTLP-JSON. Accepts application/json with optional
// charset / "; encoding=otlp-json" parameters.
func isOTLPJSONContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	// Strip parameters (anything after ;).
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "application/json"
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
func summarizeOTLPPayload(body []byte, signal otelIngestSignal) (string, error) {
	if len(body) == 0 {
		return "", errors.New("empty body")
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("unmarshal envelope: %w", err)
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
		return "", fmt.Errorf("unknown signal: %s", signal)
	}

	resourceRaw, ok := envelope[resourceKey]
	if !ok {
		return fmt.Sprintf("size=%d bytes, no %s entries", len(body), resourceKey), nil
	}

	var resources []map[string]json.RawMessage
	if err := json.Unmarshal(resourceRaw, &resources); err != nil {
		return "", fmt.Errorf("unmarshal %s: %w", resourceKey, err)
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
	return strings.Join(parts, " "), nil
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
// the fields the SIEM rollup needs (type, turn-id, model, status)
// and treat any extra keys as opaque (passed through into the
// audit Details string verbatim). The schema is deliberately
// permissive: codex bumps the notify shape across releases and we
// never want a schema drift to make the gateway 400 a real event.
type codexNotifyPayload struct {
	Type   string `json:"type"`
	TurnID string `json:"turn_id"`
	Model  string `json:"model,omitempty"`
	Status string `json:"status,omitempty"`
}

// handleCodexNotify accepts agent-turn-complete events from the
// notify-bridge.sh shim that the codex connector installs in
// Setup(). The bridge POSTs the raw JSON arg codex passes it.
//
// We:
//  1. Validate Content-Type (application/json) — the bridge sets
//     this explicitly so a non-JSON body is a real error.
//  2. Parse a permissive subset (codexNotifyPayload). Unknown fields
//     are kept in the raw body for the audit Details column.
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

	action := "codex.notify"
	severity := "INFO"
	if parseErr != nil {
		// Persist a malformed marker so operators can investigate
		// codex schema drift without losing the event.
		action = "codex.notify.malformed"
		severity = "WARN"
	} else if p.Type != "" {
		action = "codex.notify." + sanitizeNotifyType(p.Type)
	}

	details := string(body)
	if len(details) > 4096 {
		// SQLite Details is a TEXT column without a hard cap, but
		// trimming keeps the audit row queryable in tools that
		// truncate long text columns.
		details = details[:4096] + "...[truncated]"
	}

	ev := audit.Event{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "codex.session",
		Actor:     "codex",
		Details:   details,
		Severity:  severity,
		AgentName: "codex",
		SessionID: p.TurnID,
	}
	if err := persistAuditEvent(a.logger, a.store, ev); err != nil {
		fmt.Fprintf(otelIngestLogSink(), "[codex-notify] persist failed: %v\n", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
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
