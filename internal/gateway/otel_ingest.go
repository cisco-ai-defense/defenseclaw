// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package-internal OTLP-HTTP receiver. It serves both the shared
// /v1/{logs,metrics,traces} routes used by header-capable exporters and the
// connector-scoped /otlp/<source>/<token>/v1/<signal> loopback routes. Codex
// uses a dedicated path token; Claude Code uses authenticated exporter
// headers. Neither credential is inferred from payload content.
//
// The receiver is a strict v8 ingress adapter. It decodes JSON or protobuf into
// the official OTLP request types, classifies every leaf through the generated
// inbound catalog, constructs canonical DefenseClaw records, and hands them to
// the central router. It never stores or forwards the raw request envelope and
// has no legacy audit/provider fallback.
//
// Threat model:
//   - All three endpoints are gated by tokenAuth + apiCSRFProtect
//     (the same chain as /api/v1/codex/hook). Unauthenticated POSTs
//     are rejected upstream of this handler.
//   - Body size is capped by maxBodyMiddleware (1 MiB). The OTLP
//     spec recommends batching; one MiB covers roughly 50-100 log
//     records or 500-1000 metric data points per batch.
//   - Payload parsing failures emit content-free mandatory v8 health evidence
//     and still return OTLP success; retrying the same bad batch would only
//     create gateway load and noisier telemetry.
package gateway

import (
	"bytes"
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
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// otelIngestStats is the bounded batch accounting derived from the typed
// protobuf request. The counters remain low-cardinality (signal × source) so a
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

// otelIngestSource is the connector that originated the OTel POST. On shared
// /v1/* routes the x-defenseclaw-source header is consumed only after header
// authentication. On scoped routes handleOTLPPathToken overwrites the header
// with the source authenticated by the URL namespace, so a caller cannot use
// one connector's path token while claiming another connector identity.
const otelSourceHeader = "x-defenseclaw-source"

// handleOTLPLogs accepts OTLP-HTTP /v1/logs POSTs from CLI processes.
// Body may be OTLP-JSON (application/json) or OTLP protobuf
// (application/x-protobuf). Both forms enter the same typed importer.
func (a *APIServer) handleOTLPLogs(w http.ResponseWriter, r *http.Request) {
	a.handleOTLPSignal(w, r, otelSignalLogs)
}

// handleOTLPMetrics accepts OTLP-HTTP /v1/metrics POSTs.
func (a *APIServer) handleOTLPMetrics(w http.ResponseWriter, r *http.Request) {
	a.handleOTLPSignal(w, r, otelSignalMetrics)
}

// handleOTLPTraces accepts OTLP-HTTP /v1/traces POSTs.
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
// It fails closed until the process-owned v8 runtime is bound, validates the
// typed request, imports each supported leaf through generated contracts, emits
// bounded batch accounting, and returns the canonical OTLP success body.
//
// The OTLP spec defines the success response as an empty
// ExportPartialSuccess message; "{}" is the JSON form. Returning a
// non-empty body triggers retries on some exporter implementations.
func (a *APIServer) handleOTLPSignal(w http.ResponseWriter, r *http.Request, signal otelIngestSignal) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.hasOTLPObservabilityRuntime() {
		http.Error(w, "observability runtime unavailable", http.StatusServiceUnavailable)
		return
	}
	started := time.Now().UTC()
	source := normalizeConnectorTelemetrySource(r.Header.Get(otelSourceHeader))
	ctx := r.Context()
	if id := agentIdentityForOTLPSource(source); id != (AgentIdentity{}) {
		ctx = ContextWithAgentIdentity(ctx, id)
	}
	ctx, ingestTrace := a.startOTLPIngestTraceV8(ctx, r, signal, source, started)
	if ingestTrace != nil {
		defer ingestTrace.abort()
	}

	contentType := r.Header.Get("Content-Type")
	if !isOTLPContentType(contentType) {
		a.emitOTLPBatchRejectedV8(ctx, signal, source, "unknown", "unsupported_content_type", 0, started)
		ingestTrace.finishReceive(otlpIngestTraceResult{
			outcome: observability.OutcomeRejected, statusCode: http.StatusUnsupportedMediaType,
			payloadFormat: "unknown", reasonClass: "unsupported_content_type",
			errorType: "unsupported_content_type",
		})
		// Be explicit about why we rejected so the exporter logs
		// surface the right error.
		w.Header().Set("Accept", "application/json, application/x-protobuf")
		http.Error(w,
			fmt.Sprintf("unsupported content-type %q (defenseclaw OTLP receiver accepts application/json or application/x-protobuf)", contentType),
			http.StatusUnsupportedMediaType)
		return
	}

	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		reasonClass := "body_read_failed"
		status := http.StatusBadRequest
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			reasonClass = "body_too_large"
			status = http.StatusRequestEntityTooLarge
		}
		a.emitOTLPBatchRejectedV8(ctx, signal, source, "unknown", reasonClass, 0, started)
		ingestTrace.finishReceive(otlpIngestTraceResult{
			outcome: observability.OutcomeRejected, statusCode: int64(status),
			payloadFormat: "unknown", reasonClass: reasonClass, errorType: reasonClass,
			technical: reasonClass == "body_read_failed",
		})
		// MaxBytesReader writes no response until its read error reaches the
		// handler. Exporters must not treat an oversized batch as malformed
		// syntax that could succeed unchanged on retry.
		http.Error(w, "read body", status)
		return
	}
	bodyBytes := int64(len(body))
	ingestTrace.startNormalize(ctx, signal, source, time.Now().UTC())
	decoded, normalizeErr := decodeOTLPIngestBody(body, signal, contentType)
	summaryBody := decoded.normalized
	payloadFormat := decoded.payloadFormat
	if normalizeErr != nil {
		a.emitOTLPBatchRejectedV8(ctx, signal, source, payloadFormat, "invalid_"+payloadFormat, bodyBytes, started)
		result := otlpIngestTraceResult{
			outcome: observability.OutcomeRejected, statusCode: http.StatusOK,
			payloadFormat: payloadFormat, reasonClass: "invalid_" + payloadFormat,
			errorType: "invalid_" + payloadFormat, wireBytes: bodyBytes, hasWireBytes: true,
		}
		ingestTrace.finishNormalize(result)
		ingestTrace.finishReceive(result)
		writeOTLPSuccess(w)
		return
	}
	stats, parseErr := decodedOTLPIngestStats(decoded.message, signal)
	if parseErr != nil {
		a.emitOTLPBatchRejectedV8(ctx, signal, source, payloadFormat, "invalid_envelope", bodyBytes, started)
		result := otlpIngestTraceResult{
			outcome: observability.OutcomeRejected, statusCode: http.StatusOK,
			payloadFormat: payloadFormat, reasonClass: "invalid_envelope",
			errorType: "invalid_envelope", wireBytes: bodyBytes, normalizedBytes: int64(len(summaryBody)),
			hasWireBytes: true, hasNormalized: true,
		}
		ingestTrace.finishNormalize(result)
		ingestTrace.finishReceive(result)
		writeOTLPSuccess(w)
		return
	}
	accounting, importErr := a.importDecodedOTLPRequestV8(
		ctx, decoded.message, signal, source, time.Now().UTC(),
	)
	if importErr != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical accepted-record import incomplete")
	}
	if importErr == nil && accounting.allSelfSuppressed() {
		// Per-leaf generated echo recognition proved every leaf returned to
		// its local exporter. Abort the already-started health hierarchy and
		// emit no recursive log, metric, or trace.
		ingestTrace.abort()
		writeOTLPSuccess(w)
		return
	}
	ingestTrace.finishNormalize(otlpIngestTraceResult{
		outcome: func() observability.Outcome {
			if importErr != nil {
				return observability.OutcomePartial
			}
			outcome, outcomeErr := accounting.outcome()
			if outcomeErr != nil {
				return observability.OutcomePartial
			}
			return outcome
		}(), statusCode: http.StatusOK,
		payloadFormat: payloadFormat, records: stats.Records, resources: stats.Resources,
		wireBytes: bodyBytes, normalizedBytes: int64(len(summaryBody)),
		hasWireBytes: true, hasNormalized: true, hasSummary: true,
	})
	var emitErr error
	if importErr == nil {
		emitErr = a.emitOTLPBatchAccountingV8(
			ctx, signal, source, payloadFormat, stats, bodyBytes,
			int64(len(summaryBody)), started, accounting,
		)
	}
	if emitErr != nil {
		fmt.Fprintln(otelIngestLogSink(), "[otel-ingest] canonical normalized-batch persistence failed")
	}
	a.recordOTLPBatchMetricsV8(ctx, signal, source, "ok", stats.Records, bodyBytes)
	receiveResult := otlpIngestTraceResult{
		outcome: observability.OutcomeCompleted, statusCode: http.StatusOK,
		payloadFormat: payloadFormat, records: stats.Records, resources: stats.Resources,
		wireBytes: bodyBytes, normalizedBytes: int64(len(summaryBody)),
		hasWireBytes: true, hasNormalized: true, hasSummary: true,
	}
	if importErr != nil || emitErr != nil {
		receiveResult.outcome = observability.OutcomePartial
		receiveResult.errorType = "accepted_record_import_incomplete"
		receiveResult.technical = true
	} else if outcome, outcomeErr := accounting.outcome(); outcomeErr == nil {
		receiveResult.outcome = outcome
	}
	ingestTrace.finishReceive(receiveResult)
	writeOTLPSuccess(w)
}

func (a *APIServer) deltaOTLPCumulativeTokenUsage(usage otelTokenUsage) (otelTokenUsage, bool) {
	if a == nil || !usage.cumulative || usage.tokens <= 0 || usage.seriesKey == "" {
		return usage, usage.tokens > 0
	}
	a.otlpMetricMu.Lock()
	defer a.otlpMetricMu.Unlock()
	if a.otlpMetricCumulative == nil {
		a.otlpMetricCumulative = make(map[string]otlpCumulativePoint)
	}
	previous, exists := a.otlpMetricCumulative[usage.seriesKey]
	delta := usage.tokens
	start := usage.startTime
	if exists && previous.start == start {
		if usage.tokens <= previous.value {
			return usage, false
		}
		delta = usage.tokens - previous.value
	}
	if !exists {
		for len(a.otlpMetricCumulative) >= hookPromptCacheMaxEntries && len(a.otlpMetricCumulativeOrder) > 0 {
			oldest := a.otlpMetricCumulativeOrder[0]
			a.otlpMetricCumulativeOrder = a.otlpMetricCumulativeOrder[1:]
			delete(a.otlpMetricCumulative, oldest)
		}
		a.otlpMetricCumulativeOrder = append(a.otlpMetricCumulativeOrder, usage.seriesKey)
	}
	a.otlpMetricCumulative[usage.seriesKey] = otlpCumulativePoint{value: usage.tokens, start: start}
	usage.tokens = delta
	return usage, delta > 0
}

func normalizeOTLPIngestBody(body []byte, signal otelIngestSignal, contentType string) ([]byte, string, error) {
	decoded, err := decodeOTLPIngestBody(body, signal, contentType)
	if err != nil {
		return nil, decoded.payloadFormat, err
	}
	return decoded.normalized, decoded.payloadFormat, nil
}

// decodedOTLPIngestBody retains the official OTLP protobuf model for v8 leaf
// identification and mapping. Normalized JSON is used only for measured encoded
// size and bounded diagnostic helpers; canonical importers read message directly
// rather than round-tripping through a generic map.
type decodedOTLPIngestBody struct {
	message       proto.Message
	normalized    []byte
	payloadFormat string
}

func decodeOTLPIngestBody(
	body []byte,
	signal otelIngestSignal,
	contentType string,
) (decodedOTLPIngestBody, error) {
	var msg proto.Message
	switch signal {
	case otelSignalLogs:
		msg = &collectorlogspb.ExportLogsServiceRequest{}
	case otelSignalMetrics:
		msg = &collectormetricspb.ExportMetricsServiceRequest{}
	case otelSignalTraces:
		msg = &collectortracepb.ExportTraceServiceRequest{}
	default:
		return decodedOTLPIngestBody{payloadFormat: "unknown"}, fmt.Errorf("unknown OTLP signal")
	}
	payloadFormat := "json"
	if isOTLPProtobufContentType(contentType) {
		payloadFormat = "protobuf"
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, msg); err != nil {
			return decodedOTLPIngestBody{payloadFormat: payloadFormat}, err
		}
		if messageContainsUnknownOTLPFields(msg.ProtoReflect()) {
			return decodedOTLPIngestBody{payloadFormat: payloadFormat}, errors.New("OTLP protobuf contains unsupported fields")
		}
	} else {
		if err := validateUniqueOTLPJSONMembers(body); err != nil {
			return decodedOTLPIngestBody{payloadFormat: payloadFormat}, err
		}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, msg); err != nil {
			return decodedOTLPIngestBody{payloadFormat: payloadFormat}, err
		}
	}
	normalized, err := protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}.Marshal(msg)
	if err != nil {
		return decodedOTLPIngestBody{payloadFormat: payloadFormat}, err
	}
	return decodedOTLPIngestBody{
		message: msg, normalized: normalized, payloadFormat: payloadFormat,
	}, nil
}

// decodedOTLPIngestStats counts protocol leaves from the typed request. A
// metric leaf is one data point, not one instrument descriptor; this aligns
// receiver accounting with the independently disposable unit used by inbound
// binding, collection, and partial-batch dispositions.
func decodedOTLPIngestStats(message proto.Message, signal otelIngestSignal) (otelIngestStats, error) {
	return walkDecodedOTLPLeaves(message, signal, nil)
}

// validateUniqueOTLPJSONMembers rejects duplicate object members before the
// protobuf JSON decoder can normalize them. Accepting the last value would let
// two lexical JSON requests select different generated discriminators while
// appearing identical after normalization. The scanner validates structure but
// never materializes sender-controlled objects or values.
func validateUniqueOTLPJSONMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := scanUniqueOTLPJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("OTLP JSON contains trailing values")
		}
		return err
	}
	return nil
}

const maxOTLPJSONNestingDepth = 64

func scanUniqueOTLPJSONValue(decoder *json.Decoder, depth int) error {
	if decoder == nil || depth > maxOTLPJSONNestingDepth {
		return errors.New("OTLP JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			nameToken, nameErr := decoder.Token()
			if nameErr != nil {
				return nameErr
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("OTLP JSON object member is not a string")
			}
			if _, duplicate := members[name]; duplicate {
				return errors.New("OTLP JSON contains duplicate object member")
			}
			members[name] = struct{}{}
			if err := scanUniqueOTLPJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			if closeErr != nil {
				return closeErr
			}
			return errors.New("OTLP JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueOTLPJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			if closeErr != nil {
				return closeErr
			}
			return errors.New("OTLP JSON array is not closed")
		}
	default:
		return errors.New("OTLP JSON contains invalid delimiter")
	}
	return nil
}

// messageContainsUnknownOTLPFields rejects protobuf extension bytes at every
// nesting level. Silently preserving or dropping such bytes would create an
// opaque side channel around the canonical v8 schema and redaction pipeline.
func messageContainsUnknownOTLPFields(message protoreflect.Message) bool {
	if !message.IsValid() {
		return false
	}
	if len(message.GetUnknown()) != 0 {
		return true
	}
	found := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind:
			value.Map().Range(func(_ protoreflect.MapKey, child protoreflect.Value) bool {
				if messageContainsUnknownOTLPFields(child.Message()) {
					found = true
					return false
				}
				return true
			})
		case field.IsList() && field.Kind() == protoreflect.MessageKind:
			list := value.List()
			for index := 0; index < list.Len() && !found; index++ {
				found = messageContainsUnknownOTLPFields(list.Get(index).Message())
			}
		case field.Kind() == protoreflect.MessageKind:
			found = messageContainsUnknownOTLPFields(value.Message())
		}
		return !found
	})
	return found
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
	case "openclaw", "zeptoclaw", "claudecode", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent":
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

type otelTokenUsage struct {
	operationName string
	providerName  string
	model         string
	agentName     string
	sessionID     string
	tokenType     string
	tokens        int64
	cumulative    bool
	seriesKey     string
	startTime     string
}

type otlpCumulativePoint struct {
	value int64
	start string
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

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
	if isUnscopedOTLPEndpointPath(path) {
		return true
	}
	_, _, ok := parseOTLPPathToken(path)
	return ok
}

// isUnscopedOTLPEndpointPath identifies the standard OTLP-HTTP signal routes
// used by exporters that can carry connector-scoped authorization headers.
// The name distinguishes them from the legacy /otlp/<source>/<token>/...
// transport without implying that these endpoints are unauthenticated.
func isUnscopedOTLPEndpointPath(path string) bool {
	switch path {
	case "/v1/logs", "/v1/metrics", "/v1/traces":
		return true
	default:
		return false
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
	if err := persistAuditEventCtx(r.Context(), a.logger, ev); err != nil {
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
	enrichCodexNotifySpan(ctx, p, kind, result)
	metricRuntime, _ := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	recordCodexNotifyV8(ctx, metricRuntime, kind, statusLabel, result, p.TurnID)

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
		emittedPromptID := a.emitLLMPromptEventV8(ctx, meta, prompt, nil)
		if emittedPromptID != "" {
			meta.PromptID = emittedPromptID
			a.rememberHookPromptID("codex", sessionID, turnID, emittedPromptID)
		}
		spanMeta := meta
		spanMeta.Source = "codex"
		a.rememberHookLLMSpanPrompt(spanMeta, prompt)
	}
	if response := codexNotifyResponse(payload); response != "" {
		meta.ResponseID = stableLLMEventID("response", "codex", sessionID, turnID)
		finishReasons := codexNotifyFinishReasons(payload)
		meta.FinishReasons = append([]string(nil), finishReasons...)
		a.emitLLMResponseEventV8(ctx, meta, response, "", finishReasons)
		spanMeta := meta
		spanMeta.Source = "codex"
		a.emitHookLLMSpan(ctx, spanMeta, response)
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
		parts = append(parts, "thread_id="+sanitizeCodexNotifySpanString(p.ThreadID, 256))
	}
	if p.TurnID != "" {
		parts = append(parts, "turn_id="+sanitizeCodexNotifySpanString(p.TurnID, 256))
	}
	if p.Model != "" {
		parts = append(parts, "model="+sanitizeCodexNotifySpanString(p.Model, 256))
	}
	if p.Status != "" {
		parts = append(parts, "status="+sanitizeCodexNotifySpanString(p.Status, 256))
	}
	if parseErr != nil {
		parts = append(parts, "parse_error="+sanitizeCodexNotifySpanString(parseErr.Error(), 256))
	}
	return strings.Join(parts, " ")
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
