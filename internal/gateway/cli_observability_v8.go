// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const cliObservabilityV8Path = "/api/v1/observability/cli"

// cliObservabilityV8Request is the narrow, authenticated handoff from the
// Python CLI to the process-owned v8 runtime. The Python process supplies raw,
// schema-eligible source facts; audit.Logger then performs collection,
// classification, per-destination redaction, SQLite persistence, and fanout.
// Exactly one payload arm must match Kind.
type cliObservabilityV8Request struct {
	Kind            string                             `json:"kind"`
	RunID           string                             `json:"run_id,omitempty"`
	Action          *cliObservabilityV8Action          `json:"action,omitempty"`
	Activity        *cliObservabilityV8Activity        `json:"activity,omitempty"`
	Alert           *cliObservabilityV8Alert           `json:"alert,omitempty"`
	Scan            *cliObservabilityV8Scan            `json:"scan,omitempty"`
	LLMBridge       *cliObservabilityV8LLMBridge       `json:"llm_bridge,omitempty"`
	WebhookDelivery *cliObservabilityV8WebhookDelivery `json:"webhook_delivery,omitempty"`
}

type cliObservabilityV8Action struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Details string `json:"details"`
}

type cliObservabilityV8Activity struct {
	Actor       string                    `json:"actor"`
	Action      audit.Action              `json:"action"`
	TargetType  string                    `json:"target_type"`
	TargetID    string                    `json:"target_id"`
	Before      map[string]any            `json:"before,omitempty"`
	After       map[string]any            `json:"after,omitempty"`
	Diff        []audit.ActivityDiffEntry `json:"diff,omitempty"`
	VersionFrom string                    `json:"version_from,omitempty"`
	VersionTo   string                    `json:"version_to,omitempty"`
	Severity    string                    `json:"severity,omitempty"`
}

type cliObservabilityV8Alert struct {
	Source   string         `json:"source"`
	Severity string         `json:"severity,omitempty"`
	Summary  string         `json:"summary"`
	Details  map[string]any `json:"details,omitempty"`
}

type cliObservabilityV8LLMBridge struct {
	Model         string   `json:"model"`
	Provider      string   `json:"provider,omitempty"`
	Status        string   `json:"status"`
	DurationMS    float64  `json:"duration_ms"`
	InputTokens   int64    `json:"input_tokens,omitempty"`
	OutputTokens  int64    `json:"output_tokens,omitempty"`
	ResponseModel string   `json:"response_model,omitempty"`
	ResponseID    string   `json:"response_id,omitempty"`
	FinishReasons []string `json:"finish_reasons,omitempty"`
}

type cliObservabilityV8WebhookDelivery struct {
	WebhookKind string  `json:"webhook_kind"`
	TargetURL   string  `json:"target_url"`
	StatusCode  int     `json:"status_code"`
	DurationMS  float64 `json:"duration_ms"`
	Succeeded   bool    `json:"succeeded"`
}

// Python represents durations in milliseconds. Keeping that wire unit
// explicit avoids relying on Go's time.Duration JSON representation
// (nanoseconds) and makes overflow validation deterministic.
type cliObservabilityV8Scan struct {
	Scanner    string                      `json:"scanner"`
	Target     string                      `json:"target"`
	Timestamp  time.Time                   `json:"timestamp"`
	Findings   []cliObservabilityV8Finding `json:"findings"`
	DurationMS int64                       `json:"duration_ms"`
}

// cliObservabilityV8Finding deliberately mirrors Finding.to_dict in the
// Python CLI. Do not decode this boundary into scanner.Finding directly: that
// type contains internal correlation and forensic fields which an ingress
// caller must neither mint nor persist without validation.
type cliObservabilityV8Finding struct {
	ID          string           `json:"id"`
	Severity    scanner.Severity `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Location    string           `json:"location"`
	Remediation string           `json:"remediation"`
	Scanner     string           `json:"scanner"`
	Tags        []string         `json:"tags"`
	RuleID      string           `json:"rule_id,omitempty"`
	LineNumber  *int             `json:"line_number,omitempty"`
}

const (
	cliObservabilityV8MaxIdentifierBytes = 256
	cliObservabilityV8MaxTargetBytes     = 8192
	cliObservabilityV8MaxTitleBytes      = 4096
	cliObservabilityV8MaxEvidenceBytes   = 65536
	cliObservabilityV8MaxLocationBytes   = 8192
	cliObservabilityV8MaxTags            = 64
	cliObservabilityV8MaxTagBytes        = 256
	cliObservabilityV8MaxTagsBytes       = 16384
	cliObservabilityV8MaxFindings        = 4096
	cliObservabilityV8MaxDurationMS      = float64((7 * 24 * time.Hour) / time.Millisecond)
)

func (a *APIServer) handleCLIObservabilityV8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a == nil || a.observabilityV8RuntimeEmitter() == nil {
		http.Error(w, `{"error":"canonical observability runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	request, err := decodeCLIObservabilityV8Request(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid canonical observability request"}`, http.StatusBadRequest)
		return
	}
	if a.logger == nil && request.Kind != "llm_bridge" && request.Kind != "webhook_delivery" {
		http.Error(w, `{"error":"canonical observability runtime unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	envelope := audit.EnvelopeFromContext(r.Context())
	if request.RunID != "" {
		envelope.RunID = request.RunID
	}
	ctx := audit.ContextWithEnvelope(r.Context(), envelope)
	if err := a.emitCLIObservabilityV8(ctx, request, envelope); err != nil {
		// The response is intentionally content-free: runtime, database, route,
		// exporter, and source-payload errors must not cross this API boundary.
		http.Error(w, `{"error":"canonical observability emission failed"}`, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeCLIObservabilityV8Request(body io.Reader) (cliObservabilityV8Request, error) {
	if body == nil {
		return cliObservabilityV8Request{}, errors.New("missing body")
	}
	raw, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return cliObservabilityV8Request{}, errors.New("invalid body")
	}
	if !cliObservabilityV8JSONHasUniqueKeys(raw) {
		return cliObservabilityV8Request{}, errors.New("duplicate JSON member")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request cliObservabilityV8Request
	if err := decoder.Decode(&request); err != nil {
		return cliObservabilityV8Request{}, errors.New("invalid body")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return cliObservabilityV8Request{}, errors.New("trailing body")
	}
	if err := request.validate(); err != nil {
		return cliObservabilityV8Request{}, err
	}
	return request, nil
}

func (request cliObservabilityV8Request) validate() error {
	if len(request.RunID) > 256 || strings.TrimSpace(request.RunID) != request.RunID ||
		(request.RunID != "" && !observability.IsStableToken(request.RunID)) {
		return errors.New("invalid run id")
	}
	arms := 0
	for _, present := range []bool{
		request.Action != nil, request.Activity != nil, request.Alert != nil, request.Scan != nil,
		request.LLMBridge != nil, request.WebhookDelivery != nil,
	} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return errors.New("exactly one payload is required")
	}
	switch request.Kind {
	case "action":
		if request.Action == nil ||
			(!audit.IsKnownAction(request.Action.Name) && !audit.IsKnownActionPrefix(request.Action.Name)) {
			return errors.New("invalid action")
		}
	case "activity":
		if request.Activity == nil ||
			(!audit.IsKnownAction(string(request.Activity.Action)) &&
				!audit.IsKnownActionPrefix(string(request.Activity.Action))) {
			return errors.New("invalid activity")
		}
	case "alert":
		if request.Alert == nil || strings.TrimSpace(request.Alert.Source) == "" ||
			strings.TrimSpace(request.Alert.Summary) == "" {
			return errors.New("invalid alert")
		}
	case "scan":
		if request.Scan == nil || request.Scan.validate() != nil {
			return errors.New("invalid scan")
		}
	case "llm_bridge":
		if request.LLMBridge == nil || request.LLMBridge.validate() != nil {
			return errors.New("invalid llm bridge observation")
		}
	case "webhook_delivery":
		if request.WebhookDelivery == nil || request.WebhookDelivery.validate() != nil {
			return errors.New("invalid webhook delivery observation")
		}
	default:
		return errors.New("invalid kind")
	}
	return nil
}

func (observation cliObservabilityV8LLMBridge) validate() error {
	if !cliObservabilityV8Identifier(observation.Model, true) ||
		(observation.Provider != "" && !cliObservabilityV8Identifier(observation.Provider, true)) ||
		(observation.ResponseModel != "" && !cliObservabilityV8Identifier(observation.ResponseModel, true)) ||
		(observation.ResponseID != "" && !cliObservabilityV8Identifier(observation.ResponseID, true)) ||
		observation.DurationMS < 0 || observation.DurationMS > cliObservabilityV8MaxDurationMS ||
		math.IsNaN(observation.DurationMS) || math.IsInf(observation.DurationMS, 0) ||
		observation.InputTokens < 0 || observation.OutputTokens < 0 || len(observation.FinishReasons) > 64 {
		return errors.New("invalid llm bridge fields")
	}
	switch observation.Status {
	case "success", "timeout", "rate_limited", "auth_failed", "network_error", "internal":
	default:
		return errors.New("invalid llm bridge status")
	}
	for _, reason := range observation.FinishReasons {
		if !cliObservabilityV8Text(reason, 256, true) {
			return errors.New("invalid finish reason")
		}
	}
	return nil
}

func (observation cliObservabilityV8WebhookDelivery) validate() error {
	if !cliObservabilityV8Identifier(observation.WebhookKind, true) ||
		!cliObservabilityV8Text(observation.TargetURL, cliObservabilityV8MaxTargetBytes, true) ||
		observation.StatusCode < 0 || observation.StatusCode > 999 ||
		observation.DurationMS < 0 || observation.DurationMS > cliObservabilityV8MaxDurationMS ||
		math.IsNaN(observation.DurationMS) || math.IsInf(observation.DurationMS, 0) {
		return errors.New("invalid webhook delivery fields")
	}
	return nil
}

func (scan cliObservabilityV8Scan) validate() error {
	if !cliObservabilityV8Identifier(scan.Scanner, true) ||
		!cliObservabilityV8Text(scan.Target, cliObservabilityV8MaxTargetBytes, true) ||
		scan.Timestamp.IsZero() || scan.Timestamp.Year() < 1 || scan.Timestamp.Year() > 9999 ||
		scan.DurationMS < 0 || scan.DurationMS > math.MaxInt64/int64(time.Millisecond) ||
		len(scan.Findings) > cliObservabilityV8MaxFindings {
		return errors.New("invalid scan fields")
	}
	duration := time.Duration(scan.DurationMS) * time.Millisecond
	if scan.Timestamp.Add(duration).Year() > 9999 {
		return errors.New("invalid scan interval")
	}
	for i := range scan.Findings {
		if err := scan.Findings[i].validate(scan.Scanner); err != nil {
			return err
		}
	}
	return nil
}

func (finding cliObservabilityV8Finding) validate(scanScanner string) error {
	if !cliObservabilityV8Identifier(finding.ID, true) ||
		!cliObservabilityV8Severity(finding.Severity) ||
		!cliObservabilityV8Text(finding.Title, cliObservabilityV8MaxTitleBytes, true) ||
		!cliObservabilityV8Text(finding.Description, cliObservabilityV8MaxEvidenceBytes, false) ||
		!cliObservabilityV8Text(finding.Location, cliObservabilityV8MaxLocationBytes, false) ||
		!cliObservabilityV8Text(finding.Remediation, cliObservabilityV8MaxEvidenceBytes, false) ||
		(finding.Scanner != "" &&
			(!cliObservabilityV8Identifier(finding.Scanner, true) || finding.Scanner != scanScanner)) ||
		(finding.RuleID != "" && !cliObservabilityV8Identifier(finding.RuleID, true)) ||
		(finding.LineNumber != nil && *finding.LineNumber < 1) ||
		len(finding.Tags) > cliObservabilityV8MaxTags {
		return errors.New("invalid finding fields")
	}
	tagBytes := 0
	for _, tag := range finding.Tags {
		if !cliObservabilityV8Text(tag, cliObservabilityV8MaxTagBytes, true) {
			return errors.New("invalid finding tags")
		}
		tagBytes += len(tag)
		if tagBytes > cliObservabilityV8MaxTagsBytes {
			return errors.New("invalid finding tags")
		}
	}
	return nil
}

func cliObservabilityV8Severity(value scanner.Severity) bool {
	switch value {
	case scanner.SeverityInfo, scanner.SeverityLow, scanner.SeverityMedium,
		scanner.SeverityHigh, scanner.SeverityCritical:
		return true
	default:
		return false
	}
}

func cliObservabilityV8Identifier(value string, required bool) bool {
	if !cliObservabilityV8Text(value, cliObservabilityV8MaxIdentifierBytes, required) {
		return false
	}
	if value == "" {
		return true
	}
	for index, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || (index > 0 && strings.ContainsRune("._:/-", char)) {
			continue
		}
		return false
	}
	return true
}

func cliObservabilityV8Text(value string, maxBytes int, required bool) bool {
	if !utf8.ValidString(value) || len(value) > maxBytes || strings.ContainsRune(value, '\x00') {
		return false
	}
	trimmed := strings.TrimSpace(value)
	if required && trimmed == "" {
		return false
	}
	return !required || trimmed == value
}

func (finding cliObservabilityV8Finding) scannerFinding(scanScanner string) scanner.Finding {
	findingScanner := finding.Scanner
	if findingScanner == "" {
		findingScanner = scanScanner
	}
	return scanner.Finding{
		ID: finding.ID, Severity: finding.Severity, Title: finding.Title,
		Description: finding.Description, Location: finding.Location,
		Remediation: finding.Remediation, Scanner: findingScanner,
		Tags: append([]string(nil), finding.Tags...), RuleID: finding.RuleID,
		LineNumber: finding.LineNumber,
	}
}

func cliObservabilityV8JSONHasUniqueKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func() bool
	value = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delim, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return false
				}
				if _, duplicate := seen[key]; duplicate {
					return false
				}
				seen[key] = struct{}{}
				if !value() {
					return false
				}
			}
			closing, closeErr := decoder.Token()
			return closeErr == nil && closing == json.Delim('}')
		case '[':
			for decoder.More() {
				if !value() {
					return false
				}
			}
			closing, closeErr := decoder.Token()
			return closeErr == nil && closing == json.Delim(']')
		default:
			return false
		}
	}
	if !value() {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func (a *APIServer) emitCLIObservabilityV8(
	ctx context.Context,
	request cliObservabilityV8Request,
	envelope audit.CorrelationEnvelope,
) error {
	switch request.Kind {
	case "action":
		return a.logger.LogCLIAction(ctx, request.Action.Name, request.Action.Target, request.Action.Details)
	case "activity":
		activity := request.Activity
		return a.logger.LogActivity(audit.ActivityInput{
			Actor: activity.Actor, Action: activity.Action,
			TargetType: activity.TargetType, TargetID: activity.TargetID,
			Before: activity.Before, After: activity.After, Diff: activity.Diff,
			VersionFrom: activity.VersionFrom, VersionTo: activity.VersionTo,
			Severity: activity.Severity, RunID: envelope.RunID,
			RequestID: envelope.RequestID, TraceID: envelope.TraceID,
		})
	case "alert":
		alert := request.Alert
		return a.logger.LogAlertCtx(ctx, alert.Source, alert.Severity, alert.Summary, alert.Details)
	case "scan":
		scan := request.Scan
		findings := make([]scanner.Finding, len(scan.Findings))
		for i := range scan.Findings {
			findings[i] = scan.Findings[i].scannerFinding(scan.Scanner)
		}
		result := &scanner.ScanResult{
			Scanner: scan.Scanner, Target: scan.Target, Timestamp: scan.Timestamp,
			Findings: findings, Duration: time.Duration(scan.DurationMS) * time.Millisecond,
		}
		return a.logger.LogScanWithCorrelation(ctx, result, "", audit.ScanCorrelation{
			RunID: envelope.RunID, RequestID: envelope.RequestID,
			SessionID: envelope.SessionID, TraceID: envelope.TraceID,
			AgentID: envelope.AgentID, AgentName: envelope.AgentName,
			AgentInstanceID: envelope.AgentInstanceID, Connector: envelope.Connector,
		})
	case "llm_bridge":
		return a.emitCLILLMBridgeV8(ctx, *request.LLMBridge)
	case "webhook_delivery":
		return a.emitCLIWebhookDeliveryV8(ctx, *request.WebhookDelivery)
	default:
		return errors.New("invalid kind")
	}
}

type cliObservabilitySignalV8Runtime interface {
	StartModelTrace(
		context.Context,
		observability.SpanModelChatInput,
	) (context.Context, *observabilityruntime.ModelTrace, error)
	RecordGeneratedMetricBatch(
		context.Context,
		[]observabilityruntime.GeneratedMetricBatchItem,
	) ([]telemetry.V8MetricRecordResult, error)
}

const cliObservabilityV8Producer = "cli.observability.v8"

func (a *APIServer) emitCLILLMBridgeV8(
	ctx context.Context,
	request cliObservabilityV8LLMBridge,
) error {
	runtime, ok := a.observabilityV8RuntimeEmitter().(cliObservabilitySignalV8Runtime)
	if !ok || runtime == nil {
		return errors.New("canonical signal runtime unavailable")
	}
	finishedAt := time.Now().UTC()
	startedAt := finishedAt.Add(-time.Duration(request.DurationMS * float64(time.Millisecond)))
	observation := hookModelV8Observation{
		meta: llmEventMeta{
			Source: "python-cli", Provider: request.Provider, Model: request.Model,
			ResponseID: request.ResponseID, FinishReasons: append([]string(nil), request.FinishReasons...),
		},
		provider: request.Provider, reportedModel: request.Model, model: request.Model,
		responseModel: request.ResponseModel, startedAt: startedAt, finishedAt: finishedAt,
		usage:         hookLLMSpanUsage{promptTokens: request.InputTokens, completionTokens: request.OutputTokens},
		finishReasons: append([]string(nil), request.FinishReasons...),
	}
	input := hookModelV8ModelInput(observation)
	input.Envelope.Source = observability.SourceCLI
	input.Envelope.Connector = ""
	input.Envelope.Provenance.Producer = cliObservabilityV8Producer
	input.DefenseClawConnectorSource = observability.Absent[string]()
	input.ConditionConnectorKnown = false
	if request.Status != "success" {
		input.Outcome = observability.OutcomeFailed
		if request.Status == "timeout" {
			input.Outcome = observability.OutcomeTimedOut
		}
		input.Status = observability.NewTraceStatusError(observability.Absent[string]())
		input.ErrorType = observability.Present(request.Status)
		input.ConditionTechnicalFailure = true
	}
	startedContext, span, err := runtime.StartModelTrace(ctx, input)
	if err != nil {
		return err
	}
	metricContext := ctx
	if span != nil {
		defer span.Abort()
		metricContext = span.Context()
		if metricContext == nil {
			metricContext = startedContext
		}
		if err := span.End(input); err != nil {
			return err
		}
	}
	item := newGatewayGeneratedMetricItem(
		metricContext, finishedAt, observability.SourceCLI, "", cliObservabilityV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawLLMBridgeLatency),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawLLMBridgeLatency(observability.MetricDefenseClawLLMBridgeLatencyInput{
				Envelope: envelope, Value: request.DurationMS,
				GenAIRequestModel:       observability.Present(request.Model),
				DefenseClawMetricStatus: observability.Present(request.Status),
			})
		},
	)
	_, err = runtime.RecordGeneratedMetricBatch(metricContext, []observabilityruntime.GeneratedMetricBatchItem{item})
	return err
}

func (a *APIServer) emitCLIWebhookDeliveryV8(
	ctx context.Context,
	request cliObservabilityV8WebhookDelivery,
) error {
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime)
	if !ok || runtime == nil {
		return errors.New("canonical metric runtime unavailable")
	}
	dispatcher := &WebhookDispatcher{}
	dispatcher.BindObservabilityV8(runtime)
	outcome := "failed"
	if request.Succeeded {
		outcome = "delivered"
	}
	return dispatcher.recordDeliveryConfirmedV8(
		ctx, request.WebhookKind, hashWebhookTargetURL(request.TargetURL), outcome,
		request.StatusCode, request.DurationMS, false,
	)
}
