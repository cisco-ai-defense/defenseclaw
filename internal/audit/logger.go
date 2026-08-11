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

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func cloneStructuredPayload(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	buf, err := json.Marshal(in)
	if err == nil {
		var out map[string]any
		if err := json.Unmarshal(buf, &out); err == nil {
			return out
		}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// stampAuditEventEnvelope fills the source envelope before the generated v8
// runtime performs collection, projection, persistence, and destination
// routing. Store.LogEvent also stamps historical direct inserts by value.
func stampAuditEventEnvelope(e *Event) {
	if e == nil {
		return
	}
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Actor == "" {
		e.Actor = "defenseclaw"
	}
	if e.RunID == "" {
		e.RunID = currentRunID()
	}
	if e.SidecarInstanceID == "" {
		e.SidecarInstanceID = ProcessAgentInstanceID()
	}
	prov := version.Current()
	if e.SchemaVersion == 0 {
		e.SchemaVersion = prov.SchemaVersion
	}
	if e.ContentHash == "" {
		e.ContentHash = prov.ContentHash
	}
	if e.Generation == 0 {
		e.Generation = prov.Generation
	}
	if e.BinaryVersion == "" {
		e.BinaryVersion = prov.BinaryVersion
	}
}

// Logger is the audit choke point for generated v8 records and metrics.
// SQLite persistence and destination fanout are owned by the bound v8 runtime;
// the removed v7 sink, gateway.jsonl, and structured-emitter bridges cannot be
// re-enabled by configuration or by temporarily detaching the runtime.
type Logger struct {
	store *Store

	mu sync.RWMutex
	// runtimeV8 is an optional cycle-free adapter to the unified v8
	// runtime. The runtime package imports audit for event-history persistence,
	// so audit owns this narrow interface rather than importing runtime back.
	runtimeV8 RuntimeV8Emitter
}

func NewLogger(store *Store) *Logger {
	logger := &Logger{store: store}
	if store != nil {
		store.BindSQLiteBusyObservabilityV8(logger)
	}
	return logger
}

// SetRuntimeV8Emitter binds generated audit-action producers to the unified v8
// runtime. A nil emitter detaches the runtime during shutdown; it never enables
// a fallback path because v8 is the Logger's unconditional authority.
func (l *Logger) SetRuntimeV8Emitter(emitter RuntimeV8Emitter) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.runtimeV8 = emitter
	l.mu.Unlock()
}

func (l *Logger) runtimeV8Snapshot() RuntimeV8Emitter {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	emitter := l.runtimeV8
	l.mu.RUnlock()
	return emitter
}

type runtimeV8Binding struct {
	emitter                     RuntimeV8Emitter
	logBatch                    RuntimeV8LogBatchEmitter
	metricEmitter               RuntimeV8MetricEmitter
	metricBatch                 RuntimeV8MetricBatchEmitter
	assetScanTrace              RuntimeV8AssetScanTraceEmitter
	findingContentFingerprinter RuntimeV8FindingContentFingerprinter
}

// runtimeV8BindingSnapshot returns the log and generated-metric capabilities
// from one mutex snapshot. A producer must use this single binding for the
// complete occurrence so a concurrent reload/detach cannot split it between
// v7 and v8 paths.
func (l *Logger) runtimeV8BindingSnapshot() runtimeV8Binding {
	if l == nil {
		return runtimeV8Binding{}
	}
	l.mu.RLock()
	emitter := l.runtimeV8
	binding := runtimeV8Binding{emitter: emitter}
	if metricEmitter, ok := emitter.(RuntimeV8MetricEmitter); ok {
		binding.metricEmitter = metricEmitter
	}
	if logBatch, ok := emitter.(RuntimeV8LogBatchEmitter); ok {
		binding.logBatch = logBatch
	}
	if metricBatch, ok := emitter.(RuntimeV8MetricBatchEmitter); ok {
		binding.metricBatch = metricBatch
	}
	if assetScanTrace, ok := emitter.(RuntimeV8AssetScanTraceEmitter); ok {
		binding.assetScanTrace = assetScanTrace
	}
	if fingerprinter, ok := emitter.(RuntimeV8FindingContentFingerprinter); ok {
		binding.findingContentFingerprinter = fingerprinter
	}
	l.mu.RUnlock()
	return binding
}

// ScanCorrelation threads per-request correlation identifiers and
// agent identity down into the scan emission pipeline (EventScan,
// EventScanFinding, scan_results and scan_findings SQLite rows).
//
// All fields are optional; the empty value is legal at every call
// site (watcher admission happens pre-session, CLI scans have no
// request/session context). The audit package cannot import
// internal/gateway to pull these out of context itself — callers
// who have the values populate the struct and pass it in.
type ScanCorrelation struct {
	RunID     string
	RequestID string
	SessionID string
	TraceID   string
	SpanID    string

	// EvaluationID joins a runtime inspection to its scan summary, findings,
	// guardrail decision, trace, and generated metric records. Classic file and
	// inventory scans leave it empty.
	EvaluationID string

	AgentID         string
	AgentName       string
	AgentInstanceID string

	// Connector attributes the scan to its originating connector so
	// EmitScanResult can record per-connector scan-finding metrics. Empty
	// for connector-agnostic scans (CLI file scans, background rescans).
	Connector string
}

// LogScan persists the forensic scan rows and emits the canonical v8 finding,
// summary, and metric families through the bound observability runtime.
func (l *Logger) LogScan(result *scanner.ScanResult) error {
	return l.LogScanWithVerdict(result, "")
}

// LogScanWithVerdict persists a scan result with an explicit admission verdict.
func (l *Logger) LogScanWithVerdict(result *scanner.ScanResult, verdict string) error {
	return l.LogScanWithCorrelation(context.Background(), result, verdict, ScanCorrelation{})
}

// LogScanWithCorrelation is the canonical scan emission entry point with
// explicit correlation + identity. It threads run_id / request_id /
// session_id / trace_id and the three-tier agent identity onto the forensic
// scan_results / scan_findings rows and generated v8 records so every surface
// agrees.
//
// ctx is passed through to scanner.EmitScanResult for tracing
// attachments; correlation IDs are taken from the corr parameter
// (not the context) so there is a single typed contract.
func (l *Logger) LogScanWithCorrelation(
	ctx context.Context,
	result *scanner.ScanResult,
	verdict string,
	corr ScanCorrelation,
) error {
	binding := l.runtimeV8BindingSnapshot()
	if binding.logBatch == nil {
		return fmt.Errorf("audit: v8 scan log batch runtime is unavailable")
	}
	if result == nil {
		return fmt.Errorf("audit: cannot log a nil scan result")
	}

	if verdict != "" {
		result.Verdict = verdict
	}

	if ctx == nil {
		ctx = context.Background()
	}
	// Persist the same deterministic source-backed evidence that the generated
	// finding family emits. This runs before scanner.EmitScanResult so the
	// forensic scan_findings row and every destination projection agree without
	// inventing a workflow status or invoking a secondary model.
	for index := range result.Findings {
		finding := &result.Findings[index]
		if finding.EvidenceSummary == "" {
			if summary, present := scanFindingV8EvidenceSummary(*finding, result).Get(); present {
				finding.EvidenceSummary = summary
			}
		}
		fingerprintPersistedFindingEvidence(finding, binding.findingContentFingerprinter)
		// This is the final in-memory boundary before forensic persistence
		// and generated audit projection. Literal credentials and executable
		// trust directives never cross it in cleartext, even when a producer
		// omitted its dedicated evidence field.
		if isLiteralCredentialFinding(*finding) {
			redactPersistedCredentialFinding(finding)
		} else if isPIIFinding(*finding) {
			redactPersistedPIIFinding(finding)
		} else {
			redactPersistedTrustExploitFinding(finding)
		}
	}
	runID := corr.RunID
	if runID == "" {
		runID = currentRunID()
	}
	// AgentInstanceID is per-session (empty when no
	// session context is known, e.g. watcher admission); the process
	// UUID goes on SidecarInstanceID only. Consumers must not group
	// sessions by sidecar identity.
	agent := scanner.AgentIdentity{
		AgentID:           corr.AgentID,
		AgentName:         corr.AgentName,
		AgentInstanceID:   corr.AgentInstanceID,
		SidecarInstanceID: ProcessAgentInstanceID(),
		RunID:             runID,
		RequestID:         corr.RequestID,
		SessionID:         corr.SessionID,
		TraceID:           corr.TraceID,
		Connector:         corr.Connector,
		EvaluationID:      corr.EvaluationID,
	}
	// EmitScanResult remains the single forensic persistence/enrichment
	// boundary, but all signal fanout is owned by the generated v8 runtime.
	// Passing nil legacy collaborators prevents a second JSONL/OTel path from
	// being revived by configuration or a concurrent reload.
	scanID, err := scanner.EmitScanResult(ctx, l.store, result, agent)
	if err != nil {
		return err
	}
	return l.emitScanV8(ctx, binding, result, scanID, verdict, corr)
}

// fingerprintPersistedFindingEvidence replaces every producer-supplied
// content fingerprint with the installation-keyed hash-v1 evidence token. A
// missing capability, invalid evidence, malformed output, or hashing failure
// clears the field so an unkeyed SHA prefix can never cross persistence.
func fingerprintPersistedFindingEvidence(
	finding *scanner.Finding,
	fingerprinter RuntimeV8FindingContentFingerprinter,
) {
	if finding == nil {
		return
	}
	finding.ContentFingerprint = ""
	if strings.TrimSpace(finding.EvidenceSummary) == "" || fingerprinter == nil {
		return
	}
	fingerprint, err := fingerprinter.FingerprintRuntimeV8FindingContent(finding.EvidenceSummary)
	if err != nil || !isCanonicalContentFingerprint(fingerprint) {
		return
	}
	finding.ContentFingerprint = fingerprint
}

// redactPersistedCredentialFinding closes the persistence boundary for
// literal secret findings. Detection needs a stable fingerprint to correlate
// the same value across turns, but no free-form value field from a secret
// finding may carry that credential into the forensic database, raw scan JSON,
// or canonical audit record. Catalog identity, severity, correlation, and the
// original-value fingerprint remain intact.
const redactedSecretFindingTitle = "Secret finding"

func redactPersistedCredentialFinding(finding *scanner.Finding) {
	if finding == nil || !isLiteralCredentialFinding(*finding) {
		return
	}
	if !isCanonicalContentFingerprint(finding.ContentFingerprint) {
		// The common Logger boundary replaces producer-supplied fingerprints
		// with keyed tokens. Retain only that canonical representation when this
		// helper is called directly or evidence hashing failed closed.
		finding.ContentFingerprint = ""
	}
	finding.EvidenceSummary = redactCredentialFindingValue(finding.EvidenceSummary)
	finding.Title = redactedSecretFindingTitle
	finding.Description = redactCredentialFindingValue(finding.Description)
	finding.Location = redactCredentialFindingValue(finding.Location)
	finding.Remediation = redactCredentialFindingValue(finding.Remediation)
	finding.ExternalEndpoint = redactCredentialFindingValue(finding.ExternalEndpoint)
	// Tags are producer supplied and therefore cannot be retained verbatim at
	// this boundary. Keep only stable semantic labels so downstream enrichment
	// still recognizes the finding as a secret without persisting source text.
	detectionOnly := hasExactFindingTag(finding.Tags, scanner.FindingTagDetectionOnly)
	finding.Tags = []string{"secret"}
	if detectionOnly {
		finding.Tags = append(finding.Tags, scanner.FindingTagDetectionOnly)
	}
	finding.Tags = append(finding.Tags, "redacted")
	redactFindingDecisionPath(finding)
}

func isCanonicalContentFingerprint(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 8 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// redactPersistedTrustExploitFinding neutralizes prompt-injection material at
// the common forensic/canonical persistence boundary. Detection identity and
// correlation metadata remain useful, but replaying an alert or its database
// evidence cannot submit the original directive to another model turn.
const redactedTrustFindingTitle = "Trust exploit finding"

func redactPersistedTrustExploitFinding(finding *scanner.Finding) {
	if finding == nil || !isTrustExploitFinding(*finding) {
		return
	}
	if !isCanonicalContentFingerprint(finding.ContentFingerprint) {
		finding.ContentFingerprint = ""
	}
	// Titles are producer supplied on generic scanner inputs, and several
	// catalog titles necessarily resemble the directive they detected. Use one
	// stable, inert label while retaining rule_id as the precise identity.
	finding.Title = redactedTrustFindingTitle
	finding.EvidenceSummary = redactCredentialFindingValue(finding.EvidenceSummary)
	finding.Description = redactCredentialFindingValue(finding.Description)
	finding.Location = redactCredentialFindingValue(finding.Location)
	finding.Remediation = redactCredentialFindingValue(finding.Remediation)
	finding.ExternalEndpoint = redactCredentialFindingValue(finding.ExternalEndpoint)
	finding.Tags = stableRedactedTrustTags(finding.Tags)
	redactFindingDecisionPath(finding)
}

func isTrustExploitFinding(finding scanner.Finding) bool {
	if hasFindingIDPrefix(finding.RuleID, "CORR-") || hasFindingIDPrefix(finding.ID, "CORR-") {
		return false
	}
	if hasFindingIDPrefix(finding.RuleID, "TRUST-") || hasFindingIDPrefix(finding.ID, "TRUST-") ||
		hasFindingIDPrefix(finding.RuleID, "LP-INJ-") || hasFindingIDPrefix(finding.ID, "LP-INJ-") ||
		hasFindingIDPrefix(finding.RuleID, "JUDGE-ADJ-INJECTION") || hasFindingIDPrefix(finding.ID, "JUDGE-ADJ-INJECTION") ||
		isTrustExploitLabel(finding.Category) {
		return true
	}
	for _, tag := range finding.Tags {
		if isTrustExploitLabel(tag) {
			return true
		}
	}
	return false
}

func hasFindingIDPrefix(value, prefix string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), prefix)
}

func isTrustExploitLabel(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "prompt-injection" || value == "trust-exploit"
}

func stableRedactedTrustTags(tags []string) []string {
	out := make([]string, 0, len(tags)+1)
	seen := make(map[string]struct{}, len(tags)+1)
	for _, tag := range tags {
		canonical := strings.ToLower(strings.TrimSpace(tag))
		if !isStableTrustFindingTag(canonical) {
			continue
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	if _, present := seen["redacted"]; !present {
		out = append(out, "redacted")
	}
	return out
}

func isStableTrustFindingTag(value string) bool {
	switch value {
	case "prompt-injection", "trust-exploit", "obfuscation",
		scanner.FindingTagDetectionOnly, "redacted":
		return true
	default:
		return false
	}
}

func hasExactFindingTag(tags []string, want string) bool {
	for _, tag := range tags {
		if strings.EqualFold(strings.TrimSpace(tag), want) {
			return true
		}
	}
	return false
}

func redactFindingDecisionPath(finding *scanner.Finding) {
	if finding == nil || len(finding.DecisionPath) == 0 {
		return
	}
	var existing map[string]string
	if json.Unmarshal(finding.DecisionPath, &existing) == nil && len(existing) == 1 &&
		isSensitiveFindingRedactionPlaceholder(existing["redacted_evidence"]) {
		return
	}
	placeholder := redactCredentialFindingValue(string(finding.DecisionPath))
	finding.DecisionPath, _ = json.Marshal(map[string]string{"redacted_evidence": placeholder})
}

func redactCredentialFindingValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	if isSensitiveFindingRedactionPlaceholder(value) {
		return value
	}
	return fmt.Sprintf("<redacted-sensitive len=%d>", len(value))
}

func isSensitiveFindingRedactionPlaceholder(value string) bool {
	const prefix = "<redacted-sensitive len="
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, ">") {
		return false
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(value, prefix), ">")
	length, err := strconv.Atoi(digits)
	return err == nil && length >= 0 && value == fmt.Sprintf("%s%d>", prefix, length)
}

func isLiteralCredentialFinding(finding scanner.Finding) bool {
	category := strings.TrimSpace(finding.Category)
	if hasSecretFindingIDPrefix(finding.RuleID) || hasSecretFindingIDPrefix(finding.ID) ||
		strings.EqualFold(category, "secret") || strings.EqualFold(category, "cred") ||
		strings.EqualFold(category, "credential") || strings.EqualFold(category, "credential-leak") {
		return true
	}
	for _, tag := range finding.Tags {
		canonical := strings.TrimSpace(tag)
		if strings.EqualFold(canonical, "secret") || strings.EqualFold(canonical, "credential") ||
			strings.EqualFold(canonical, "credential-leak") {
			return true
		}
	}
	return false
}

func hasSecretFindingIDPrefix(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	return strings.HasPrefix(value, "SEC-") || strings.HasPrefix(value, "CS-SEC-") ||
		strings.HasPrefix(value, "SECRET-") || strings.HasPrefix(value, "JSON-SEC-") ||
		strings.HasPrefix(value, "CRED-") ||
		strings.HasPrefix(value, "CG-CRED-") || strings.HasPrefix(value, "LP-SECRET-")
}

// redactPersistedPIIFinding applies the same last-mile protection as literal
// credentials to personally identifying data. Detector identity, severity,
// and correlation-envelope fields remain queryable, while raw values,
// unkeyed fingerprints, and producer-supplied labels cannot cross into SQLite,
// raw_json, or generated canonical records.
const redactedPIIFindingTitle = "PII finding"

func redactPersistedPIIFinding(finding *scanner.Finding) {
	if finding == nil || !isPIIFinding(*finding) {
		return
	}
	// Common identifiers have small enumerable spaces. Preserve only the
	// installation-keyed token installed by the common Logger boundary; an
	// untrusted or malformed producer value fails closed.
	if !isCanonicalContentFingerprint(finding.ContentFingerprint) {
		finding.ContentFingerprint = ""
	}
	finding.Title = redactedPIIFindingTitle
	finding.EvidenceSummary = redactPIIFindingValue(finding.EvidenceSummary)
	finding.Description = redactPIIFindingValue(finding.Description)
	finding.Location = redactPIIFindingValue(finding.Location)
	finding.Remediation = redactPIIFindingValue(finding.Remediation)
	finding.ExternalEndpoint = redactPIIFindingValue(finding.ExternalEndpoint)
	detectionOnly := hasExactFindingTag(finding.Tags, scanner.FindingTagDetectionOnly)
	finding.Tags = []string{"pii"}
	if detectionOnly {
		finding.Tags = append(finding.Tags, scanner.FindingTagDetectionOnly)
	}
	finding.Tags = append(finding.Tags, "redacted")
	redactPIIFindingDecisionPath(finding)
}

func redactPIIFindingValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	if isPIIRedactionPlaceholder(value) {
		return value
	}
	return fmt.Sprintf("<redacted-pii len=%d>", len(value))
}

func isPIIRedactionPlaceholder(value string) bool {
	const prefix = "<redacted-pii len="
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, ">") {
		return false
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(value, prefix), ">")
	length, err := strconv.Atoi(digits)
	return err == nil && length >= 0 && value == fmt.Sprintf("%s%d>", prefix, length)
}

func redactPIIFindingDecisionPath(finding *scanner.Finding) {
	if finding == nil || len(finding.DecisionPath) == 0 {
		return
	}
	var existing map[string]string
	if json.Unmarshal(finding.DecisionPath, &existing) == nil && len(existing) == 1 &&
		isPIIRedactionPlaceholder(existing["redacted_pii"]) {
		return
	}
	placeholder := redactPIIFindingValue(string(finding.DecisionPath))
	finding.DecisionPath, _ = json.Marshal(map[string]string{"redacted_pii": placeholder})
}

func isPIIFinding(finding scanner.Finding) bool {
	if hasPIIFindingID(finding.RuleID) || hasPIIFindingID(finding.ID) ||
		isPIIFindingLabel(finding.Category) {
		return true
	}
	for _, tag := range finding.Tags {
		if isPIIFindingLabel(tag) {
			return true
		}
	}
	return false
}

func hasPIIFindingID(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	return strings.HasPrefix(value, "PII-") || strings.HasPrefix(value, "CS-PII-") ||
		strings.HasPrefix(value, "LP-PII-") || strings.HasPrefix(value, "JUDGE-PII-") ||
		strings.HasPrefix(value, "JUDGE-ADJ-PII") ||
		isKnownEnterprisePIIFindingID(value)
}

func isPIIFindingLabel(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pii", "pii-exposure":
		return true
	default:
		return false
	}
}

func isKnownEnterprisePIIFindingID(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN",
		"ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER",
		"ENT-IBAN", "ENT-US-PHONE", "ENT-EMAIL-BULK", "ENT-PASSPORT-US",
		"ENT-DL-CA", "ENT-MEDICAL-RECORD", "ENT-DOB-PATTERN", "ENT-NHS-NUMBER",
		"ENT-BULK-CSV-PII", "ENT-BULK-JSON-PII":
		return true
	default:
		return false
	}
}

// LogInspectFindingsWithCorrelation is the canonical live runtime-inspection
// entry point. It adapts the detector-neutral finding source once, persists the
// forensic rows, and emits generated v8 finding/summary logs and metrics on the
// same runtime generation. No gateway JSONL or legacy Provider fanout occurs.
func (l *Logger) LogInspectFindingsWithCorrelation(
	ctx context.Context,
	source scanner.InspectFindingSource,
	corr ScanCorrelation,
) (evaluationID, scanID string, err error) {
	evaluationID, result := scanner.BuildInspectScanResult(source)
	corr.EvaluationID = evaluationID
	if err := l.LogScanWithCorrelation(ctx, result, source.Verdict, corr); err != nil {
		return evaluationID, result.ScanID, err
	}
	return evaluationID, result.ScanID, nil
}

// LogAction emits one registered audit action through the v8 runtime.
func (l *Logger) LogAction(action, target, details string) error {
	return l.LogActionWithTrace(action, target, details, "")
}

// LogActionCtx is the context-aware shortcut for HTTP-driven call sites. It
// pulls the canonical correlation envelope stamped by gateway middleware so
// every routed v8 signal carries the same trace/session/agent/policy identity.
//
// Use this from every proxy / router / api handler that already has a
// *http.Request in scope. Non-HTTP callers (watcher, CLI commands)
// should continue using LogAction / LogActionWithCorrelation since
// their ctx will not carry an envelope (EnvelopeFromContext returns
// the zero value, which the auto-fill treats as "no override").
func (l *Logger) LogActionCtx(ctx context.Context, action, target, details string) error {
	return l.logActionWithEnvelopeContext(ctx, EnvelopeFromContext(ctx), action, target, details, "INFO")
}

// LogCLIAction is the canonical Python/operator CLI ingress. It retains the
// caller's raw source facts for central per-destination projection while
// stamping actor/origin as CLI instead of misclassifying the authenticated
// loopback HTTP handoff as an operator API action.
func (l *Logger) LogCLIAction(ctx context.Context, action, target, details string) error {
	return l.logActionWithEnvelopeContextActor(
		ctx, EnvelopeFromContext(ctx), action, target, details, "INFO", "cli",
	)
}

// LogActionWithTrace persists an action event with an OTel trace ID for
// cross-system correlation between Splunk O11y and Splunk local.
func (l *Logger) LogActionWithTrace(action, target, details, traceID string) error {
	return l.LogActionWithCorrelation(action, target, details, traceID, "")
}

// LogActionWithCorrelation emits an action event with both an OTel trace ID
// and a gateway request ID. Kept for non-HTTP callers that
// resolved the ids out-of-band (watcher rescans, CLI orchestration).
// HTTP-driven call sites should use LogActionCtx instead so every
// envelope dimension (session_id, agent_id, agent_name,
// agent_instance_id, policy_id, destination_app, tool_*) stays in lockstep.
//
// An empty requestID is legal (pre-proxy subsystems like the watcher
// have no HTTP correlation context); the SQLite column is nullable
// and downstream sinks strip the attribute when unset.
func (l *Logger) LogActionWithCorrelation(action, target, details, traceID, requestID string) error {
	return l.logActionWithEnvelope(CorrelationEnvelope{
		TraceID:   traceID,
		RequestID: requestID,
	}, action, target, details)
}

// LogActionWithCorrelationConnector is LogActionWithCorrelation plus a
// connector attribution stamp. The proxy guardrail-verdict path knows
// which connector produced the decision (p.connectorName()); threading
// it here lets the verdict row carry the dedicated connector column on
// SQLite and the top-level connector field on every sink, instead of
// forcing SIEM consumers to scrape a `connector=` token out of details.
// An empty connector behaves exactly like LogActionWithCorrelation.
func (l *Logger) LogActionWithCorrelationConnector(action, target, details, traceID, requestID, connector string) error {
	return l.logActionWithEnvelope(CorrelationEnvelope{
		TraceID:   traceID,
		RequestID: requestID,
		Connector: connector,
	}, action, target, details)
}

// LogActionSeverityConnector persists an action event with an explicit
// severity and connector attribution. Most lifecycle rows are fine at the
// INFO default LogAction applies, but security-relevant call sites — like
// the hook self-heal guard, where a runtime enforcement-hook tamper/repair
// is the event — must land at the right severity on every surface AND carry
// the dedicated connector column so SIEM consumers can filter by connector
// without scraping a token out of details. An empty severity falls back to
// INFO; an empty connector behaves exactly like LogAction.
func (l *Logger) LogActionSeverityConnector(action, target, details, severity, connector string) error {
	return l.logActionWithEnvelopeSeverity(CorrelationEnvelope{Connector: connector}, action, target, details, severity)
}

// logActionWithEnvelope is the shared implementation for every LogAction*
// variant. Centralizing here keeps every correlation dimension identical.
func (l *Logger) logActionWithEnvelope(env CorrelationEnvelope, action, target, details string) error {
	return l.logActionWithEnvelopeContext(context.Background(), env, action, target, details, "INFO")
}

// logActionWithEnvelopeSeverity is logActionWithEnvelope with a caller-chosen
// severity. logActionWithEnvelope delegates here with "INFO" so the default
// path is unchanged; only call sites that explicitly need a non-INFO row
// (via LogActionSeverityConnector) reach this with a different value.
func (l *Logger) logActionWithEnvelopeSeverity(env CorrelationEnvelope, action, target, details, severity string) error {
	return l.logActionWithEnvelopeContext(context.Background(), env, action, target, details, severity)
}

func (l *Logger) logActionWithEnvelopeContext(
	ctx context.Context,
	env CorrelationEnvelope,
	action, target, details, severity string,
) error {
	return l.logActionWithEnvelopeContextActor(ctx, env, action, target, details, severity, "defenseclaw")
}

func (l *Logger) logActionWithEnvelopeContextActor(
	ctx context.Context,
	env CorrelationEnvelope,
	action, target, details, severity, actor string,
) error {
	return l.logActionWithEnvelopeContextAndAssetActor(
		ctx, env, action, target, details, severity, actor, nil,
	)
}

func (l *Logger) logActionWithEnvelopeContextAndAsset(
	ctx context.Context,
	env CorrelationEnvelope,
	action, target, details, severity string,
	assetInput *AssetLifecycleInput,
) error {
	return l.logActionWithEnvelopeContextAndAssetActor(
		ctx, env, action, target, details, severity, "defenseclaw", assetInput,
	)
}

func (l *Logger) logActionWithEnvelopeContextAndAssetActor(
	ctx context.Context,
	env CorrelationEnvelope,
	action, target, details, severity, actor string,
	assetInput *AssetLifecycleInput,
) error {
	if severity == "" {
		severity = "INFO"
	}
	if actor == "" {
		actor = "defenseclaw"
	}
	event := Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    target,
		Actor:     actor,
		Details:   details,
		Severity:  severity,
		// Process-scoped identifier — never collapses onto
		// agent_instance_id (per-session) per the three-tier contract.
		SidecarInstanceID: ProcessAgentInstanceID(),
	}
	// Apply caller-supplied correlation before stampAuditEventEnvelope fills
	// any missing run ID from the process.  Initializing RunID eagerly from the
	// sidecar made an authenticated CLI handoff silently discard its explicit
	// per-command run ID in a real running gateway.
	applyEnvelope(&event, env)
	stampAuditEventEnvelope(&event)
	disposition, emitErr := l.emitControlPlaneV8(ctx, event)
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	disposition, emitErr = l.emitAuditPlatformHealthV8(ctx, event)
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	if mapping, mapped := telemetry.AssetLifecycleAction(action); mapped && mapping.CanonicalEvent != "" {
		input := AssetLifecycleInput{
			AssetID: target, AssetType: inferAssetTypeFromAction(action, ""),
			TargetRef: target,
		}
		if assetInput != nil {
			input = *assetInput
		}
		binding := l.runtimeV8BindingSnapshot()
		if binding.emitter == nil {
			return fmt.Errorf("audit: asset lifecycle v8 runtime is unavailable")
		}
		disposition, emitErr = l.emitAssetLifecycleV8(ctx, event, input, mapping, binding.emitter)
		if emitErr != nil {
			return emitErr
		}
		if disposition != auditV8Unhandled {
			return nil
		}
	}
	disposition, emitErr = l.emitCompatibilityAuditV8(ctx, event, compatibilityAuditV8Options{})
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	return fmt.Errorf("audit: no generated v8 family handled action %q", event.Action)
}

// LogActionWithEnforcement persists an action event with enforcement metadata.
// The enforcement map may contain keys:
// "install", "file", "runtime", "source_path".
func (l *Logger) LogActionWithEnforcement(action, target, details string, enforcement map[string]string) error {
	structured := make(map[string]any, len(enforcement))
	for key, value := range enforcement {
		structured[key] = value
	}
	event := Event{
		ID:                uuid.New().String(),
		Timestamp:         time.Now().UTC(),
		Action:            action,
		Target:            target,
		Actor:             "defenseclaw",
		Details:           details,
		Severity:          "INFO",
		RunID:             currentRunID(),
		SidecarInstanceID: ProcessAgentInstanceID(),
		Structured:        structured,
	}
	return l.logEventWithV8(context.Background(), event, func(ctx context.Context, stamped Event) (auditV8Disposition, error) {
		return l.emitCompatibilityAuditV8(ctx, stamped, compatibilityAuditV8Options{
			classification: observability.ClassificationContext{
				MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: true},
				Enforced:       true,
			},
			source: observability.SourceWatcher, phase: "apply", outcome: observability.OutcomeBlocked,
		})
	})
}

// LogEventCtx is the context-aware variant of LogEvent. It pulls the
// correlation envelope (run_id, trace_id, request_id, session_id,
// agent_*, policy_id, destination_app, tool_*) from ctx via the
// gateway correlation middleware and auto-fills any empty field on
// event before handing off to LogEvent. This is the preferred entry
// point for any HTTP-driven code path so every canonical record and
// local-history row carries the same envelope without each call site
// having to plumb seven strings manually.
//
// Non-empty fields on event always win over the ctx envelope —
// callers that already resolved a specific identity (e.g. a
// scanner callback that uses the agent from the scan target, not
// the request) keep their pin.
func (l *Logger) LogEventCtx(ctx context.Context, event Event) error {
	applyEnvelope(&event, EnvelopeFromContext(ctx))
	return l.logEventWithV8(ctx, event, l.emitControlPlaneV8)
}

// LogEvent emits a pre-built event through the registered v8 audit pipeline.
func (l *Logger) LogEvent(event Event) error {
	return l.logEventWithV8(context.Background(), event, l.emitControlPlaneV8)
}

type auditV8EventEmitter func(context.Context, Event) (auditV8Disposition, error)

func (l *Logger) logEventWithV8(ctx context.Context, event Event, emit auditV8EventEmitter) error {
	// v7 clean break: AgentInstanceID is per-SESSION. Callers that
	// carry a session context (the router, proxy session resolver)
	// stamp it explicitly. Absence is meaningful — "no session
	// anchor for this event" — and must round-trip as empty.
	// The process-scoped identifier lives on SidecarInstanceID;
	// we auto-fill that one so every row has a stable sidecar
	// identity without burdening callers.
	stampAuditEventEnvelope(&event)
	disposition := auditV8Unhandled
	if emit != nil {
		var emitErr error
		disposition, emitErr = emit(ctx, event)
		if emitErr != nil {
			return emitErr
		}
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	disposition, emitErr := l.emitAuditPlatformHealthV8(ctx, event)
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	disposition, emitErr = l.emitCompatibilityAuditV8(ctx, event, compatibilityAuditV8Options{})
	if emitErr != nil {
		return emitErr
	}
	if disposition != auditV8Unhandled {
		return nil
	}
	return fmt.Errorf("audit: no generated v8 family handled action %q", event.Action)
}

// ActivityInput is the source-fact contract for an operator-facing mutation.
// The generated v8 runtime owns its projection and persistence; activity_events
// remains readable only for historical database compatibility.
type ActivityInput struct {
	Actor       string
	Action      Action
	TargetType  string
	TargetID    string
	Reason      string
	Before      map[string]any
	After       map[string]any
	Diff        []ActivityDiffEntry
	VersionFrom string
	VersionTo   string
	Severity    string
	RunID       string
	RequestID   string
	TraceID     string
}

// ActivityDiffEntry records one canonical control-plane mutation delta.
type ActivityDiffEntry struct {
	Path   string `json:"path"`
	Op     string `json:"op"` // add | remove | replace
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// LogActivity emits an operator mutation through the generated v8 runtime.
func (l *Logger) LogActivity(in ActivityInput) error {
	if l == nil {
		return nil
	}
	return l.logActivityImpl(in)
}

// LogAlert records a runtime alert through canonical platform-health signals.
//
// Severity should be one of INFO / WARN / HIGH / CRITICAL. Source
// is a short subsystem name ("admission", "scanner", "sink", etc).
// Summary is a single-line human string; Details is an arbitrary
// map that becomes the details blob.
func (l *Logger) LogAlert(source, severity, summary string, details map[string]any) error {
	return l.logAlertWithEnvelope(CorrelationEnvelope{}, source, severity, summary, details)
}

// LogAlertCtx is the context-aware variant of LogAlert. It lifts the
// correlation envelope out of ctx so every admitted signal carries the same
// trace/session/agent/policy identity as the request that triggered the alert.
//
// Non-HTTP callers (watcher, CLI) can continue calling LogAlert; the
// ctx-less path leaves the envelope empty, which round-trips as NULL
// in SQLite and an absent attribute in OTel — the same behavior as
// before this change.
func (l *Logger) LogAlertCtx(ctx context.Context, source, severity, summary string, details map[string]any) error {
	return l.logAlertWithEnvelope(EnvelopeFromContext(ctx), source, severity, summary, details)
}

// logAlertWithEnvelope is the shared implementation for LogAlert and
// LogAlertCtx.
func (l *Logger) logAlertWithEnvelope(env CorrelationEnvelope, source, severity, summary string, details map[string]any) error {
	if l == nil {
		return nil
	}
	if severity == "" {
		severity = "WARN"
	}
	payload := map[string]any{
		"source":  source,
		"summary": summary,
	}
	for k, v := range details {
		payload[k] = v
	}
	blob, _ := json.Marshal(payload)

	ev := Event{
		Action:   string(ActionAlert),
		Target:   source,
		Actor:    "defenseclaw",
		Details:  string(blob),
		Severity: severity,
	}
	applyEnvelope(&ev, env)
	errorCode := runtimeAlertErrorCode(ev.Details)
	return l.logEventWithV8(context.Background(), ev, func(ctx context.Context, stamped Event) (auditV8Disposition, error) {
		return l.emitRuntimeAlertV8(ctx, stamped, source, errorCode)
	})
}

// Close detaches the cycle-free runtime adapter after the owner has drained
// and shut down the canonical observability runtime. Logger owns no exporter or
// sink resources in v8.
func (l *Logger) Close() {
	l.SetRuntimeV8Emitter(nil)
}

func inferTargetType(scannerName string) string {
	switch scannerName {
	case "mcp-scanner", "mcp_scanner":
		return "mcp"
	case "skill-scanner", "skill_scanner":
		return "skill"
	case "codeguard", "aibom", "aibom-claw",
		"clawshield-vuln", "clawshield-secrets", "clawshield-pii",
		"clawshield-malware", "clawshield-injection":
		return "code"
	default:
		return "unknown"
	}
}

func inferAssetTypeFromAction(action, details string) string {
	switch {
	case contains(action, "mcp") || contains(details, "type=mcp"):
		return "mcp"
	case contains(action, "plugin") || contains(details, "type=plugin"):
		return "plugin"
	case contains(action, "skill") || contains(details, "type=skill"):
		return "skill"
	default:
		return ""
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
