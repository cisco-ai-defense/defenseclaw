// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// emitScanV8 emits every finding before the finalized scan summary on one
// immutable runtime generation. Each operation retains its own collection
// decision; disabling security.finding does not suppress asset.scan and vice
// versa. The scanner's forensic tables have already committed before entry.
func (l *Logger) emitScanV8(
	ctx context.Context,
	binding runtimeV8Binding,
	result *scanner.ScanResult,
	scanID string,
	verdict string,
	correlation ScanCorrelation,
) error {
	if binding.logBatch == nil || result == nil || scanID == "" {
		return fmt.Errorf("audit: v8 scan log batch runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	observedAt := result.Timestamp.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	operations := make([]RuntimeV8LogOperation, 0, len(result.Findings)+1)
	for index := range result.Findings {
		finding := result.Findings[index]
		operation, err := scanFindingV8Operation(
			ctx, finding, result, scanID, observedAt, correlation,
		)
		if err != nil {
			return err
		}
		operations = append(operations, operation)
	}
	summaryEvent := scanSummaryV8Event(result, scanID, observedAt, correlation)
	summary, err := scanSummaryV8Operation(ctx, summaryEvent, result, scanID, verdict, correlation)
	if err != nil {
		return err
	}
	operations = append(operations, summary)

	outcomes, emitErr := binding.logBatch.EmitRuntimeV8LogBatch(ctx, operations)
	if emitErr != nil {
		return fmt.Errorf("audit: emit generated scan log batch: %w", emitErr)
	}
	if len(outcomes) != len(operations) {
		return fmt.Errorf("audit: generated scan log batch returned an incomplete outcome set")
	}
	for index := range outcomes {
		if _, outcomeErr := runtimeV8Disposition(outcomes[index], false); outcomeErr != nil {
			return fmt.Errorf("audit: generated scan log %d: %w", index, outcomeErr)
		}
	}
	if binding.assetScanTrace != nil {
		traceInput, traceInputErr := newAssetScanRuntimeV8TraceInput(
			summaryEvent, result, scanID, verdict, correlation,
		)
		if traceInputErr == nil {
			// Trace collection and sampling are independent of log routing. A
			// trace/export failure cannot replay already-committed forensic rows
			// or turn a successful scan into a caller-visible scan failure.
			_ = binding.assetScanTrace.EmitRuntimeV8AssetScanTrace(ctx, traceInput)
		}
	}

	metrics, metricErr := newScanRuntimeV8GeneratedMetrics(
		summaryEvent, result, scanID, verdict, correlation,
	)
	if metricErr == nil {
		// Metrics are independent best-effort signals. Log collection drops do
		// not disable them, and a metric failure cannot invite duplicate scan
		// persistence or replay the already-emitted finding batch.
		_ = l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, metrics)
	}
	return nil
}

func newAssetScanRuntimeV8TraceInput(
	event Event,
	result *scanner.ScanResult,
	scanID string,
	verdict string,
	correlation ScanCorrelation,
) (observability.SpanAssetScanInput, error) {
	if result == nil || result.Duration < 0 || !runtimeV8Identifier(scanID) || event.Timestamp.IsZero() {
		return observability.SpanAssetScanInput{}, fmt.Errorf("audit: invalid generated scan trace input")
	}
	start := event.Timestamp.UTC()
	end := start.Add(result.Duration)
	if start.UnixNano() <= 0 || end.UnixNano() <= 0 || end.Before(start) {
		return observability.SpanAssetScanInput{}, fmt.Errorf("audit: invalid generated scan trace timestamps")
	}
	counts := scanV8SeverityCounts(result)
	failed := strings.TrimSpace(result.ScanError) != "" || result.ExitCode != 0
	outcome := observability.OutcomeCompleted
	status := observability.NewTraceStatusOK()
	errorType := observability.Absent[string]()
	if failed {
		outcome = observability.OutcomeFailed
		status = observability.NewTraceStatusError(observability.Absent[string]())
		errorType = observability.Present("scan_failed")
	}
	connector := optionalScanV8Identifier(correlation.Connector)
	return observability.SpanAssetScanInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(start), Source: observability.SourceScanner,
			Connector: correlation.Connector, Action: string(ActionScan), Phase: "completed",
			Correlation: controlPlaneV8Correlation(event),
			Provenance: observability.FamilyProvenanceInput{
				Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
			},
		},
		Outcome: outcome, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(end.UnixNano()),
		Status:                       status,
		DefenseClawConnectorSource:   connector,
		DefenseClawRunID:             optionalScanV8Identifier(correlation.RunID),
		DefenseClawEvaluationID:      optionalScanV8Identifier(correlation.EvaluationID),
		DefenseClawScanID:            observability.Present(scanID),
		DefenseClawScanScanner:       optionalScanV8Text(result.Scanner),
		DefenseClawScanTargetRef:     optionalScanV8Text(result.Target),
		DefenseClawScanTargetType:    optionalScanV8Text(scanner.NormalizeTargetTypeEnum(result.EffectiveTargetType())),
		DefenseClawScanDurationMs:    observability.Present(result.Duration.Milliseconds()),
		DefenseClawScanFindingCount:  observability.Present(int64(len(result.Findings))),
		DefenseClawScanCriticalCount: observability.Present(counts[scanner.SeverityCritical]),
		DefenseClawScanHighCount:     observability.Present(counts[scanner.SeverityHigh]),
		DefenseClawScanMediumCount:   observability.Present(counts[scanner.SeverityMedium]),
		DefenseClawScanLowCount:      observability.Present(counts[scanner.SeverityLow]),
		DefenseClawScanInfoCount:     observability.Present(counts[scanner.SeverityInfo]),
		DefenseClawScanSeverityMax:   optionalScanV8Text(string(result.MaxSeverity())),
		DefenseClawScanVerdict:       optionalScanV8Text(scanner.NormalizeVerdictEnum(verdict)),
		DefenseClawScanExitCode:      observability.Present(int64(result.ExitCode)),
		DefenseClawScanErrorSummary:  optionalScanV8Text(result.ScanError),
		ErrorType:                    errorType,
		ConditionConnectorKnown:      connector.IsPresent(),
		ConditionOperationTerminal:   true,
		ConditionTechnicalFailure:    failed,
	}, nil
}

func scanFindingV8Operation(
	ctx context.Context,
	finding scanner.Finding,
	result *scanner.ScanResult,
	scanID string,
	observedAt time.Time,
	correlation ScanCorrelation,
) (RuntimeV8LogOperation, error) {
	if !runtimeV8Identifier(finding.FindingOccurrenceID) || !runtimeV8Identifier(finding.RuleID) {
		return RuntimeV8LogOperation{}, fmt.Errorf("audit: scan finding has no stable occurrence or rule identity")
	}
	event := Event{
		ID: finding.FindingOccurrenceID, Timestamp: observedAt,
		Action: string(ActionScanFinding), Target: result.Target, Actor: "defenseclaw",
		Details:  fmt.Sprintf("scanner=%s rule_id=%s category=%s", result.Scanner, finding.RuleID, finding.Category),
		Severity: string(finding.Severity), RunID: correlation.RunID, SpanID: correlation.SpanID,
		RequestID: correlation.RequestID, SessionID: correlation.SessionID, TraceID: correlation.TraceID,
		AgentID: correlation.AgentID, AgentName: correlation.AgentName,
		AgentInstanceID: correlation.AgentInstanceID, SidecarInstanceID: ProcessAgentInstanceID(),
		Connector: correlation.Connector, EvaluationID: correlation.EvaluationID,
		ScanID: scanID, FindingOccurrenceID: finding.FindingOccurrenceID,
	}
	stampAuditEventEnvelope(&event)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketSecurityFinding,
		EventName:   observability.EventName(observability.TelemetryEventFindingObserved),
		RawSeverity: event.Severity,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent, observability.ProducerKey(gatewaylog.EventScanFinding),
		classification, observability.SourceScanner, event.Connector,
		observability.ProducerKey(event.Action),
	)
	if err != nil {
		return RuntimeV8LogOperation{}, fmt.Errorf("audit: classify scan finding: %w", err)
	}
	build := func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, fmt.Errorf("audit: scan finding requires ordinary admission")
		}
		canonicalCorrelation := controlPlaneV8Correlation(event)
		builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
			event, snapshot, observability.SourceScanner, "finding", canonicalCorrelation,
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		lineNumber := observability.Absent[int64]()
		if finding.LineNumber != nil && *finding.LineNumber > 0 {
			lineNumber = observability.Present(int64(*finding.LineNumber))
		}
		confidence := observability.Absent[float64]()
		if finding.Confidence > 0 && finding.Confidence <= 1 && !math.IsNaN(finding.Confidence) {
			confidence = observability.Present(finding.Confidence)
		}
		record, buildErr := builder.BuildLogFindingObserved(observability.LogFindingObservedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel,
			DefenseClawEvaluationID:               optionalScanV8Identifier(correlation.EvaluationID),
			DefenseClawFindingID:                  finding.FindingOccurrenceID,
			DefenseClawScanID:                     observability.Present(scanID),
			DefenseClawFindingRuleID:              finding.RuleID,
			DefenseClawFindingCategory:            optionalScanV8Text(finding.Category),
			DefenseClawSecuritySeverity:           string(finding.Severity),
			DefenseClawFindingConfidence:          confidence,
			DefenseClawFindingTargetRef:           optionalScanV8Identifier(result.Target),
			DefenseClawGuardrailEvidenceSummary:   scanFindingV8EvidenceSummary(finding, result),
			DefenseClawFindingTitle:               optionalScanV8Text(finding.Title),
			DefenseClawFindingDescription:         optionalScanV8Text(finding.Description),
			DefenseClawFindingLocation:            optionalScanV8Text(finding.Location),
			DefenseClawFindingLineNumber:          lineNumber,
			DefenseClawFindingRemediation:         optionalScanV8Text(finding.Remediation),
			DefenseClawFindingTags:                optionalScanV8StringSlice(finding.Tags),
			DefenseClawFindingDataAxes:            optionalScanV8StringSlice(finding.DataAxis),
			DefenseClawFindingToolCapabilityClass: optionalScanV8Text(finding.ToolCapabilityClass),
			DefenseClawFindingExternalEndpoint:    optionalScanV8Text(finding.ExternalEndpoint),
			DefenseClawFindingDecisionPath:        optionalScanV8DecisionPath(finding.DecisionPath),
			DefenseClawFindingContentFingerprint:  optionalScanV8Identifier(finding.ContentFingerprint),
			DefenseClawScanScanner:                optionalScanV8Text(result.Scanner),
		})
		return verifyRuntimeV8Record(record, buildErr, event, false)
	}
	return RuntimeV8LogOperation{
		ctx: contextWithLegacyEventProjection(ctx, event), metadata: metadata, build: build,
	}, nil
}

// scanFindingV8EvidenceSummary follows the deterministic source order in the
// v8 contract: a producer-supplied bounded excerpt, then source description,
// then a rule/title/target/location fallback. It never invokes a model and
// never substitutes a workflow status for an observation fact.
func scanFindingV8EvidenceSummary(
	finding scanner.Finding,
	result *scanner.ScanResult,
) observability.Optional[string] {
	if summary := optionalScanV8Text(finding.EvidenceSummary); summary.IsPresent() {
		return summary
	}
	if description := optionalScanV8Text(finding.Description); description.IsPresent() {
		return description
	}
	parts := make([]string, 0, 4)
	if finding.RuleID != "" {
		parts = append(parts, "rule="+finding.RuleID)
	}
	if finding.Title != "" {
		parts = append(parts, "title="+finding.Title)
	}
	if result != nil {
		if targetType := strings.TrimSpace(result.EffectiveTargetType()); targetType != "" {
			parts = append(parts, "target_type="+targetType)
		}
	}
	if finding.Location != "" {
		parts = append(parts, "location="+finding.Location)
	}
	return optionalScanV8Text(strings.Join(parts, "; "))
}

func scanSummaryV8Event(
	result *scanner.ScanResult,
	scanID string,
	observedAt time.Time,
	correlation ScanCorrelation,
) Event {
	event := Event{
		ID: uuid.NewString(), Timestamp: observedAt, Action: string(ActionScan), Target: result.Target,
		Actor: "defenseclaw",
		Details: fmt.Sprintf("scanner=%s findings=%d max_severity=%s duration=%s",
			result.Scanner, len(result.Findings), result.MaxSeverity(), result.Duration),
		Severity: string(result.MaxSeverity()), RunID: correlation.RunID, SpanID: correlation.SpanID,
		RequestID: correlation.RequestID, SessionID: correlation.SessionID, TraceID: correlation.TraceID,
		AgentID: correlation.AgentID, AgentName: correlation.AgentName,
		AgentInstanceID: correlation.AgentInstanceID, SidecarInstanceID: ProcessAgentInstanceID(),
		Connector: correlation.Connector, EvaluationID: correlation.EvaluationID, ScanID: scanID,
	}
	stampAuditEventEnvelope(&event)
	return event
}

func scanSummaryV8Operation(
	ctx context.Context,
	event Event,
	result *scanner.ScanResult,
	scanID string,
	verdict string,
	correlation ScanCorrelation,
) (RuntimeV8LogOperation, error) {
	eventName := observability.EventName(observability.TelemetryEventScanCompleted)
	outcome := observability.OutcomeCompleted
	if strings.TrimSpace(result.ScanError) != "" || result.ExitCode != 0 {
		eventName = observability.EventName(observability.TelemetryEventScanFailed)
		outcome = observability.OutcomeFailed
	}
	classification := observability.ClassificationContext{
		Bucket: observability.BucketAssetScan, EventName: eventName, RawSeverity: event.Severity,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, observability.ProducerKey(ActionScan), classification,
		observability.SourceScanner, event.Connector, observability.ProducerKey(event.Action),
	)
	if err != nil {
		return RuntimeV8LogOperation{}, fmt.Errorf("audit: classify scan summary: %w", err)
	}
	counts := scanV8SeverityCounts(result)
	build := func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, fmt.Errorf("audit: scan summary requires ordinary admission")
		}
		canonicalCorrelation := controlPlaneV8Correlation(event)
		builder, envelope, severity, logLevel, buildErr := runtimeV8FamilyBuildState(
			event, snapshot, observability.SourceScanner, "completed", canonicalCorrelation,
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		input := observability.LogScanCompletedInput{
			Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
			DefenseClawEvaluationID: optionalScanV8Identifier(correlation.EvaluationID),
			DefenseClawScanID:       scanID, DefenseClawScanScanner: result.Scanner,
			DefenseClawScanTargetRef:     optionalScanV8Identifier(result.Target),
			DefenseClawScanTargetType:    optionalScanV8Text(scanner.NormalizeTargetTypeEnum(result.EffectiveTargetType())),
			DefenseClawScanDurationMs:    observability.Present(result.Duration.Milliseconds()),
			DefenseClawScanFindingCount:  observability.Present(int64(len(result.Findings))),
			DefenseClawScanCriticalCount: observability.Present(counts[scanner.SeverityCritical]),
			DefenseClawScanHighCount:     observability.Present(counts[scanner.SeverityHigh]),
			DefenseClawScanMediumCount:   observability.Present(counts[scanner.SeverityMedium]),
			DefenseClawScanLowCount:      observability.Present(counts[scanner.SeverityLow]),
			DefenseClawScanInfoCount:     observability.Present(counts[scanner.SeverityInfo]),
			DefenseClawScanSeverityMax:   optionalScanV8Text(string(result.MaxSeverity())),
			DefenseClawScanVerdict:       optionalScanV8Text(scanner.NormalizeVerdictEnum(verdict)),
			DefenseClawScanExitCode:      observability.Present(int64(result.ExitCode)),
			DefenseClawScanErrorSummary:  optionalScanV8Text(result.ScanError),
		}
		var record observability.Record
		if eventName == observability.EventName(observability.TelemetryEventScanFailed) {
			failed := observability.LogScanFailedInput(input)
			record, buildErr = builder.BuildLogScanFailed(failed)
		} else {
			record, buildErr = builder.BuildLogScanCompleted(input)
		}
		return verifyRuntimeV8Record(record, buildErr, event, false)
	}
	return RuntimeV8LogOperation{
		ctx: contextWithLegacyEventProjection(ctx, event), metadata: metadata, build: build,
	}, nil
}

func newScanRuntimeV8GeneratedMetrics(
	event Event,
	result *scanner.ScanResult,
	scanID string,
	verdict string,
	correlation ScanCorrelation,
) ([]RuntimeV8GeneratedMetric, error) {
	if event.Timestamp.IsZero() || result == nil || result.Duration < 0 || !runtimeV8Identifier(scanID) {
		return nil, fmt.Errorf("audit: invalid generated scan metric input")
	}
	connector := correlation.Connector
	if strings.TrimSpace(connector) == "" {
		connector = "unknown"
	}
	targetType := result.EffectiveTargetType()
	durationMS := float64(result.Duration) / float64(time.Millisecond)
	counts := scanV8SeverityCounts(result)
	type metricInput struct {
		family                                                    observability.EventName
		valueInt                                                  int64
		valueFloat                                                float64
		scanner, targetType, verdict, connector, severity, ruleID string
	}
	inputs := []metricInput{
		{family: observability.EventName(observability.TelemetryInstrumentDefenseClawScanDuration), valueFloat: durationMS, scanner: result.Scanner},
		{family: observability.EventName(observability.TelemetryInstrumentDefenseClawScanCount), valueInt: 1, scanner: result.Scanner, targetType: targetType, verdict: verdict},
		{family: observability.EventName(observability.TelemetryInstrumentDefenseClawScanDuration), valueFloat: durationMS, scanner: result.Scanner, targetType: targetType},
	}
	for _, severity := range []scanner.Severity{
		scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium,
		scanner.SeverityLow, scanner.SeverityInfo,
	} {
		count := counts[severity]
		if count == 0 {
			continue
		}
		inputs = append(inputs,
			metricInput{family: observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings), valueInt: count, scanner: result.Scanner, targetType: targetType, connector: connector, severity: string(severity)},
			metricInput{family: observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge), valueInt: count, targetType: targetType, severity: string(severity)},
		)
	}
	for index := range result.Findings {
		finding := result.Findings[index]
		inputs = append(inputs, metricInput{
			family:   observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule),
			valueInt: 1, scanner: result.Scanner, connector: connector,
			severity: string(finding.Severity), ruleID: finding.RuleID,
		})
	}
	metrics := make([]RuntimeV8GeneratedMetric, 0, len(inputs)+1)
	auditMetric, err := newAuditEventRuntimeV8GeneratedMetric(event)
	if err != nil {
		return nil, err
	}
	metrics = append(metrics, auditMetric)
	for _, input := range inputs {
		input := input
		metrics = append(metrics, RuntimeV8GeneratedMetric{
			family: input.family,
			build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
				return buildScanRuntimeV8GeneratedMetric(snapshot, event, input)
			},
		})
	}
	return metrics, nil
}

func buildScanRuntimeV8GeneratedMetric(
	snapshot RuntimeV8BuildContext,
	event Event,
	input struct {
		family                                                    observability.EventName
		valueInt                                                  int64
		valueFloat                                                float64
		scanner, targetType, verdict, connector, severity, ruleID string
	},
) (observability.Record, error) {
	if snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
		return observability.Record{}, fmt.Errorf("audit: invalid v8 scan metric build context")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return event.Timestamp.UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	canonicalCorrelation := controlPlaneV8Correlation(event)
	envelope := observability.FamilyEnvelopeInput{
		ObservedAt: observability.Present(event.Timestamp.UTC()), Source: observability.SourceScanner,
		Connector: event.Connector, Action: event.Action, Phase: "metrics",
		Correlation: canonicalCorrelation,
		Provenance: observability.FamilyProvenanceInput{
			Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
		},
	}
	scannerName := optionalScanV8Text(input.scanner)
	targetType := optionalScanV8Text(input.targetType)
	severity := optionalScanV8Text(input.severity)
	switch input.family {
	case observability.EventName(observability.TelemetryInstrumentDefenseClawScanCount):
		return builder.BuildMetricDefenseClawScanCount(observability.MetricDefenseClawScanCountInput{
			Envelope: envelope, Value: input.valueInt, DefenseClawScanScanner: scannerName,
			DefenseClawMetricTargetType: targetType, DefenseClawMetricVerdict: optionalScanV8Text(input.verdict),
		})
	case observability.EventName(observability.TelemetryInstrumentDefenseClawScanDuration):
		return builder.BuildMetricDefenseClawScanDuration(observability.MetricDefenseClawScanDurationInput{
			Envelope: envelope, Value: input.valueFloat, DefenseClawScanScanner: scannerName,
			DefenseClawMetricTargetType: targetType,
		})
	case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings):
		return builder.BuildMetricDefenseClawScanFindings(observability.MetricDefenseClawScanFindingsInput{
			Envelope: envelope, Value: input.valueInt,
			DefenseClawConnectorSource: optionalScanV8Identifier(input.connector),
			DefenseClawScanScanner:     scannerName, DefenseClawSecuritySeverity: severity,
			DefenseClawMetricTargetType: targetType,
		})
	case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge):
		return builder.BuildMetricDefenseClawScanFindingsGauge(observability.MetricDefenseClawScanFindingsGaugeInput{
			Envelope: envelope, Value: input.valueInt,
			DefenseClawSecuritySeverity: severity, DefenseClawMetricTargetType: targetType,
		})
	case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule):
		return builder.BuildMetricDefenseClawScanFindingsByRule(observability.MetricDefenseClawScanFindingsByRuleInput{
			Envelope: envelope, Value: input.valueInt,
			DefenseClawConnectorSource: optionalScanV8Identifier(input.connector),
			DefenseClawFindingRuleID:   optionalScanV8Identifier(input.ruleID),
			DefenseClawScanScanner:     scannerName, DefenseClawSecuritySeverity: severity,
		})
	default:
		return observability.Record{}, fmt.Errorf("audit: unsupported generated scan metric")
	}
}

func scanV8SeverityCounts(result *scanner.ScanResult) map[scanner.Severity]int64 {
	counts := map[scanner.Severity]int64{
		scanner.SeverityCritical: 0, scanner.SeverityHigh: 0, scanner.SeverityMedium: 0,
		scanner.SeverityLow: 0, scanner.SeverityInfo: 0,
	}
	for index := range result.Findings {
		counts[result.Findings[index].Severity]++
	}
	return counts
}

func optionalScanV8Identifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if !runtimeV8Identifier(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalScanV8Text(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || len(value) > 4096 {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func optionalScanV8StringSlice(values []string) observability.Optional[[]string] {
	if len(values) == 0 || len(values) > 256 {
		return observability.Absent[[]string]()
	}
	copyValues := append([]string(nil), values...)
	for _, value := range copyValues {
		if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || len(value) > 4096 {
			return observability.Absent[[]string]()
		}
	}
	return observability.Present(copyValues)
}

func optionalScanV8DecisionPath(value json.RawMessage) observability.Optional[string] {
	if len(value) == 0 || len(value) > 65_536 || !json.Valid(value) {
		return observability.Absent[string]()
	}
	return observability.Present(string(value))
}
