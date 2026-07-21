// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const aiDiscoveryV8Producer = "inventory.ai_discovery"

type aiDiscoveryV8Runtime interface {
	sidecarRuntimeEmitter
	otlpGeneratedMetricRuntime
	StartAIDiscoveryTrace(
		context.Context,
		observability.SpanAIDiscoveryInput,
	) (context.Context, *observabilityruntime.AIDiscoveryTrace, error)
}

type aiDiscoveryV8Adapter struct{ runtime aiDiscoveryV8Runtime }

func newAIDiscoveryV8Adapter(emitter sidecarRuntimeEmitter) inventory.AIDiscoveryObservabilityV8 {
	runtime, ok := emitter.(aiDiscoveryV8Runtime)
	if !ok || runtime == nil {
		return nil
	}
	return &aiDiscoveryV8Adapter{runtime: runtime}
}

func (adapter *aiDiscoveryV8Adapter) StartScan(
	ctx context.Context,
	start inventory.AIDiscoveryV8ScanStart,
) (context.Context, inventory.AIDiscoveryV8ScanTrace, error) {
	if adapter == nil || adapter.runtime == nil || ctx == nil || start.StartedAt.IsZero() {
		return ctx, nil, &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	input := observability.SpanAIDiscoveryInput{
		Envelope:                          aiDiscoveryV8Envelope(ctx, "scan"),
		Outcome:                           observability.OutcomeFailed,
		Kind:                              "INTERNAL",
		StartTimeUnixNano:                 uint64(start.StartedAt.UTC().UnixNano()),
		Status:                            observability.NewTraceStatusOK(),
		DefenseClawAIDiscoveryScanID:      aiDiscoveryV8Optional(start.ScanID),
		DefenseClawAIDiscoverySource:      aiDiscoveryV8Optional(start.Source),
		DefenseClawAIDiscoveryPrivacyMode: aiDiscoveryV8Optional(start.PrivacyMode),
		DefenseClawRunID:                  aiDiscoveryV8Optional(gatewaylog.ProcessRunID()),
		ConditionOperationTerminal:        true,
	}
	startedContext, generated, err := adapter.runtime.StartAIDiscoveryTrace(ctx, input)
	if err != nil || generated == nil {
		return startedContext, nil, err
	}
	return startedContext, &aiDiscoveryV8ScanTrace{generated: generated, input: input}, nil
}

type aiDiscoveryV8ScanTrace struct {
	generated *observabilityruntime.AIDiscoveryTrace
	input     observability.SpanAIDiscoveryInput
}

type aiDiscoveryV8DetectorTrace struct {
	generated *observabilityruntime.AIDiscoveryDetectorTrace
	input     observability.SpanAIDiscoveryDetectorInput
}

func (trace *aiDiscoveryV8ScanTrace) StartDetector(
	start inventory.AIDiscoveryV8DetectorStart,
) (inventory.AIDiscoveryV8DetectorTrace, error) {
	if trace == nil || trace.generated == nil || start.StartedAt.IsZero() ||
		!observability.IsStableToken(start.Detector) {
		return nil, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	input := observability.SpanAIDiscoveryDetectorInput{
		Envelope:                       aiDiscoveryV8Envelope(trace.generated.Context(), "detector"),
		Outcome:                        observability.OutcomeFailed,
		Kind:                           "INTERNAL",
		StartTimeUnixNano:              uint64(start.StartedAt.UTC().UnixNano()),
		Status:                         observability.NewTraceStatusOK(),
		DefenseClawAIDiscoveryScanID:   aiDiscoveryV8Optional(start.ScanID),
		DefenseClawAIDiscoveryDetector: start.Detector,
		DefenseClawRunID:               aiDiscoveryV8Optional(gatewaylog.ProcessRunID()),
		ConditionOperationTerminal:     true,
	}
	generated, err := trace.generated.StartDetector(input)
	if err != nil || generated == nil {
		return nil, err
	}
	return &aiDiscoveryV8DetectorTrace{generated: generated, input: input}, nil
}

func (trace *aiDiscoveryV8DetectorTrace) End(result inventory.AIDiscoveryV8DetectorResult) error {
	if trace == nil || trace.generated == nil || result.EndedAt.IsZero() ||
		result.DurationMs < 0 || result.SignalsTotal < 0 || result.FilesScanned < 0 {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	input := trace.input
	input.EndTimeUnixNano = uint64(result.EndedAt.UTC().UnixNano())
	input.Outcome = observability.OutcomeCompleted
	input.DefenseClawAIDiscoveryDurationMs = observability.Present(result.DurationMs)
	input.DefenseClawAIDiscoverySignalsTotal = observability.Present(result.SignalsTotal)
	input.DefenseClawAIDiscoveryFilesScanned = observability.Present(result.FilesScanned)
	if result.Failed {
		input.Outcome = observability.OutcomeFailed
		input.Status = observability.NewTraceStatusError(observability.Present("detector_error"))
		input.ErrorType = observability.Present("detector_error")
		input.ConditionTechnicalFailure = true
	}
	return trace.generated.End(input)
}

func (trace *aiDiscoveryV8DetectorTrace) Abort() {
	if trace != nil && trace.generated != nil {
		trace.generated.Abort()
	}
}

func (trace *aiDiscoveryV8ScanTrace) End(report inventory.AIDiscoveryReport) error {
	if trace == nil || trace.generated == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	summary := report.Summary
	if !aiDiscoveryV8SummaryValid(summary) {
		trace.generated.Abort()
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	input := trace.input
	endedAt := time.Now().UTC()
	input.EndTimeUnixNano = uint64(endedAt.UnixNano())
	input.Outcome = observability.OutcomeCompleted
	input.DefenseClawAIDiscoveryScanID = aiDiscoveryV8Optional(summary.ScanID)
	input.DefenseClawAIDiscoverySource = aiDiscoveryV8Optional(summary.Source)
	input.DefenseClawAIDiscoveryPrivacyMode = aiDiscoveryV8Optional(summary.PrivacyMode)
	input.DefenseClawAIDiscoveryResult = aiDiscoveryV8Optional(summary.Result)
	input.DefenseClawAIDiscoveryDurationMs = observability.Present(summary.DurationMs)
	input.DefenseClawAIDiscoverySignalsTotal = observability.Present(int64(summary.TotalSignals))
	input.DefenseClawAIDiscoveryActiveSignals = observability.Present(int64(summary.ActiveSignals))
	input.DefenseClawAIDiscoveryNewSignals = observability.Present(int64(summary.NewSignals))
	input.DefenseClawAIDiscoveryChangedSignals = observability.Present(int64(summary.ChangedSignals))
	input.DefenseClawAIDiscoveryGoneSignals = observability.Present(int64(summary.GoneSignals))
	input.DefenseClawAIDiscoveryFilesScanned = observability.Present(int64(summary.FilesScanned))
	input.DefenseClawAIDiscoveryDedupeSuppressed = observability.Present(int64(summary.DedupeSuppressed))
	input.DefenseClawAIDiscoveryErrors = observability.Present(int64(summary.Errors))
	if summary.Errors > 0 || summary.Result == "partial" {
		input.Outcome = observability.OutcomePartial
		input.Status = observability.NewTraceStatusError(observability.Present("detector_error"))
		input.ErrorType = observability.Present("detector_error")
		input.ConditionTechnicalFailure = true
	}
	return trace.generated.End(input)
}

func (trace *aiDiscoveryV8ScanTrace) Abort() {
	if trace != nil && trace.generated != nil {
		trace.generated.Abort()
	}
}

func (adapter *aiDiscoveryV8Adapter) EmitReport(
	ctx context.Context,
	report inventory.AIDiscoveryReport,
	components []inventory.AIDiscoveryV8ComponentObservation,
) error {
	if adapter == nil || adapter.runtime == nil || ctx == nil || !aiDiscoveryV8SummaryValid(report.Summary) {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	logErr := adapter.emitSummaryLog(ctx, report.Summary)
	for _, signal := range report.Signals {
		// Managed enterprise receives a complete endpoint snapshot on every
		// cadence, including steady-state `seen` observations. Other modes keep
		// the historical lifecycle-delta contract.
		isDelta := signal.State == inventory.AIStateNew ||
			signal.State == inventory.AIStateChanged || signal.State == inventory.AIStateGone
		if !isDelta && !(ManagedEnterpriseActive() && signal.State == inventory.AIStateSeen) {
			continue
		}
		if err := adapter.emitSignalLog(ctx, report.Summary, signal); err != nil && logErr == nil {
			logErr = err
		}
	}
	for _, component := range components {
		if !component.HasLifecycleChange {
			continue
		}
		if err := adapter.emitComponentConfidenceLog(ctx, report.Summary, component); err != nil && logErr == nil {
			logErr = err
		}
	}
	metricErr := adapter.emitMetrics(ctx, report, components)
	if logErr != nil {
		return logErr
	}
	return metricErr
}

func (adapter *aiDiscoveryV8Adapter) emitSignalLog(
	ctx context.Context,
	summary inventory.AIDiscoverySummary,
	signal inventory.AISignal,
) error {
	eventName := observability.EventName("ai_component.changed")
	switch signal.State {
	case inventory.AIStateNew:
		eventName = "ai_component.discovered"
	case inventory.AIStateChanged:
		eventName = "ai_component.changed"
	case inventory.AIStateSeen:
		eventName = "ai_component.observed"
	case inventory.AIStateGone:
		eventName = "ai_component.removed"
	default:
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	if signal.SignalID == "" || signal.Category == "" {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: eventName, RawSeverity: "INFO",
		},
		observability.SourceSystem,
		"",
		observability.ProducerKey("ai_discovery"),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		base := observability.LogAIComponentChangedInput{
			Envelope:                         aiDiscoveryV8EmitEnvelope(ctx, snapshot, "signal"),
			Severity:                         observability.Present(observability.SeverityInfo),
			LogLevel:                         observability.Present(observability.LogLevelInfo),
			DefenseClawAIComponentID:         signal.SignalID,
			DefenseClawAIComponentType:       signal.Category,
			DefenseClawAIDiscoveryDetector:   aiDiscoveryV8OptionalText(signal.Detector),
			DefenseClawAIDiscoverySignal:     aiDiscoveryV8OptionalText(signal.SignatureID),
			DefenseClawAIDiscoveryConfidence: observability.Present(aiDiscoveryV8Clamp(signal.Confidence)),
			DefenseClawAIDiscoveryScanID:     aiDiscoveryV8Optional(summary.ScanID),
			DefenseClawAIDiscoverySignalID:   aiDiscoveryV8Optional(signal.SignalID),
			DefenseClawAIDiscoverySource:     aiDiscoveryV8Optional(summary.Source),
			DefenseClawAIComponentVendor:     aiDiscoveryV8OptionalText(signal.Vendor),
			DefenseClawAIComponentProduct:    aiDiscoveryV8OptionalText(signal.Product),
		}
		switch eventName {
		case "ai_component.discovered":
			return builder.BuildLogAIComponentDiscovered(observability.LogAIComponentDiscoveredInput(base))
		case "ai_component.changed":
			return builder.BuildLogAIComponentChanged(base)
		case "ai_component.observed":
			return builder.BuildLogAIComponentObserved(observability.LogAIComponentObservedInput{
				Envelope:                         base.Envelope,
				Severity:                         base.Severity,
				LogLevel:                         base.LogLevel,
				DefenseClawAIComponentID:         base.DefenseClawAIComponentID,
				DefenseClawAIComponentType:       base.DefenseClawAIComponentType,
				DefenseClawAIDiscoveryDetector:   base.DefenseClawAIDiscoveryDetector,
				DefenseClawAIDiscoverySignal:     base.DefenseClawAIDiscoverySignal,
				DefenseClawAIDiscoveryConfidence: base.DefenseClawAIDiscoveryConfidence,
				DefenseClawAIDiscoveryScanID:     base.DefenseClawAIDiscoveryScanID,
				DefenseClawAIDiscoverySignalID:   base.DefenseClawAIDiscoverySignalID,
				DefenseClawAIDiscoverySource:     base.DefenseClawAIDiscoverySource,
				DefenseClawAIComponentVendor:     base.DefenseClawAIComponentVendor,
				DefenseClawAIComponentProduct:    base.DefenseClawAIComponentProduct,
			})
		case "ai_component.removed":
			return builder.BuildLogAIComponentRemoved(observability.LogAIComponentRemovedInput(base))
		default:
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
	})
	return err
}

func (adapter *aiDiscoveryV8Adapter) emitComponentConfidenceLog(
	ctx context.Context,
	summary inventory.AIDiscoverySummary,
	component inventory.AIDiscoveryV8ComponentObservation,
) error {
	if component.ComponentID == "" || component.ComponentType == "" {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	severity, logLevel := observability.SeverityInfo, observability.LogLevelInfo
	if component.Metrics.IdentityScore >= .7 && component.Metrics.PresenceScore <= .2 {
		severity, logLevel = observability.SeverityMedium, observability.LogLevelWarn
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket:    observability.BucketAIDiscovery,
			EventName: "ai_component.confidence.changed", RawSeverity: string(logLevel),
		},
		observability.SourceSystem,
		"",
		observability.ProducerKey("ai_discovery"),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		metrics := component.Metrics
		return builder.BuildLogAIComponentConfidenceChanged(observability.LogAIComponentConfidenceChangedInput{
			Envelope: aiDiscoveryV8EmitEnvelope(ctx, snapshot, "confidence"),
			Severity: observability.Present(severity), LogLevel: observability.Present(logLevel),
			DefenseClawAIComponentID:             component.ComponentID,
			DefenseClawAIComponentType:           component.ComponentType,
			DefenseClawAIDiscoveryScanID:         aiDiscoveryV8Optional(summary.ScanID),
			DefenseClawAIDiscoverySource:         aiDiscoveryV8Optional(summary.Source),
			DefenseClawAIComponentIdentityScore:  observability.Present(aiDiscoveryV8Clamp(metrics.IdentityScore)),
			DefenseClawAIComponentIdentityBand:   aiDiscoveryV8OptionalText(metrics.IdentityBand),
			DefenseClawAIComponentPresenceScore:  observability.Present(aiDiscoveryV8Clamp(metrics.PresenceScore)),
			DefenseClawAIComponentPresenceBand:   aiDiscoveryV8OptionalText(metrics.PresenceBand),
			DefenseClawAIComponentInstallCount:   observability.Present(int64(metrics.InstallCount)),
			DefenseClawAIComponentWorkspaceCount: observability.Present(int64(metrics.WorkspaceCount)),
			DefenseClawAIComponentDetectorCount:  observability.Present(int64(metrics.DetectorCount)),
			DefenseClawAIComponentPolicyVersion:  observability.Present(int64(metrics.PolicyVersion)),
		})
	})
	return err
}

func (adapter *aiDiscoveryV8Adapter) emitSummaryLog(
	ctx context.Context,
	summary inventory.AIDiscoverySummary,
) error {
	severity := "INFO"
	canonicalSeverity := observability.SeverityInfo
	logLevel := observability.LogLevelInfo
	outcome := observability.OutcomeCompleted
	if summary.Result == "partial" || summary.Errors > 0 {
		severity = "WARN"
		canonicalSeverity = observability.SeverityMedium
		logLevel = observability.LogLevelWarn
		outcome = observability.OutcomePartial
	}
	classification := observability.ClassificationContext{
		Bucket:    observability.BucketAIDiscovery,
		EventName: "ai.discovery.completed", RawSeverity: severity,
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		classification,
		observability.SourceSystem,
		"",
		observability.ProducerKey("ai_discovery"),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIDiscoveryCompleted(observability.LogAIDiscoveryCompletedInput{
			Envelope: aiDiscoveryV8EmitEnvelope(ctx, snapshot, "scan"),
			Severity: observability.Present(canonicalSeverity), LogLevel: observability.Present(logLevel),
			Outcome:                                outcome,
			DefenseClawAIDiscoveryScanID:           summary.ScanID,
			DefenseClawAIDiscoverySource:           summary.Source,
			DefenseClawAIDiscoveryPrivacyMode:      summary.PrivacyMode,
			DefenseClawAIDiscoveryResult:           summary.Result,
			DefenseClawAIDiscoveryDurationMs:       summary.DurationMs,
			DefenseClawAIDiscoverySignalsTotal:     int64(summary.TotalSignals),
			DefenseClawAIDiscoveryActiveSignals:    int64(summary.ActiveSignals),
			DefenseClawAIDiscoveryNewSignals:       int64(summary.NewSignals),
			DefenseClawAIDiscoveryChangedSignals:   int64(summary.ChangedSignals),
			DefenseClawAIDiscoveryGoneSignals:      int64(summary.GoneSignals),
			DefenseClawAIDiscoveryFilesScanned:     int64(summary.FilesScanned),
			DefenseClawAIDiscoveryDedupeSuppressed: int64(summary.DedupeSuppressed),
			DefenseClawAIDiscoveryErrors:           int64(summary.Errors),
		})
	})
	return err
}

type aiDiscoveryV8MetricBuild func(
	*observability.FamilyBuilder,
	observability.FamilyEnvelopeInput,
) (observability.Record, error)

func (adapter *aiDiscoveryV8Adapter) recordMetric(
	ctx context.Context,
	family string,
	build aiDiscoveryV8MetricBuild,
) error {
	_, err := adapter.runtime.RecordGeneratedMetric(ctx, observability.EventName(family), func(
		snapshot observabilityruntime.EmitContext,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return build(builder, aiDiscoveryV8EmitEnvelope(ctx, snapshot, "metrics"))
	})
	return err
}

// RecordSQLiteBusyMetric preserves the inventory database contention counter
// without exposing the runtime's OTel provider to the inventory package.
func (adapter *aiDiscoveryV8Adapter) RecordSQLiteBusyMetric(
	ctx context.Context,
	operation string,
) error {
	operation = strings.TrimSpace(operation)
	if adapter == nil || adapter.runtime == nil || ctx == nil || operation == "" ||
		len(operation) > 256 {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	return adapter.recordMetric(
		ctx,
		observability.TelemetryInstrumentDefenseClawSqliteBusyRetries,
		func(
			builder *observability.FamilyBuilder,
			envelope observability.FamilyEnvelopeInput,
		) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSqliteBusyRetries(
				observability.MetricDefenseClawSqliteBusyRetriesInput{
					Envelope: envelope, Value: 1,
					DefenseClawMetricOperation: observability.Present(operation),
				},
			)
		},
	)
}

type aiDiscoveryV8MetricRecorder struct {
	adapter *aiDiscoveryV8Adapter
	ctx     context.Context
	failed  bool
}

func (recorder *aiDiscoveryV8MetricRecorder) record(family string, build aiDiscoveryV8MetricBuild) {
	if recorder == nil || recorder.adapter == nil || recorder.ctx == nil {
		if recorder != nil {
			recorder.failed = true
		}
		return
	}
	if err := recorder.adapter.recordMetric(recorder.ctx, family, build); err != nil {
		recorder.failed = true
	}
}

func (recorder *aiDiscoveryV8MetricRecorder) result() error {
	if recorder != nil && recorder.failed {
		return &sidecarObservabilityError{code: sidecarObservabilityEmitFailed}
	}
	return nil
}

func (adapter *aiDiscoveryV8Adapter) emitMetrics(
	ctx context.Context,
	report inventory.AIDiscoveryReport,
	components []inventory.AIDiscoveryV8ComponentObservation,
) error {
	summary := report.Summary
	source := observability.Present(aiDiscoveryV8MetricLabel(summary.Source, "sidecar"))
	privacy := observability.Present(aiDiscoveryV8MetricLabel(summary.PrivacyMode, "enhanced"))
	result := observability.Present(aiDiscoveryV8MetricLabel(summary.Result, "ok"))
	recorder := &aiDiscoveryV8MetricRecorder{adapter: adapter, ctx: ctx}
	recorder.record(observability.TelemetryInstrumentDefenseClawAIDiscoveryRuns, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAIDiscoveryRuns(observability.MetricDefenseClawAIDiscoveryRunsInput{Envelope: envelope, Value: 1, DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
	})
	recorder.record(observability.TelemetryInstrumentDefenseClawAIDiscoveryDuration, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAIDiscoveryDuration(observability.MetricDefenseClawAIDiscoveryDurationInput{Envelope: envelope, Value: float64(summary.DurationMs), DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
	})
	recorder.record(observability.TelemetryInstrumentDefenseClawAIDiscoveryActiveSignals, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAIDiscoveryActiveSignals(observability.MetricDefenseClawAIDiscoveryActiveSignalsInput{Envelope: envelope, Value: int64(summary.ActiveSignals), DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricSource: source})
	})
	optionalCount := func(value int, family string, build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput, int64) (observability.Record, error)) {
		if value <= 0 {
			return
		}
		recorder.record(family, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return build(builder, envelope, int64(value))
		})
	}
	optionalCount(summary.FilesScanned, observability.TelemetryInstrumentDefenseClawAIDiscoveryFilesScanned, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAIDiscoveryFilesScanned(observability.MetricDefenseClawAIDiscoveryFilesScannedInput{Envelope: envelope, Value: value, DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
	})
	optionalCount(summary.DedupeSuppressed, observability.TelemetryInstrumentDefenseClawAIDiscoveryDedupeSuppressed, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput, value int64) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAIDiscoveryDedupeSuppressed(observability.MetricDefenseClawAIDiscoveryDedupeSuppressedInput{Envelope: envelope, Value: value, DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
	})
	emitSummarySignalCountsV8(recorder, summary, source, privacy, result)
	if summary.Errors > 0 {
		recorder.record(observability.TelemetryInstrumentDefenseClawAIDiscoveryErrors, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAIDiscoveryErrors(observability.MetricDefenseClawAIDiscoveryErrorsInput{Envelope: envelope, Value: 1, DefenseClawMetricDetector: observability.Present("scan"), DefenseClawMetricReason: observability.Present("partial")})
		})
	}
	for _, signal := range report.Signals {
		if signal.State != inventory.AIStateNew && signal.State != inventory.AIStateChanged && signal.State != inventory.AIStateGone {
			continue
		}
		emitSignalMetricsV8(recorder, signal)
	}
	for _, component := range components {
		emitComponentMetricsV8(recorder, component.Metrics)
	}
	return recorder.result()
}

func emitSummarySignalCountsV8(recorder *aiDiscoveryV8MetricRecorder, summary inventory.AIDiscoverySummary, source, privacy, result observability.Optional[string]) {
	for _, item := range []struct {
		value  int
		family string
	}{{summary.NewSignals, observability.TelemetryInstrumentDefenseClawAIDiscoveryNewSignals}, {summary.GoneSignals, observability.TelemetryInstrumentDefenseClawAIDiscoveryGoneSignals}} {
		if item.value <= 0 {
			continue
		}
		value := int64(item.value)
		recorder.record(item.family, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			common := observability.MetricDefenseClawAIDiscoveryNewSignalsInput{Envelope: envelope, Value: value, DefenseClawMetricPrivacyMode: privacy, DefenseClawMetricResult: result, DefenseClawMetricSource: source}
			if item.family == observability.TelemetryInstrumentDefenseClawAIDiscoveryNewSignals {
				return builder.BuildMetricDefenseClawAIDiscoveryNewSignals(common)
			}
			return builder.BuildMetricDefenseClawAIDiscoveryGoneSignals(observability.MetricDefenseClawAIDiscoveryGoneSignalsInput(common))
		})
	}
}

func emitSignalMetricsV8(recorder *aiDiscoveryV8MetricRecorder, signal inventory.AISignal) {
	labels := observability.MetricDefenseClawAIDiscoverySignalsInput{
		Value:                             1,
		DefenseClawMetricSignalCategory:   observability.Present(aiDiscoveryV8MetricLabel(signal.Category, "unknown")),
		DefenseClawMetricAIVendor:         observability.Present(aiDiscoveryV8MetricLabel(signal.Vendor, "unknown")),
		DefenseClawMetricAIProduct:        observability.Present(aiDiscoveryV8MetricLabel(signal.Product, "unknown")),
		DefenseClawAIDiscoverySignalState: observability.Present(aiDiscoveryV8MetricLabel(signal.State, "seen")),
		DefenseClawMetricDetector:         observability.Present(aiDiscoveryV8MetricLabel(signal.Detector, "unknown")),
		DefenseClawMetricConfidence:       observability.Present(aiDiscoveryV8ConfidenceBucket(signal.Confidence)),
	}
	recorder.record(observability.TelemetryInstrumentDefenseClawAIDiscoverySignals, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		labels.Envelope = envelope
		return builder.BuildMetricDefenseClawAIDiscoverySignals(labels)
	})
	var family string
	switch signal.State {
	case inventory.AIStateNew, inventory.AIStateChanged:
		family = observability.TelemetryInstrumentDefenseClawAIDiscoveryNewSignals
	case inventory.AIStateGone:
		family = observability.TelemetryInstrumentDefenseClawAIDiscoveryGoneSignals
	default:
		return
	}
	recorder.record(family, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		if family == observability.TelemetryInstrumentDefenseClawAIDiscoveryNewSignals {
			input := observability.MetricDefenseClawAIDiscoveryNewSignalsInput{
				Envelope: envelope, Value: labels.Value,
				DefenseClawMetricAIProduct:        labels.DefenseClawMetricAIProduct,
				DefenseClawMetricAIVendor:         labels.DefenseClawMetricAIVendor,
				DefenseClawMetricConfidence:       labels.DefenseClawMetricConfidence,
				DefenseClawMetricDetector:         labels.DefenseClawMetricDetector,
				DefenseClawMetricSignalCategory:   labels.DefenseClawMetricSignalCategory,
				DefenseClawAIDiscoverySignalState: labels.DefenseClawAIDiscoverySignalState,
			}
			return builder.BuildMetricDefenseClawAIDiscoveryNewSignals(input)
		}
		input := observability.MetricDefenseClawAIDiscoveryGoneSignalsInput{
			Envelope: envelope, Value: labels.Value,
			DefenseClawMetricAIProduct:        labels.DefenseClawMetricAIProduct,
			DefenseClawMetricAIVendor:         labels.DefenseClawMetricAIVendor,
			DefenseClawMetricConfidence:       labels.DefenseClawMetricConfidence,
			DefenseClawMetricDetector:         labels.DefenseClawMetricDetector,
			DefenseClawMetricSignalCategory:   labels.DefenseClawMetricSignalCategory,
			DefenseClawAIDiscoverySignalState: labels.DefenseClawAIDiscoverySignalState,
		}
		return builder.BuildMetricDefenseClawAIDiscoveryGoneSignals(input)
	})
}

func emitComponentMetricsV8(recorder *aiDiscoveryV8MetricRecorder, component telemetry.AIComponentConfidenceAttrs) {
	ecosystem := observability.Present(aiDiscoveryV8MetricLabel(component.Ecosystem, "unknown"))
	name := observability.Present(aiDiscoveryV8MetricLabel(component.Name, "unknown"))
	framework := observability.Present(aiDiscoveryV8MetricLabel(component.Framework, "unknown"))
	identityBand := observability.Present(aiDiscoveryV8MetricLabel(component.IdentityBand, "unknown"))
	presenceBand := observability.Present(aiDiscoveryV8MetricLabel(component.PresenceBand, "unknown"))
	metrics := []struct {
		family string
		build  aiDiscoveryV8MetricBuild
	}{
		{observability.TelemetryInstrumentDefenseClawAIComponentsObservations, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawAIComponentsObservations(observability.MetricDefenseClawAIComponentsObservationsInput{Envelope: e, Value: 1, DefenseClawMetricEcosystem: ecosystem, DefenseClawMetricName: name, DefenseClawMetricIdentityBand: identityBand, DefenseClawMetricPresenceBand: presenceBand})
		}},
		{observability.TelemetryInstrumentDefenseClawAIComponentsInstalls, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawAIComponentsInstalls(observability.MetricDefenseClawAIComponentsInstallsInput{Envelope: e, Value: int64(component.InstallCount), DefenseClawMetricEcosystem: ecosystem, DefenseClawMetricName: name})
		}},
		{observability.TelemetryInstrumentDefenseClawAIComponentsWorkspaces, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawAIComponentsWorkspaces(observability.MetricDefenseClawAIComponentsWorkspacesInput{Envelope: e, Value: int64(component.WorkspaceCount), DefenseClawMetricEcosystem: ecosystem, DefenseClawMetricName: name})
		}},
		{observability.TelemetryInstrumentDefenseClawAIConfidenceIdentityScore, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawAIConfidenceIdentityScore(observability.MetricDefenseClawAIConfidenceIdentityScoreInput{Envelope: e, Value: aiDiscoveryV8Clamp(component.IdentityScore), DefenseClawMetricEcosystem: ecosystem, DefenseClawMetricName: name, DefenseClawMetricFramework: framework})
		}},
		{observability.TelemetryInstrumentDefenseClawAIConfidencePresenceScore, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawAIConfidencePresenceScore(observability.MetricDefenseClawAIConfidencePresenceScoreInput{Envelope: e, Value: aiDiscoveryV8Clamp(component.PresenceScore), DefenseClawMetricEcosystem: ecosystem, DefenseClawMetricName: name, DefenseClawMetricFramework: framework})
		}},
	}
	for _, metric := range metrics {
		recorder.record(metric.family, metric.build)
	}
}

func aiDiscoveryV8Envelope(ctx context.Context, phase string) observability.FamilyEnvelopeInput {
	correlation := observability.Correlation{RunID: gatewaylog.ProcessRunID(), SidecarInstanceID: gatewaylog.SidecarInstanceID()}
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		correlation.TraceID = spanContext.TraceID().String()
		correlation.SpanID = spanContext.SpanID().String()
	}
	return observability.FamilyEnvelopeInput{Source: observability.SourceSystem, Action: "ai_discovery", Phase: phase, Correlation: correlation, Provenance: observability.FamilyProvenanceInput{Producer: aiDiscoveryV8Producer}}
}

func aiDiscoveryV8EmitEnvelope(ctx context.Context, snapshot observabilityruntime.EmitContext, phase string) observability.FamilyEnvelopeInput {
	envelope := aiDiscoveryV8Envelope(ctx, phase)
	envelope.Provenance.BinaryVersion = version.Current().BinaryVersion
	envelope.Provenance.ConfigGeneration = int64(snapshot.Generation())
	envelope.Provenance.ConfigDigest = snapshot.Digest()
	return envelope
}

func aiDiscoveryV8Builder() (*observability.FamilyBuilder, error) {
	return observability.NewFamilyBuilder(observability.ClockFunc(func() time.Time { return time.Now().UTC() }), observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }))
}

func aiDiscoveryV8Optional(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || !observability.IsStableToken(value) {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func aiDiscoveryV8OptionalText(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 4096 {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func aiDiscoveryV8SummaryValid(summary inventory.AIDiscoverySummary) bool {
	return aiDiscoveryV8Optional(summary.ScanID).IsPresent() && aiDiscoveryV8Optional(summary.Source).IsPresent() && aiDiscoveryV8Optional(summary.PrivacyMode).IsPresent() && (summary.Result == "ok" || summary.Result == "partial") && summary.DurationMs >= 0 && summary.TotalSignals >= 0 && summary.ActiveSignals >= 0 && summary.NewSignals >= 0 && summary.ChangedSignals >= 0 && summary.GoneSignals >= 0 && summary.FilesScanned >= 0 && summary.DedupeSuppressed >= 0 && summary.Errors >= 0
}

func aiDiscoveryV8MetricLabel(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	if len(value) > 80 {
		value = value[:80]
	}
	return value
}
func aiDiscoveryV8ConfidenceBucket(value float64) string {
	if value >= .9 {
		return "high"
	}
	if value >= .7 {
		return "medium"
	}
	return "low"
}
func aiDiscoveryV8Clamp(value float64) float64 {
	if math.IsNaN(value) || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

var _ inventory.AIDiscoveryObservabilityV8 = (*aiDiscoveryV8Adapter)(nil)
var _ inventory.AIDiscoveryV8ScanTrace = (*aiDiscoveryV8ScanTrace)(nil)
var _ inventory.AIDiscoveryV8DetectorTrace = (*aiDiscoveryV8DetectorTrace)(nil)
