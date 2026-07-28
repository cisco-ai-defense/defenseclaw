// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const agentDiscoveryV8Producer = "gateway.agent_discovery"

type agentDiscoveryTelemetrySummary struct {
	source         string
	cacheHit       bool
	result         string
	durationMs     int64
	agentsTotal    int
	installedTotal int
}

func (a *APIServer) emitAgentDiscoverySummary(ctx context.Context, summary agentDiscoveryTelemetrySummary) {
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil || ctx == nil {
		return
	}
	a.emitAgentDiscoverySummaryV8(ctx, emitter, summary)
	a.recordAgentDiscoverySummaryMetricsV8(ctx, emitter, summary)
}

func (a *APIServer) emitAgentDiscoverySignal(ctx context.Context, reportSource, connector string, signal agentDiscoverySignal, probeStatus string) {
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil || ctx == nil {
		return
	}
	source := agentDiscoverySource(reportSource)
	a.emitAgentDiscoverySignalV8(ctx, emitter, source, connector, signal, probeStatus)
	a.recordAgentDiscoverySignalMetricsV8(ctx, emitter, source, connector, signal, probeStatus)
}

func (a *APIServer) emitAgentDiscoveryError(ctx context.Context, reportSource, connector, reason string) {
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil || ctx == nil {
		return
	}
	metricRuntime, ok := emitter.(otlpGeneratedMetricRuntime)
	if !ok {
		return
	}
	_ = recordAgentDiscoveryMetricV8(ctx, metricRuntime, observability.TelemetryInstrumentDefenseClawAgentDiscoveryErrors, agentDiscoverySource(reportSource), connector, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAgentDiscoveryErrors(observability.MetricDefenseClawAgentDiscoveryErrorsInput{
			Envelope: envelope, Value: 1,
			DefenseClawConnectorSource: observability.Present(aiDiscoveryV8MetricLabel(connector, "unknown")),
			DefenseClawMetricReason:    observability.Present(aiDiscoveryV8MetricLabel(reason, "other")),
		})
	})
}

func (a *APIServer) emitAgentDiscoverySummaryV8(ctx context.Context, emitter sidecarRuntimeEmitter, summary agentDiscoveryTelemetrySummary) {
	completed := summary.result == "ok"
	eventName := observability.EventName("agent.discovery.rejected")
	severity := "WARN"
	source := agentDiscoverySource(summary.source)
	if completed {
		eventName, severity = "agent.discovery.completed", "INFO"
	}
	// Agent-discovery is an agent.lifecycle occurrence, so it deliberately uses
	// the contextual gateway lifecycle authority. The narrower ai_discovery
	// classification is fixed to the ai.discovery bucket and owns continuous
	// component-inventory events, not connector installation discovery.
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("lifecycle"),
		observability.ClassificationContext{Bucket: observability.BucketAgentLifecycle, EventName: eventName, RawSeverity: severity},
		source,
		"",
		observability.ProducerKey("agent_discovery"),
	)
	if err != nil {
		return
	}
	_, _ = emitter.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := agentDiscoveryEmitEnvelope(ctx, snapshot, source, "summary")
		if completed {
			return builder.BuildLogAgentDiscoveryCompleted(observability.LogAgentDiscoveryCompletedInput{
				Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
				LogLevel: observability.Present(observability.LogLevelInfo), Outcome: observability.OutcomeCompleted,
				DefenseClawAgentDiscoverySource:         summary.source,
				DefenseClawAgentDiscoveryCacheHit:       summary.cacheHit,
				DefenseClawAgentDiscoveryResult:         summary.result,
				DefenseClawAgentDiscoveryDurationMs:     summary.durationMs,
				DefenseClawAgentDiscoveryAgentsTotal:    int64(summary.agentsTotal),
				DefenseClawAgentDiscoveryInstalledTotal: int64(summary.installedTotal),
			})
		}
		duration := observability.Absent[int64]()
		if summary.durationMs >= 0 {
			duration = observability.Present(summary.durationMs)
		}
		return builder.BuildLogAgentDiscoveryRejected(observability.LogAgentDiscoveryRejectedInput{
			Envelope: envelope, Severity: observability.Present(observability.SeverityMedium),
			LogLevel: observability.Present(observability.LogLevelWarn), Outcome: observability.OutcomeRejected,
			DefenseClawAgentDiscoverySource:         summary.source,
			DefenseClawAgentDiscoveryCacheHit:       observability.Present(summary.cacheHit),
			DefenseClawAgentDiscoveryResult:         summary.result,
			DefenseClawAgentDiscoveryDurationMs:     duration,
			DefenseClawAgentDiscoveryAgentsTotal:    observability.Present(int64(summary.agentsTotal)),
			DefenseClawAgentDiscoveryInstalledTotal: observability.Present(int64(summary.installedTotal)),
		})
	})
}

func (a *APIServer) emitAgentDiscoverySignalV8(ctx context.Context, emitter sidecarRuntimeEmitter, source observability.Source, connector string, signal agentDiscoverySignal, probeStatus string) {
	// See emitAgentDiscoverySummaryV8: lifecycle is the registered contextual
	// authority for these agent.lifecycle companions.
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("lifecycle"),
		observability.ClassificationContext{Bucket: observability.BucketAgentLifecycle, EventName: "agent.discovery.signal", RawSeverity: "INFO"},
		source,
		connector,
		observability.ProducerKey("agent_discovery"),
	)
	if err != nil {
		return
	}
	_, _ = emitter.Emit(ctx, metadata, func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := agentDiscoveryEmitEnvelope(ctx, snapshot, source, "signal")
		envelope.Connector = connector
		return builder.BuildLogAgentDiscoverySignal(observability.LogAgentDiscoverySignalInput{
			Envelope: envelope,
			Severity: observability.Present(observability.SeverityInfo), LogLevel: observability.Present(observability.LogLevelInfo),
			DefenseClawAgentDiscoveryConnector: connector, DefenseClawAgentDiscoveryInstalled: signal.Installed,
			DefenseClawAgentDiscoveryHasConfig: signal.HasConfig, DefenseClawAgentDiscoveryHasBinary: signal.HasBinary,
			DefenseClawAgentDiscoveryProbeStatus: probeStatus,
		})
	})
}

func (a *APIServer) recordAgentDiscoverySummaryMetricsV8(ctx context.Context, emitter sidecarRuntimeEmitter, summary agentDiscoveryTelemetrySummary) {
	runtime, ok := emitter.(otlpGeneratedMetricRuntime)
	if !ok {
		return
	}
	source := observability.Present(aiDiscoveryV8MetricLabel(summary.source, "unknown"))
	result := observability.Present(aiDiscoveryV8MetricLabel(summary.result, "ok"))
	cacheHit := observability.Present(summary.cacheHit)
	_ = recordAgentDiscoveryMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawAgentDiscoveryRuns, agentDiscoverySource(summary.source), "", func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAgentDiscoveryRuns(observability.MetricDefenseClawAgentDiscoveryRunsInput{Envelope: envelope, Value: 1, DefenseClawMetricCacheHit: cacheHit, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
	})
	if summary.durationMs >= 0 {
		_ = recordAgentDiscoveryMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawAgentDiscoveryDuration, agentDiscoverySource(summary.source), "", func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawAgentDiscoveryDuration(observability.MetricDefenseClawAgentDiscoveryDurationInput{Envelope: envelope, Value: float64(summary.durationMs), DefenseClawMetricCacheHit: cacheHit, DefenseClawMetricResult: result, DefenseClawMetricSource: source})
		})
	}
}

func (a *APIServer) recordAgentDiscoverySignalMetricsV8(ctx context.Context, emitter sidecarRuntimeEmitter, source observability.Source, connector string, signal agentDiscoverySignal, probeStatus string) {
	runtime, ok := emitter.(otlpGeneratedMetricRuntime)
	if !ok {
		return
	}
	connectorLabel := observability.Present(aiDiscoveryV8MetricLabel(connector, "unknown"))
	_ = recordAgentDiscoveryMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawAgentDiscoverySignals, source, connector, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAgentDiscoverySignals(observability.MetricDefenseClawAgentDiscoverySignalsInput{Envelope: envelope, Value: 1, DefenseClawConnectorSource: connectorLabel, DefenseClawMetricInstalled: observability.Present(signal.Installed), DefenseClawMetricHasConfig: observability.Present(signal.HasConfig), DefenseClawMetricHasBinary: observability.Present(signal.HasBinary), DefenseClawMetricProbeStatus: observability.Present(aiDiscoveryV8MetricLabel(probeStatus, "unknown"))})
	})
	installed := int64(0)
	if signal.Installed {
		installed = 1
	}
	_ = recordAgentDiscoveryMetricV8(ctx, runtime, observability.TelemetryInstrumentDefenseClawAgentDiscoveryInstalled, source, connector, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
		return builder.BuildMetricDefenseClawAgentDiscoveryInstalled(observability.MetricDefenseClawAgentDiscoveryInstalledInput{Envelope: envelope, Value: installed, DefenseClawConnectorSource: connectorLabel})
	})
}

func recordAgentDiscoveryMetricV8(ctx context.Context, runtime otlpGeneratedMetricRuntime, family string, source observability.Source, connector string, build aiDiscoveryV8MetricBuild) error {
	_, err := runtime.RecordGeneratedMetric(ctx, observability.EventName(family), func(snapshot observabilityruntime.EmitContext) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return build(builder, agentDiscoveryEmitEnvelope(ctx, snapshot, source, "metrics"))
	})
	return err
}

func agentDiscoveryEmitEnvelope(ctx context.Context, snapshot observabilityruntime.EmitContext, source observability.Source, phase string) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: source, Action: "agent_discovery", Phase: phase,
		Correlation: observability.Correlation{RunID: gatewaylog.ProcessRunID(), RequestID: RequestIDFromContext(ctx), SidecarInstanceID: gatewaylog.SidecarInstanceID()},
		Provenance:  observability.FamilyProvenanceInput{Producer: agentDiscoveryV8Producer, BinaryVersion: version.Current().BinaryVersion, ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest()},
	}
}

func agentDiscoverySource(source string) observability.Source {
	switch source {
	case "cli", "tui":
		return observability.SourceCLI
	case "api":
		return observability.SourceOperatorAPI
	default:
		return observability.SourceOperatorAPI
	}
}
