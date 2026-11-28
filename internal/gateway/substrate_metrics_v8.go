// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// The Agent Substrate metrics a gateway replica measures, recorded through
// the process's generated metrics runtime like every other defenseclaw.*
// instrument, so they reach the OTLP destinations (GAP-0401). Before, the
// eight documented defenseclaw.substrate.* instruments existed only in the
// registry, and rate_limited only as a Prometheus counter no destination
// read. None carries an identity label: they are recorded with no request
// context, and the export cuts their resource (ResourceRestrictedMetric).

const substrateMetricsV8Producer = "gateway.substrate"

func (a *APIServer) recordSubstrateMetricV8(family string, build hookV8MetricRecordBuilder) {
	runtime := a.apiOperationalV8Runtime()
	if runtime == nil {
		return
	}
	ctx := context.Background()
	item := newGatewayGeneratedMetricItem(ctx, time.Now().UTC(), observability.SourceGateway, "",
		substrateMetricsV8Producer, observability.EventName(family), build)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

func substrateMetricMillis(d time.Duration) float64 {
	if d < 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

// recordSubstrateHookRTT is defenseclaw.substrate.hook_rtt: an actor hook
// call's time in the gateway, from its arrival on the actor listener to its
// answer (the kit's network leg is not seen here).
func (a *APIServer) recordSubstrateHookRTT(d time.Duration) {
	ms := substrateMetricMillis(d)
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateHookRtt,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstrateHookRtt(observability.MetricDefenseClawSubstrateHookRttInput{Envelope: envelope, Value: ms})
		})
}

// recordSubstrateFirstHookAfterResume is
// defenseclaw.substrate.first_hook_after_resume: the round trip in the
// gateway of an actor's first hook call after a resume (GAP-0486), the same
// measure as hook_rtt.
func (a *APIServer) recordSubstrateFirstHookAfterResume(d time.Duration) {
	ms := substrateMetricMillis(d)
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateFirstHookAfterResume,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstrateFirstHookAfterResume(observability.MetricDefenseClawSubstrateFirstHookAfterResumeInput{Envelope: envelope, Value: ms})
		})
}

// recordSubstrateLeaderObserve is defenseclaw.substrate.leader_observe_latency:
// one tool-chain step this replica sent to the leader, until its answer.
func (a *APIServer) recordSubstrateLeaderObserve(d time.Duration) {
	ms := substrateMetricMillis(d)
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateLeaderObserveLatency,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstrateLeaderObserveLatency(observability.MetricDefenseClawSubstrateLeaderObserveLatencyInput{Envelope: envelope, Value: ms})
		})
}

// recordSubstrateRateLimited is defenseclaw.substrate.rate_limited: one
// actor request the fair-share limits refused.
func (a *APIServer) recordSubstrateRateLimited() {
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateRateLimited,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstrateRateLimited(observability.MetricDefenseClawSubstrateRateLimitedInput{Envelope: envelope, Value: 1})
		})
}

// recordSubstratePolicyLag is defenseclaw.substrate.policy_lag: a launcher
// create on this replica until the new actor runs with its egress policy
// (the create path writes the policy before it resumes the actor).
func (a *APIServer) recordSubstratePolicyLag(d time.Duration) {
	s := float64(d) / float64(time.Second)
	if s < 0 {
		s = 0
	}
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstratePolicyLag,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstratePolicyLag(observability.MetricDefenseClawSubstratePolicyLagInput{Envelope: envelope, Value: s})
		})
}

// recordSubstrateCount records a count the controller reported through the
// leader (telemetryrelay): defenseclaw.substrate.idle_suspends or
// policy_conflicts. Each increment reaches one replica only, so the sum
// over the replicas is the cluster's.
func (a *APIServer) recordSubstrateCount(metric string, n int64) {
	if n <= 0 {
		return
	}
	switch metric {
	case telemetryrelay.MetricIdleSuspends:
		a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateIdleSuspends,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSubstrateIdleSuspends(observability.MetricDefenseClawSubstrateIdleSuspendsInput{Envelope: envelope, Value: n})
			})
	case telemetryrelay.MetricPolicyConflicts:
		a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstratePolicyConflicts,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSubstratePolicyConflicts(observability.MetricDefenseClawSubstratePolicyConflictsInput{Envelope: envelope, Value: n})
			})
	}
}

// recordSubstrateUnattestedTemplates is defenseclaw.substrate.unattested_templates:
// the controller's current count, which every replica reports.
func (a *APIServer) recordSubstrateUnattestedTemplates(n int64) {
	a.recordSubstrateMetricV8(observability.TelemetryInstrumentDefenseClawSubstrateUnattestedTemplates,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawSubstrateUnattestedTemplates(observability.MetricDefenseClawSubstrateUnattestedTemplatesInput{Envelope: envelope, Value: n})
		})
}
