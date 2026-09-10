// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package gateway

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// maxRuntimeSignalsPerRecord bounds the rendered evidence trail. The registry
// bounds each item; this bounds the count so one pathological finding cannot
// dominate a record.
const maxRuntimeSignalsPerRecord = 32

// runtimeSignalsByteBudget mirrors defenseclaw.ai.runtime.signals'
// max_utf8_bytes in schemas/telemetry/v8/operations.yaml. The budget covers
// the whole array, so it has to hold what maxRuntimeSignalsPerRecord is
// willing to send -- the two disagreed by an order of magnitude, and a
// finding whose trail exceeded the budget lost the entire record.
const runtimeSignalsByteBudget = 2048

// aiRuntimeV8Adapter emits runtime-plane records through the canonical v8
// pipeline. There is no v7 path: the retired ai_discovery envelope had no
// producer and this subsystem never had one.
type aiRuntimeV8Adapter struct {
	runtime sidecarRuntimeEmitter
}

func newAIRuntimeV8Adapter(emitter sidecarRuntimeEmitter) *aiRuntimeV8Adapter {
	if emitter == nil {
		return nil
	}
	return &aiRuntimeV8Adapter{runtime: emitter}
}

// EmitSnapshot publishes one poll cycle.
//
// Plane health is emitted for every plane on every cycle, including planes
// that are down. Emitting only healthy planes would make a dead subscription
// indistinguishable from a clean host, and absence is the hardest thing to
// alert on.
func (adapter *aiRuntimeV8Adapter) EmitSnapshot(ctx context.Context, snapshot sensor.Snapshot) error {
	if adapter == nil || adapter.runtime == nil || ctx == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	var firstErr error
	for _, health := range snapshot.Planes {
		if err := adapter.emitPlaneHealth(ctx, snapshot, health); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, finding := range snapshot.Findings {
		if err := adapter.emitFinding(ctx, snapshot, finding); err != nil && firstErr == nil {
			firstErr = err
		}
		if finding.AgentName == "" {
			// Activity records are per-tactic and carry the agent. Plane A and
			// plane B findings have no lineage behind them, so there is no
			// agent to name -- emitting anyway would have the builder refuse
			// the record and turn every such poll into an error. The finding
			// itself is already emitted above; only the activity breakdown is
			// host-plane-only.
			continue
		}
		// One record per tactic, not per signal. Several signal ids map to
		// the same tactic -- agent_persistence and agent_config_persistence
		// both mean Persistence -- and emitting each would double-count a
		// stage in every consumer that counts activity records.
		seen := make(map[tactics.Tactic]bool, len(finding.Signals))
		for _, signal := range finding.Signals {
			tactic, ok := tactics.ForSignal(signal.ID)
			if !ok || seen[tactic] {
				continue
			}
			seen[tactic] = true
			if err := adapter.emitActivity(ctx, snapshot, finding, tactic); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// planeHealthReason is what a plane-health record says happened.
//
// A running plane names its mechanism; a stopped or blind one names its
// reason. One of the two is always present, so a reader never has to go to
// the source to find out what happened.
//
// Exported to the test rather than restated there: a test that re-implements
// this rule asserts against itself and keeps passing when the rule changes.
func planeHealthReason(health sensor.PlaneHealth) string {
	if health.Reason != "" {
		return health.Reason
	}
	if health.Running {
		return health.Mechanism
	}
	return ""
}

func runtimeOutcome(snapshot sensor.Snapshot) observability.Outcome {
	// A degraded cycle is partial, not completed. Reporting a blinded poll as
	// complete is the exact substitution this subsystem refuses everywhere
	// else.
	if snapshot.Degraded {
		return observability.OutcomePartial
	}
	return observability.OutcomeCompleted
}

func (adapter *aiRuntimeV8Adapter) metadata(eventName observability.EventName) (router.Metadata, error) {
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
		return router.Metadata{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	return metadata, nil
}

func (adapter *aiRuntimeV8Adapter) emitPlaneHealth(
	ctx context.Context, snapshot sensor.Snapshot, health sensor.PlaneHealth,
) error {
	metadata, err := adapter.metadata("ai.runtime.plane_health")
	if err != nil {
		return err
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIRuntimePlaneHealth(observability.LogAIRuntimePlaneHealthInput{
			Envelope:                                aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime"),
			Severity:                                observability.Present(observability.SeverityInfo),
			LogLevel:                                observability.Present(observability.LogLevelInfo),
			Outcome:                                 runtimeOutcome(snapshot),
			DefenseClawAIRuntimeProcessesObserved:   int64(snapshot.ProcessesObserved),
			DefenseClawAIRuntimeProcessesSkipped:    int64(snapshot.ProcessesSkipped),
			DefenseClawAIRuntimeConnectionsObserved: int64(snapshot.ConnectionsObserved),
			DefenseClawAIRuntimeConnectionsUnattributed: int64(snapshot.ConnectionsUnattributed),
			DefenseClawAIRuntimePlane:                   string(health.Plane),
			DefenseClawAIRuntimePlaneAvailable:          health.Available,
			DefenseClawAIRuntimePlaneRunning:            health.Running,
			DefenseClawAIRuntimePlaneReason:             aiDiscoveryV8OptionalText(planeHealthReason(health)),
		})
	})
	return err
}

func (adapter *aiRuntimeV8Adapter) emitFinding(
	ctx context.Context, snapshot sensor.Snapshot, finding sensor.Finding,
) error {
	metadata, err := adapter.metadata("ai.runtime.finding")
	if err != nil {
		return err
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIRuntimeFinding(observability.LogAIRuntimeFindingInput{
			Envelope:                                aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime"),
			Severity:                                observability.Present(runtimeSeverity(string(finding.Severity))),
			LogLevel:                                observability.Present(observability.LogLevelInfo),
			Outcome:                                 runtimeOutcome(snapshot),
			DefenseClawAIRuntimeProcessesObserved:   int64(snapshot.ProcessesObserved),
			DefenseClawAIRuntimeProcessesSkipped:    int64(snapshot.ProcessesSkipped),
			DefenseClawAIRuntimeConnectionsObserved: int64(snapshot.ConnectionsObserved),
			DefenseClawAIRuntimeConnectionsUnattributed: int64(snapshot.ConnectionsUnattributed),
			DefenseClawAIRuntimeFindingID:               finding.FindingID,
			DefenseClawAIRuntimeScore:                   int64(finding.Score),
			DefenseClawAIRuntimeSeverity:                string(finding.Severity),
			DefenseClawAIRuntimeProcess:                 finding.Process,
			// Always populated, including "unobserved". A reader who saw the
			// field only when the inventory agreed would mistake blindness for
			// agreement.
			DefenseClawAIRuntimeCorrelationVerdict: string(finding.Correlation.Verdict),
			DefenseClawAIRuntimeCorrelationReason:  finding.Correlation.Reason,
			DefenseClawAIRuntimeAgent:              aiDiscoveryV8OptionalText(finding.AgentName),
			// Content class. Each destination's redaction profile governs
			// whether argv leaves the host.
			DefenseClawAIRuntimeCmdline:   aiDiscoveryV8OptionalText(finding.Cmdline),
			DefenseClawAIRuntimeSignals:   aiDiscoveryV8OptionalStrings(renderRuntimeSignals(finding)),
			DefenseClawAIRuntimeProviders: aiDiscoveryV8OptionalStrings(renderRuntimeProviders(finding)),
		})
	})
	return err
}

func (adapter *aiRuntimeV8Adapter) emitActivity(
	ctx context.Context, snapshot sensor.Snapshot, finding sensor.Finding, tactic tactics.Tactic,
) error {
	metadata, err := adapter.metadata("ai.runtime.activity")
	if err != nil {
		return err
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		stage := tactics.ChainStage(tactic)
		if stage < 0 {
			stage = 0
		}
		agent := finding.AgentName
		if agent == "" {
			// Every host-plane tactic is lineage-gated, so an activity record
			// without an agent should not exist. Fail the build rather than
			// emitting a record that implies an unattributed tactic.
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		return builder.BuildLogAIRuntimeActivity(observability.LogAIRuntimeActivityInput{
			Envelope:                       aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime"),
			Severity:                       observability.Present(runtimeSeverity(string(finding.Severity))),
			LogLevel:                       observability.Present(observability.LogLevelInfo),
			Outcome:                        observability.OutcomeCompleted,
			DefenseClawAIRuntimeFindingID:  finding.FindingID,
			DefenseClawAIRuntimeTactic:     string(tactic),
			DefenseClawAIRuntimeTechnique:  tactic.Technique(),
			DefenseClawAIRuntimeChainStage: int64(stage),
			DefenseClawAIRuntimeAgent:      agent,
			DefenseClawAIRuntimeProcess:    aiDiscoveryV8OptionalText(finding.Process),
		})
	})
	return err
}

// runtimeSeverity maps a finding band onto the telemetry severity vocabulary.
func runtimeSeverity(band string) observability.Severity {
	switch strings.ToLower(band) {
	case "critical":
		return observability.SeverityCritical
	case "high":
		return observability.SeverityHigh
	case "medium":
		return observability.SeverityMedium
	case "low":
		return observability.SeverityLow
	default:
		return observability.SeverityInfo
	}
}

// renderRuntimeSignals flattens the evidence trail to bounded metadata.
//
// Rendered as signal_id=weight rather than as structured content so the whole
// trail stays a metadata field: it is the arithmetic behind the score, not
// something derived from what the process was doing.
func renderRuntimeSignals(finding sensor.Finding) []string {
	rendered := make([]string, 0, len(finding.Signals))
	weights := make(map[string]int, len(finding.Signals))
	for _, signal := range finding.Signals {
		if signal.ID == "" {
			continue
		}
		rendered = append(rendered, fmt.Sprintf("%s=%d", signal.ID, signal.Weight))
		weights[rendered[len(rendered)-1]] = signal.Weight
	}
	// Select by weight, then order the survivors lexically.
	//
	// Sorting first and cutting the tail keeps the alphabetically earliest
	// signals, which has nothing to do with which ones explain the score: a
	// trail truncated that way can drop the heaviest evidence and keep the
	// lightest. Ties break on the rendered string so the result is stable.
	sort.SliceStable(rendered, func(i, j int) bool {
		if weights[rendered[i]] != weights[rendered[j]] {
			return weights[rendered[i]] > weights[rendered[j]]
		}
		return rendered[i] < rendered[j]
	})
	if len(rendered) > maxRuntimeSignalsPerRecord {
		rendered = rendered[:maxRuntimeSignalsPerRecord]
	}
	sort.Strings(rendered)
	return rendered
}

// renderRuntimeProviders flattens attributed peers to content-class strings.
func renderRuntimeProviders(finding sensor.Finding) []string {
	rendered := make([]string, 0, len(finding.Providers))
	seen := make(map[string]bool, len(finding.Providers))
	// Keep the strongest attribution per hostname, not the first one seen.
	// A DNS answer this host actually resolved (0.95) and a PTR record (0.6)
	// can name the same peer, and provider order carries no guarantee about
	// which arrives first -- so keeping the first would report the weaker
	// confidence for a peer that was directly observed.
	best := make(map[string]sensor.ProviderReach, len(finding.Providers))
	for _, provider := range finding.Providers {
		if provider.Hostname == "" {
			continue
		}
		if existing, ok := best[provider.Hostname]; ok &&
			existing.Confidence >= provider.Confidence {
			continue
		}
		best[provider.Hostname] = provider
	}
	for hostname, provider := range best {
		seen[hostname] = true
		rendered = append(rendered, fmt.Sprintf("%s|%s|%.2f",
			provider.Hostname, provider.Category, provider.Confidence))
	}
	sort.Strings(rendered)
	if len(rendered) > maxRuntimeSignalsPerRecord {
		rendered = rendered[:maxRuntimeSignalsPerRecord]
	}
	return rendered
}
