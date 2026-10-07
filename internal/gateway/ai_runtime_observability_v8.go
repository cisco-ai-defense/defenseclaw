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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
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
	// kernelCursor remembers which helper state changes were already
	// reported; nil means the process-wide cursor. An adapter is built per
	// poll, so the cursor cannot live here.
	kernelCursor *kernelChangeCursor
	// directories memoizes the directory attribution of a user for the
	// snapshot being emitted (EmitSnapshot resets it; an adapter emits one
	// snapshot at a time).
	directories   map[string]*llmEventIdentity
	directoriesMu sync.Mutex
	// kernelDeltas remembers the helper's counters for the per-cycle
	// growth on plane_health, and kernelState the kernel state gauge's last
	// label set; nil means the process-wide cursors.
	kernelDeltas *kernelDeltaCursor
	kernelState  *kernelStateCursor
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
	adapter.directoriesMu.Lock()
	adapter.directories = nil
	adapter.directoriesMu.Unlock()
	// Once per cycle: the growth of the helper's counters is per cycle.
	fleet := adapter.kernelFleetOf(snapshot, time.Now())
	for _, health := range snapshot.Planes {
		if err := adapter.emitPlaneHealth(ctx, snapshot, health, fleet); err != nil && firstErr == nil {
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
	// Kernel floor: denials of DefenseClaw's controls and the helper's
	// state changes. Both are empty off managed Linux.
	if err := adapter.emitKernelBlocks(ctx, snapshot); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := adapter.emitKernelPolicyChanges(ctx, snapshot); err != nil && firstErr == nil {
		firstErr = err
	}
	// The host's own Tetragon policies' events below an AI agent, and the
	// kernel metrics.
	if err := adapter.emitCustomerKernelEvents(ctx, snapshot); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := adapter.emitKernelMetrics(ctx, snapshot, fleet); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// runtimePlaneBackend is the process backend Plane C ran on; absent off the
// managed Linux helper and for the other planes.
func runtimePlaneBackend(health sensor.PlaneHealth) observability.Optional[string] {
	if health.Plane != platform.PlaneC || health.Backend == nil {
		return observability.Absent[string]()
	}
	return runtimeEnum(health.Backend.Kind, runtimePlaneBackends)
}

// runtimePlaneEventsLost is the backend's loss count; present with the
// backend, zero included.
func runtimePlaneEventsLost(health sensor.PlaneHealth) observability.Optional[int64] {
	if health.Plane != platform.PlaneC || health.Backend == nil {
		return observability.Absent[int64]()
	}
	return observability.Present(runtimeCount(health.Backend.EventsLost, math.MaxInt64))
}

// runtimePlaneLossKnown says whether the backend's own loss counters were
// readable; a false is "unknown", not "none".
func runtimePlaneLossKnown(health sensor.PlaneHealth) observability.Optional[bool] {
	if health.Plane != platform.PlaneC || health.Backend == nil {
		return observability.Absent[bool]()
	}
	return observability.Present(health.Backend.LossKnown)
}

// runtimePlaneContainerEvents is how many events this cycle were routed to
// the container bucket. It is reported with the managed Linux backend (zero
// included, so a quiet count is distinguishable from no reading) and on any
// plane C cycle that routed some.
func runtimePlaneContainerEvents(health sensor.PlaneHealth) observability.Optional[int64] {
	if health.Plane != platform.PlaneC || (health.Backend == nil && health.ContainerEvents <= 0) {
		return observability.Absent[int64]()
	}
	return observability.Present(runtimeCount(health.ContainerEvents, runtimeContainerMax))
}

// runtimeCorrelationID keeps a joined hook decision's id when it fits the
// correlation envelope.
func runtimeCorrelationID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 || !utf8.ValidString(value) {
		return ""
	}
	return value
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

func (adapter *aiRuntimeV8Adapter) metadata(
	eventName observability.EventName,
	rawSeverity string,
) (router.Metadata, error) {
	if strings.TrimSpace(rawSeverity) == "" {
		rawSeverity = "INFO"
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: eventName, RawSeverity: rawSeverity,
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
	ctx context.Context, snapshot sensor.Snapshot, health sensor.PlaneHealth, fleet kernelFleet,
) error {
	metadata, err := adapter.metadata("ai.runtime.plane_health", "INFO")
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
		input := observability.LogAIRuntimePlaneHealthInput{
			Envelope:                                aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime"),
			Severity:                                observability.Present(observability.SeverityInfo),
			LogLevel:                                observability.Present(observability.LogLevelInfo),
			Outcome:                                 runtimeOutcome(snapshot),
			DefenseClawAIRuntimeProcessesObserved:   int64(snapshot.ProcessesObserved),
			DefenseClawAIRuntimeProcessesSkipped:    int64(snapshot.ProcessesSkipped),
			DefenseClawAIRuntimeConnectionsObserved: int64(snapshot.ConnectionsObserved),
			DefenseClawAIRuntimeConnectionsUnattributed: int64(snapshot.ConnectionsUnattributed),
			DefenseClawAIRuntimeHostPlaneObservations:   snapshot.HostPlaneObservations,
			DefenseClawAIRuntimeHostPlaneGated:          snapshot.HostPlaneGated,
			DefenseClawAIRuntimePlane:                   string(health.Plane),
			DefenseClawAIRuntimePlaneAvailable:          health.Available,
			DefenseClawAIRuntimePlaneRunning:            health.Running,
			// A running plane names its mechanism on every cycle, and a
			// stopped, blind or partial one its reason, so a reader never has
			// to go to the source to find out what a plane is doing.
			DefenseClawAIRuntimePlaneReason:     aiDiscoveryV8OptionalText(health.Reason),
			DefenseClawAIRuntimePlaneMechanism:  runtimeBoundedText(health.Mechanism, runtimeMechanismMaxBytes),
			DefenseClawAIRuntimePlaneBackend:    runtimePlaneBackend(health),
			DefenseClawAIRuntimeEventsLost:      runtimePlaneEventsLost(health),
			DefenseClawAIRuntimeLossKnown:       runtimePlaneLossKnown(health),
			DefenseClawAIRuntimeContainerEvents: runtimePlaneContainerEvents(health),
		}
		if health.Plane == platform.PlaneC && fleet.present {
			// The fleet fields: the latest plane c record of each host is the
			// fleet table's row.
			input.DefenseClawAIRuntimeKernelHelperMode = fleet.helperMode
			input.DefenseClawAIRuntimeKernelApproval = fleet.approval
			input.DefenseClawPolicyVersion = fleet.policy
			input.DefenseClawAIRuntimeKernelUsersEnrolled = fleet.enrolled
			input.DefenseClawAIRuntimeKernelUsersEnforced = fleet.enforced
			input.DefenseClawAIRuntimeKernelUsersBurnIn = fleet.burnIn
			input.DefenseClawAIRuntimeKernelPaused = fleet.paused
			input.DefenseClawAIRuntimeTetragonVersion = fleet.version
			input.DefenseClawAIRuntimeTetragonInstalled = fleet.installed
			input.DefenseClawAIRuntimeKernelWouldBlockDelta = fleet.wouldBlockDelta
			input.DefenseClawAIRuntimeKernelBlockedDelta = fleet.blockedDelta
			input.DefenseClawAIRuntimeKernelCustomerEventsDelta = fleet.customerDelta
		}
		return builder.BuildLogAIRuntimePlaneHealth(input)
	})
	return err
}

func (adapter *aiRuntimeV8Adapter) emitFinding(
	ctx context.Context, snapshot sensor.Snapshot, finding sensor.Finding,
) error {
	metadata, err := adapter.metadata("ai.runtime.finding", string(finding.Severity))
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
		fields := adapter.identityFields(runtimeFindingIdentity(finding, snapshot.Kernel))
		source, kernelOutcome, kernelControl := findingKernelFacts(finding)
		input := observability.LogAIRuntimeFindingInput{
			Envelope:                                aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime"),
			Severity:                                observability.Present(runtimeSeverity(string(finding.Severity))),
			LogLevel:                                observability.Present(observability.LogLevelInfo),
			Outcome:                                 runtimeOutcome(snapshot),
			DefenseClawAIRuntimeProcessesObserved:   int64(snapshot.ProcessesObserved),
			DefenseClawAIRuntimeProcessesSkipped:    int64(snapshot.ProcessesSkipped),
			DefenseClawAIRuntimeConnectionsObserved: int64(snapshot.ConnectionsObserved),
			DefenseClawAIRuntimeConnectionsUnattributed: int64(snapshot.ConnectionsUnattributed),
			DefenseClawAIRuntimeHostPlaneObservations:   snapshot.HostPlaneObservations,
			DefenseClawAIRuntimeHostPlaneGated:          snapshot.HostPlaneGated,
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

			UserID:                            fields.UserID,
			DefenseClawUserIDKind:             fields.IDKind,
			DefenseClawUserName:               fields.UserName,
			DefenseClawUserLoginID:            fields.LoginID,
			DefenseClawAgentIdentityID:        fields.AgentIdentityID,
			DefenseClawAIRuntimeEventSource:   runtimeEnum(string(source), runtimeEventSources),
			DefenseClawAIRuntimeKernelOutcome: runtimeEnum(string(kernelOutcome), runtimeKernelOutcomes),
			DefenseClawAIRuntimeKernelControl: runtimeEnum(kernelControl, kernelControls),
		}
		fields.Directory.applyTo(&input)
		return builder.BuildLogAIRuntimeFinding(input)
	})
	return err
}

func (adapter *aiRuntimeV8Adapter) emitActivity(
	ctx context.Context, snapshot sensor.Snapshot, finding sensor.Finding, tactic tactics.Tactic,
) error {
	metadata, err := adapter.metadata("ai.runtime.activity", string(finding.Severity))
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
		// The process that did this tactic: its own uid when the backend
		// reported it, else the agent root's. The agent identity is the
		// root's (the install the activity belongs to).
		findingIdentity := runtimeFindingIdentity(finding, snapshot.Kernel)
		detail, _ := findingActivity(finding, tactic)
		identity := runtimeActivityIdentity(finding, detail)
		identity.AgentIdentityID = findingIdentity.AgentIdentityID
		fields := adapter.identityFields(identity)
		envelope := aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "runtime")
		input := observability.LogAIRuntimeActivityInput{
			Envelope:                          envelope,
			Severity:                          observability.Present(runtimeSeverity(string(finding.Severity))),
			LogLevel:                          observability.Present(observability.LogLevelInfo),
			Outcome:                           observability.OutcomeCompleted,
			UserID:                            fields.UserID,
			DefenseClawUserIDKind:             fields.IDKind,
			DefenseClawUserName:               fields.UserName,
			DefenseClawUserLoginID:            fields.LoginID,
			DefenseClawAgentIdentityID:        fields.AgentIdentityID,
			DefenseClawAIRuntimeEventSource:   runtimeEnum(string(detail.Source), runtimeEventSources),
			DefenseClawAIRuntimeKernelOutcome: runtimeEnum(string(detail.Outcome), runtimeKernelOutcomes),
			DefenseClawAIRuntimeKernelControl: runtimeEnum(detail.Control, kernelControls),
			DefenseClawAIRuntimeFindingID:     finding.FindingID,
			DefenseClawAIRuntimeTactic:        string(tactic),
			DefenseClawAIRuntimeTechnique:     tactic.Technique(),
			DefenseClawAIRuntimeChainStage:    int64(stage),
			DefenseClawAIRuntimeAgent:         agent,
			DefenseClawAIRuntimeProcess:       aiDiscoveryV8OptionalText(finding.Process),
		}
		if detail.Hook != nil {
			// Managed hosts only. The join labels the activity and never
			// blocks it: hook_seen=false is activity no decision covered.
			input.DefenseClawAIRuntimeHookSeen = observability.Present(detail.Hook.Seen)
			if detail.Hook.Seen {
				input.DefenseClawAIRuntimeHookJoin = runtimeEnum(detail.Hook.Confidence, runtimeHookJoins)
				input.Envelope.Correlation.SessionID = runtimeCorrelationID(detail.Hook.SessionID)
				input.Envelope.Correlation.ToolInvocationID = runtimeCorrelationID(detail.Hook.ToolInvocationID)
			}
		}
		fields.Directory.applyTo(&input)
		return builder.BuildLogAIRuntimeActivity(input)
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
