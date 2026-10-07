// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Telemetry for the Linux kernel floor (SPEC-TETRAGON sections 9.1 and 9.2).
//
// Three things leave the gateway from here:
//
//   - the identity, event-source and kernel-outcome fields that the runtime
//     activity and finding records carry;
//   - log.enforcement.block.applied for a denial a DefenseClaw kernel control
//     returned, tagged initiator "kernel";
//   - log.ai.runtime.kernel_policy, one low-volume record per state change the
//     sensor helper's reconciler reports.
//
// The sensor helper emits no telemetry itself. It reports state through
// kernel_status, and the gateway (the only process with an exporter) turns
// the changes into records.

const (
	// kernelBlockV8Producer is the provenance producer of a kernel denial.
	kernelBlockV8Producer = "gateway.kernel.policy"
	// kernelBlockInitiator is the enforcement initiator of a kernel denial.
	kernelBlockInitiator = "kernel"

	// maxKernelBlocksPerSnapshot bounds the denials one poll emits. The host
	// plane already caps KernelEvents; this keeps a denial storm from
	// dominating one emission cycle, and the remainder is counted, not lost
	// silently (KernelEventsDropped covers the host plane's own cap).
	maxKernelBlocksPerSnapshot = 256
	// maxKernelChangesPerSnapshot bounds the state-change records of one cycle.
	maxKernelChangesPerSnapshot = 64
	// kernelChangeFirstSightWindow is how far back the first look at the
	// helper's change ring reaches. A gateway restarting with the helper
	// (ensure restarts both) should still report the policies the helper just
	// loaded, and an old ring must not be replayed as if it were new.
	kernelChangeFirstSightWindow = 5 * time.Minute

	runtimeMechanismMaxBytes = 256
	runtimeReasonMaxBytes    = 256
	runtimeContainerMax      = 1_000_000_000
)

// kernelPolicyEvents, kernelPolicyFamilies, kernelPolicyModes and
// kernelControls are the closed vocabularies of the registry enums. A value
// outside them (a newer helper) is omitted rather than failing the record.
var (
	kernelPolicyEvents = []string{
		"loaded", "mode_changed", "removed", "operator_override", "paused", "resumed", "orphaned",
		"reconcile_failed", "ack_stale", "uid_ready", "uid_burnin", "tetragon_restarted", "fallback",
	}
	kernelPolicyFamilies  = []string{"observe", "connect", "controls", "controls-burnin"}
	kernelPolicyModes     = []string{"monitor", "enforce"}
	kernelControls        = []string{"kernel.ssh_private_key_read", "kernel.persistence_write"}
	runtimeEventSources   = []string{"tetragon", "cn_proc", "fanotify", "endpoint_security", "etw", "poll"}
	runtimeKernelOutcomes = []string{
		string(plane.OutcomeObserved), string(plane.OutcomeWouldBlock), string(plane.OutcomeBlocked),
	}
	runtimePlaneBackends = []string{plane.BackendTetragon, plane.BackendNative}
	runtimeHookJoins     = []string{sensor.HookJoinExact, sensor.HookJoinTemporal}
	// kernelAttentionEvents are state changes an operator should notice; the
	// rest are routine.
	kernelAttentionEvents = map[string]bool{
		"operator_override": true, "orphaned": true, "reconcile_failed": true, "ack_stale": true, "paused": true,
	}
)

// kernelChangeCursor remembers the last state change the gateway reported,
// across the per-poll adapters: the helper's change ring is read on every
// poll and must not be reported twice.
type kernelChangeCursor struct {
	mu   sync.Mutex
	seq  uint64
	seen bool
}

// defaultKernelChangeCursor is shared by the adapters of one gateway process.
var defaultKernelChangeCursor = &kernelChangeCursor{}

// take returns the changes not yet reported, oldest first, and advances the
// cursor past them.
//
// On first sight only changes within kernelChangeFirstSightWindow are
// returned. When the helper's sequence restarted below the cursor (its state
// was removed), the same window applies to the new sequence.
func (cursor *kernelChangeCursor) take(changes []acquire.KernelChange, now time.Time) []acquire.KernelChange {
	if cursor == nil || len(changes) == 0 {
		return nil
	}
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	var highest uint64
	for _, change := range changes {
		if change.Seq > highest {
			highest = change.Seq
		}
	}
	windowed := !cursor.seen || highest < cursor.seq
	last := cursor.seq
	if highest < cursor.seq {
		last = 0
	}
	var out []acquire.KernelChange
	for _, change := range changes {
		if change.Seq <= last {
			continue
		}
		if windowed && change.AtUnixNano > 0 &&
			now.Sub(time.Unix(0, change.AtUnixNano)) > kernelChangeFirstSightWindow {
			continue
		}
		out = append(out, change)
	}
	cursor.seq, cursor.seen = highest, true
	return out
}

// runtimeEnum passes value through when it is one of allowed.
func runtimeEnum(value string, allowed []string) observability.Optional[string] {
	for _, candidate := range allowed {
		if value == candidate {
			return observability.Present(value)
		}
	}
	return observability.Absent[string]()
}

// runtimeIdentifier passes a bounded identifier-class value: trimmed,
// non-empty, valid UTF-8, no control characters, at most 128 bytes. Unlike a
// stable token it allows the upper case and colons of rule ids and digests.
func runtimeIdentifier(value string) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return observability.Absent[string]()
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return observability.Absent[string]()
		}
	}
	return observability.Present(value)
}

// runtimeIdentifierText is runtimeIdentifier as a plain string, "" when absent.
func runtimeIdentifierText(value string) string {
	text, _ := runtimeIdentifier(value).Get()
	return text
}

// runtimeBoundedText trims value to max bytes on a rune boundary; empty is absent.
func runtimeBoundedText(value string, max int) observability.Optional[string] {
	value = strings.TrimSpace(value)
	if value == "" {
		return observability.Absent[string]()
	}
	if len(value) > max {
		value = value[:max]
		for len(value) > 0 && !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

// runtimeCount clamps a counter into the registry's range.
func runtimeCount(value int64, max int64) int64 {
	switch {
	case value < 0:
		return 0
	case value > max:
		return max
	default:
		return value
	}
}

// runtimeIdentityFields is the user and agent identity of one host-plane
// record (SPEC-TETRAGON 12.1), in the optional shapes the builders take.
type runtimeIdentityFields struct {
	UserID          observability.Optional[string]
	IDKind          observability.Optional[string]
	UserName        observability.Optional[string]
	LoginID         observability.Optional[string]
	AgentIdentityID observability.Optional[string]
	// Directory is the verified directory attribution of UserID; nil when the
	// user is unknown or identity facts are off.
	Directory *llmEventIdentity
}

// runtimeLoginID bounds login_id to the digits of a Linux audit uid.
func runtimeLoginID(value string) observability.Optional[string] {
	if value == "" || len(value) > 10 {
		return observability.Absent[string]()
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return observability.Absent[string]()
		}
	}
	return observability.Present(value)
}

func (adapter *aiRuntimeV8Adapter) identityFields(identity runtimeIdentity) runtimeIdentityFields {
	fields := runtimeIdentityFields{
		UserID:          aiDiscoveryV8OptionalText(identity.UserID),
		IDKind:          v8UserIDKind(discoveryUserIDKind(identity.UserID)),
		UserName:        aiDiscoveryV8OptionalText(identity.UserName),
		LoginID:         runtimeLoginID(identity.LoginID),
		AgentIdentityID: agentIdentityV8(identity.AgentIdentityID),
	}
	if identity.UserID != "" {
		fields.Directory = adapter.directory(identity.UserID)
	}
	return fields
}

// directory memoizes inventoryIdentity for one snapshot: a poll can carry
// many records for the same few users, and the lookup touches the user
// database.
func (adapter *aiRuntimeV8Adapter) directory(userID string) *llmEventIdentity {
	adapter.directoriesMu.Lock()
	defer adapter.directoriesMu.Unlock()
	if adapter.directories == nil {
		adapter.directories = make(map[string]*llmEventIdentity)
	}
	if facts, ok := adapter.directories[userID]; ok {
		return facts
	}
	facts := inventoryIdentity(userID)
	adapter.directories[userID] = facts
	return facts
}

// activityStrength orders kernel outcomes: a denial outranks a would-be
// denial, which outranks a plain observation.
func activityStrength(outcome plane.KernelOutcome) int {
	switch outcome {
	case plane.OutcomeBlocked:
		return 3
	case plane.OutcomeWouldBlock:
		return 2
	case plane.OutcomeObserved:
		return 1
	default:
		return 0
	}
}

// findingKernelFacts summarizes a finding's per-tactic activity for the
// finding record: the backend of the latest tactic in chain order that names
// one, and the strongest kernel outcome with the control that produced it.
func findingKernelFacts(finding sensor.Finding) (plane.EventSource, plane.KernelOutcome, string) {
	var (
		source  plane.EventSource
		outcome plane.KernelOutcome
		control string
	)
	for _, activity := range finding.Activities {
		if activity.Source != "" {
			source = activity.Source
		}
		if activityStrength(activity.Outcome) > activityStrength(outcome) {
			outcome, control = activity.Outcome, activity.Control
		}
	}
	return source, outcome, control
}

// findingActivity is the per-tactic detail of a finding for tactic.
func findingActivity(finding sensor.Finding, tactic tactics.Tactic) (sensor.RuntimeActivity, bool) {
	for _, activity := range finding.Activities {
		if activity.Tactic == tactic {
			return activity, true
		}
	}
	return sensor.RuntimeActivity{}, false
}

// emitKernelBlocks reports the denials DefenseClaw's kernel controls returned
// since the previous poll. A would-block (control in monitor mode) is not an
// enforcement: it rides on the activity records instead.
func (adapter *aiRuntimeV8Adapter) emitKernelBlocks(ctx context.Context, snapshot sensor.Snapshot) error {
	var firstErr error
	emitted := 0
	for _, event := range snapshot.KernelEvents {
		if event.Outcome != plane.OutcomeBlocked {
			continue
		}
		if emitted >= maxKernelBlocksPerSnapshot {
			break
		}
		emitted++
		if err := adapter.emitKernelBlock(ctx, snapshot, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// kernelEnforcementID is a stable, content-free id for one denial. The path
// is hashed, never emitted.
func kernelEnforcementID(event sensor.KernelEvent) string {
	sum := sha256.New()
	for _, part := range []string{
		event.Policy, event.Control, event.ExecID, strconv.Itoa(event.PID), event.Path,
		strconv.FormatInt(event.At.UnixNano(), 10),
	} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	return "kernel-" + hex.EncodeToString(sum.Sum(nil))[:24]
}

// kernelPolicyMatchesGeneration reports whether the live configuration
// generation's kernel_policy component names the same control set as the
// helper's applied digest. The helper reports sha256:<12 hex> (the value
// enforce_ack approves) and a generation may carry the full digest, so one
// may be a prefix of the other.
func kernelPolicyMatchesGeneration(helper, component string) bool {
	helper, component = strings.TrimSpace(helper), strings.TrimSpace(component)
	if helper == "" || component == "" {
		return false
	}
	return helper == component || strings.HasPrefix(component, helper) || strings.HasPrefix(helper, component)
}

// kernelGenerationFacts returns the effective policy digest and generation to
// stamp on a denial. They are honest only when the generation the gateway
// holds was built against the same control set the helper applied; otherwise
// the value is unknown and omitted.
func kernelGenerationFacts(helperPolicy string) (observability.Optional[string], observability.Optional[int64]) {
	g := livePolicyGeneration()
	if g == nil || !kernelPolicyMatchesGeneration(helperPolicy, g.Components["kernel_policy"]) {
		return observability.Absent[string](), observability.Absent[int64]()
	}
	return livePolicyDigestV8(), livePolicyGenerationV8()
}

func (adapter *aiRuntimeV8Adapter) emitKernelBlock(
	ctx context.Context, snapshot sensor.Snapshot, event sensor.KernelEvent,
) error {
	connector := proxyV8StableID(strings.ToLower(strings.TrimSpace(event.Connector)))
	producerKey := observability.ProducerKey(audit.ActionBlock)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketEnforcementAction,
		EventName:   observability.EventName(observability.TelemetryEventEnforcementBlockApplied),
		RawSeverity: string(observability.SeverityHigh), Enforced: true,
		MandatoryFacts: observability.MandatoryFacts{EnforcedOutcome: true},
	}
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerAuditAction, producerKey, classification,
		observability.SourceGateway, connector, producerKey,
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	observedAt := event.At
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	enforcementID := kernelEnforcementID(event)
	var helperPolicy string
	if snapshot.Kernel != nil {
		helperPolicy = snapshot.Kernel.Status.KernelPolicy
	}
	base := aiDiscoveryV8Envelope(ctx, "apply").Correlation
	correlation := observability.Correlation{
		RunID: base.RunID, SidecarInstanceID: base.SidecarInstanceID, TraceID: base.TraceID, SpanID: base.SpanID,
		EnforcementActionID: enforcementID,
		PolicyID:            runtimeIdentifierText(event.Policy),
		PolicyVersion:       runtimeIdentifierText(helperPolicy),
		ConnectorID:         connector,
	}
	if event.Hook != nil && event.Hook.Seen {
		correlation.SessionID = proxyV8StableID(event.Hook.SessionID)
		correlation.ToolInvocationID = proxyV8StableID(event.Hook.ToolInvocationID)
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, errors.New("kernel enforcement generation is invalid")
		}
		provenance := observability.Provenance{
			Producer: kernelBlockV8Producer, BinaryVersion: version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(emitCtx.Generation()), ConfigDigest: emitCtx.Digest(),
		}
		if admission == observabilityrouter.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(
				observability.ClockFunc(func() time.Time { return observedAt }),
				observability.OccurrenceIDGeneratorFunc(func() (string, error) { return kernelOccurrenceID(enforcementID) }),
			)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerAuditAction, ProducerKey: producerKey,
				ClassificationContext: classification, Source: observability.SourceGateway,
				Connector: connector, Action: string(audit.ActionBlock), Phase: "apply",
				Outcome: observability.OutcomeBlocked, Correlation: correlation, Provenance: provenance,
			})
		}
		if admission != observabilityrouter.AdmissionOrdinary {
			return observability.Record{}, errors.New("kernel enforcement admission is invalid")
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return kernelOccurrenceID(enforcementID) }),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		identity := adapter.identityFields(runtimeIdentity{
			UserID:          uidString(event.UID),
			LoginID:         loginString(event.UID, event.AUID),
			UserName:        event.User,
			AgentIdentityID: kernelAgentIdentityID(event),
		})
		digest, generation := kernelGenerationFacts(helperPolicy)
		input := observability.LogEnforcementBlockAppliedInput{
			Envelope: observability.FamilyEnvelopeInput{
				ObservedAt: observability.Present(observedAt),
				Source:     observability.SourceGateway, Connector: connector,
				Action: string(audit.ActionBlock), Phase: "apply", Correlation: correlation,
				Provenance: observability.FamilyProvenanceInput{
					Producer: kernelBlockV8Producer, BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(emitCtx.Generation()), ConfigDigest: emitCtx.Digest(),
				},
			},
			Severity: observability.Present(observability.SeverityHigh),
			LogLevel: observability.Present(observability.LogLevelWarn),
			Outcome:  observability.OutcomeBlocked,
			// The Tetragon policy name joins the record to the policy the
			// helper loaded; the version is the control-set digest an
			// administrator approved.
			DefenseClawPolicyID:                   runtimeIdentifier(event.Policy),
			DefenseClawPolicyVersion:              runtimeIdentifier(helperPolicy),
			DefenseClawEnforcementID:              enforcementID,
			DefenseClawEnforcementRequestedAction: observability.Present("block"),
			DefenseClawEnforcementEffectiveAction: "block",
			DefenseClawEnforcementInitiator:       observability.Present(kernelBlockInitiator),
			DefenseClawPolicyEffectiveDigest:      digest,
			DefenseClawPolicyGeneration:           generation,
			DefenseClawAgentIdentityID:            identity.AgentIdentityID,
			DefenseClawGuardrailRuleID:            runtimeIdentifier(event.RuleID),
			DefenseClawAIRuntimeKernelControl:     runtimeEnum(event.Control, kernelControls),
			UserID:                                identity.UserID,
			DefenseClawUserIDKind:                 identity.IDKind,
			DefenseClawUserName:                   identity.UserName,
			DefenseClawUserLoginID:                identity.LoginID,
			MandatoryEnforcedOutcome:              true,
		}
		identity.Directory.applyTo(&input)
		return builder.BuildLogEnforcementBlockApplied(input)
	})
	return err
}

// kernelOccurrenceID is a stable occurrence id for one denial, so a
// resend of the same event collapses instead of double counting.
func kernelOccurrenceID(enforcementID string) (string, error) {
	sum := sha256.Sum256([]byte("kernel.block.applied\x00" + enforcementID))
	return "kernel-occ-" + hex.EncodeToString(sum[:])[:24], nil
}

func uidString(uid *int) string {
	if uid == nil {
		return ""
	}
	return strconv.Itoa(*uid)
}

func loginString(uid, auid *int) string {
	if uid == nil || *uid != 0 || auid == nil {
		return ""
	}
	return strconv.Itoa(*auid)
}

// kernelAgentIdentityID is the agt-... id of the denied process's agent, when
// the gateway attributed it to an enrolled connector.
func kernelAgentIdentityID(event sensor.KernelEvent) string {
	uid := uidString(event.UID)
	if event.Connector == "" || uid == "" {
		return ""
	}
	return inventoryAgentIdentityID(event.Connector, uid)
}

// emitKernelPolicyChanges reports the helper's new state changes as
// log.ai.runtime.kernel_policy records: one per change, never one per kernel
// event.
func (adapter *aiRuntimeV8Adapter) emitKernelPolicyChanges(ctx context.Context, snapshot sensor.Snapshot) error {
	if snapshot.Kernel == nil || len(snapshot.Kernel.Status.Changes) == 0 {
		return nil
	}
	cursor := adapter.kernelCursor
	if cursor == nil {
		cursor = defaultKernelChangeCursor
	}
	changes := cursor.take(snapshot.Kernel.Status.Changes, time.Now())
	var firstErr error
	emitted := 0
	for _, change := range changes {
		if emitted >= maxKernelChangesPerSnapshot {
			break
		}
		if runtimeEnum(change.Event, kernelPolicyEvents).IsPresent() {
			emitted++
			if err := adapter.emitKernelPolicy(ctx, snapshot.Kernel.Status, change); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (adapter *aiRuntimeV8Adapter) emitKernelPolicy(
	ctx context.Context, status acquire.KernelStatus, change acquire.KernelChange,
) error {
	rawSeverity := "INFO"
	level := observability.LogLevelInfo
	severity := observability.SeverityInfo
	if kernelAttentionEvents[change.Event] {
		rawSeverity, level, severity = "WARN", observability.LogLevelWarn, observability.SeverityMedium
	}
	metadata, err := adapter.metadata("ai.runtime.kernel_policy", rawSeverity)
	if err != nil {
		return err
	}
	outcome := observability.OutcomeCompleted
	if change.Event == "reconcile_failed" {
		outcome = observability.OutcomeFailed
	}
	var observedAt observability.Optional[time.Time]
	if change.AtUnixNano > 0 {
		observedAt = observability.Present(time.Unix(0, change.AtUnixNano).UTC())
	}
	userID := ""
	if change.UID != nil && strings.HasPrefix(change.Event, "uid_") {
		userID = strconv.Itoa(*change.UID)
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		envelope := aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "kernel_policy")
		envelope.ObservedAt = observedAt
		return builder.BuildLogAIRuntimeKernelPolicy(observability.LogAIRuntimeKernelPolicyInput{
			Envelope: envelope,
			Severity: observability.Present(severity),
			LogLevel: observability.Present(level),
			Outcome:  outcome,

			DefenseClawAIRuntimeKernelEvent:  change.Event,
			DefenseClawPolicyID:              runtimeIdentifier(change.Policy),
			DefenseClawAIRuntimeKernelFamily: runtimeEnum(change.Family, kernelPolicyFamilies),
			DefenseClawAIRuntimeKernelMode:   runtimeEnum(change.Mode, kernelPolicyModes),
			DefenseClawAIRuntimeKernelState:  runtimeStateText(change.State),
			DefenseClawPolicyVersion:         runtimeIdentifier(status.KernelPolicy),
			UserID:                           aiDiscoveryV8OptionalText(userID),
			DefenseClawUserIDKind:            v8UserIDKind(discoveryUserIDKind(userID)),
			DefenseClawAIRuntimeKernelReason: runtimeBoundedText(change.Reason, runtimeReasonMaxBytes),
		})
	})
	return err
}

// runtimeStateText keeps Tetragon's state name when it is short enough.
func runtimeStateText(state string) observability.Optional[string] {
	state = strings.TrimSpace(state)
	if len(state) > 64 {
		return observability.Absent[string]()
	}
	return runtimeIdentifier(state)
}
