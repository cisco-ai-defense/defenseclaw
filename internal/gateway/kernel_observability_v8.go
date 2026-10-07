// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	osuser "os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
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
		"reconcile_failed", "ack_stale", "uid_ready", "uid_burnin", "uid_progress", "tetragon_restarted", "fallback",
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

// notifyKernelBlocks hands the denials of DefenseClaw's kernel controls to
// the notifier the way hook and guardrail blocks reach it (spec 9.1): the
// block_enforced category and the hook source, with no source key of their
// own, labelled kernel. It runs once per poll, beside the telemetry and
// independent of it: an unreachable destination must not silence the
// operator's notification. A would-block is not an enforcement and is not
// notified.
func notifyKernelBlocks(dispatcher *notifier.Dispatcher, snapshot sensor.Snapshot) {
	if dispatcher == nil {
		return
	}
	notified := 0
	for _, event := range snapshot.KernelEvents {
		if event.Outcome != plane.OutcomeBlocked {
			continue
		}
		if notified >= maxKernelBlocksPerSnapshot {
			return
		}
		notified++
		dispatcher.OnBlock(kernelBlockNotification(event))
	}
}

// kernelBlockNotification is one denial as a notification: the control and
// the connector, and a fixed sentence for the control. Nothing a user did
// (path, process, command line) is in it, as the path stays out of the
// block.applied record; the record and `ai-runtime` name the rest.
func kernelBlockNotification(event sensor.KernelEvent) notifier.BlockEvent {
	ev := notifier.BlockEvent{
		Source:    notifier.SourceHook,
		Target:    "kernel control " + firstNonEmpty(event.Control, "unknown"),
		Reason:    kernelDenialText(event.Control),
		Severity:  string(observability.SeverityHigh),
		Connector: event.Connector,
		Event:     kernelNotificationLabel,
	}
	if event.RuleID != "" {
		ev.RuleIDs = []string{event.RuleID}
	}
	return ev
}

// kernelNotificationLabel is the event label of a kernel denial's
// notification (its subtitle reads "hook · HIGH · <connector> · kernel").
const kernelNotificationLabel = "kernel"

// kernelDenialText says what a kernel control denied, from its id alone.
func kernelDenialText(control string) string {
	switch control {
	case "kernel.ssh_private_key_read":
		return "Tetragon denied an agent's process a read of an SSH private key"
	case "kernel.persistence_write":
		return "Tetragon denied an agent's process a write to a shell profile or user autostart entry"
	}
	return "Tetragon denied an agent's process an open"
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
			// The process's basename and the file relative to the user's
			// home (OD-5): an analyst can triage a denial without logging in
			// to the host; the target is content class, so each
			// destination's redaction profile decides whether it leaves.
			DefenseClawAIRuntimeProcess:      runtimeBoundedText(event.Process, kernelProcessMaxBytes),
			DefenseClawAIRuntimeKernelTarget: runtimeBoundedText(homeRelativeTarget(event.Path, event.UID, event.User), kernelTargetMaxBytes),
			UserID:                           identity.UserID,
			DefenseClawUserIDKind:            identity.IDKind,
			DefenseClawUserName:              identity.UserName,
			DefenseClawUserLoginID:           identity.LoginID,
			MandatoryEnforcedOutcome:         true,
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

			DefenseClawAIRuntimeKernelEvent:        change.Event,
			DefenseClawPolicyID:                    runtimeIdentifier(change.Policy),
			DefenseClawAIRuntimeKernelFamily:       runtimeEnum(change.Family, kernelPolicyFamilies),
			DefenseClawAIRuntimeKernelMode:         runtimeEnum(change.Mode, kernelPolicyModes),
			DefenseClawAIRuntimeKernelState:        runtimeStateText(change.State),
			DefenseClawPolicyVersion:               runtimeIdentifier(status.KernelPolicy),
			UserID:                                 aiDiscoveryV8OptionalText(userID),
			DefenseClawUserIDKind:                  v8UserIDKind(discoveryUserIDKind(userID)),
			DefenseClawAIRuntimeKernelReason:       runtimeBoundedText(change.Reason, runtimeReasonMaxBytes),
			DefenseClawAIRuntimeKernelCoveredHours: kernelHours(change, change.CoveredSeconds),
			DefenseClawAIRuntimeKernelNeededHours:  kernelHours(change, change.NeededSeconds),
		})
	})
	return err
}

// kernelHours renders a burn-in progress figure in hours, on the uid
// changes that carry progress; absent elsewhere.
func kernelHours(change acquire.KernelChange, seconds int64) observability.Optional[float64] {
	switch change.Event {
	case "uid_progress", "uid_burnin", "uid_ready":
	default:
		return observability.Absent[float64]()
	}
	if change.NeededSeconds <= 0 && change.Event != "uid_progress" {
		return observability.Absent[float64]()
	}
	return observability.Present(math.Round(float64(max(seconds, 0))/36) / 100)
}

// runtimeStateText keeps Tetragon's state name when it is short enough.
func runtimeStateText(state string) observability.Optional[string] {
	state = strings.TrimSpace(state)
	if len(state) > 64 {
		return observability.Absent[string]()
	}
	return runtimeIdentifier(state)
}

// Item 1 of the Tetragon UX spec and its fleet view (section 5.9): one
// log.ai.runtime.kernel_event record per attributed event of the host's own
// Tetragon policy, the plane c plane_health fleet fields, the kernel events
// counter and the kernel state gauge.

const (
	// maxCustomerEventsPerSnapshot bounds the kernel_event records of one
	// cycle; the host plane caps a poll's records at the same figure and
	// counts the rest.
	maxCustomerEventsPerSnapshot = 256
	kernelPolicyNameMaxBytes     = 253
	kernelFunctionMaxBytes       = 128
	kernelTargetMaxBytes         = 1024
	kernelMessageMaxBytes        = 256
	kernelProcessMaxBytes        = 128
	kernelTagMaxBytes            = 64
	kernelMaxTags                = 8
	tetragonVersionMaxBytes      = 32
	kernelUsersMax               = 1_000_000
	kernelDeltaMax               = 1_000_000_000
)

// The closed vocabularies of the kernel_event and fleet fields. A value
// outside them (a newer helper) is omitted rather than failing the record.
var (
	runtimeKernelPolicyOwners = []string{plane.PolicyOwnerDefenseClaw, plane.PolicyOwnerCustomer}
	runtimeKernelHookTypes    = []string{"kprobe", "lsm"}
	runtimeKernelActions      = []string{
		"cleanup_enforcer_notification", "copyfd", "dnslookup", "followfd", "geturl", "nopost", "notify_enforcer",
		"other", "override", "post", "set", "sigkill", "signal", "tracksock", "unfollowfd", "untracksock",
	}
	runtimeKernelPolicyModes = []string{"enforce", "monitor", "unknown"}
	runtimeHookActions       = []string{"allow", "alert"}
	kernelHelperModes        = []string{"off", "consume", "observe", "enforce"}
	kernelApprovals          = []string{"not_needed", "missing", "stale", "approved"}
	kernelMetricControls     = []string{"kernel.ssh_private_key_read", "kernel.persistence_write", "customer"}
)

// emitCustomerKernelEvents reports the attributed events of the host's own
// Tetragon policies since the previous poll, one record each.
func (adapter *aiRuntimeV8Adapter) emitCustomerKernelEvents(ctx context.Context, snapshot sensor.Snapshot) error {
	var firstErr error
	for index, event := range snapshot.CustomerKernelEvents {
		if index >= maxCustomerEventsPerSnapshot {
			break
		}
		if err := adapter.emitCustomerKernelEvent(ctx, event); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (adapter *aiRuntimeV8Adapter) emitCustomerKernelEvent(ctx context.Context, event sensor.CustomerKernelEvent) error {
	rawSeverity, level, severity := "INFO", observability.LogLevelInfo, observability.SeverityInfo
	if event.Outcome == plane.OutcomeBlocked {
		rawSeverity, level, severity = "WARN", observability.LogLevelWarn, observability.SeverityMedium
	}
	metadata, err := adapter.metadata("ai.runtime.kernel_event", rawSeverity)
	if err != nil {
		return err
	}
	_, err = adapter.runtime.Emit(ctx, metadata, func(
		emitCtx observabilityruntime.EmitContext, admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || emitCtx.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		policy := runtimeBoundedText(event.Policy, kernelPolicyNameMaxBytes)
		name, named := policy.Get()
		if strings.TrimSpace(event.AgentName) == "" || !named {
			// Only attributed events become records; one without an agent
			// or a policy should not exist.
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		identity := adapter.identityFields(runtimeIdentity{
			UserID: uidString(event.UID), LoginID: loginString(event.UID, event.AUID), UserName: event.User,
			AgentIdentityID: customerAgentIdentityID(event),
		})
		envelope := aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "kernel_event")
		if !event.At.IsZero() {
			envelope.ObservedAt = observability.Present(event.At.UTC())
		}
		input := observability.LogAIRuntimeKernelEventInput{
			Envelope: envelope,
			Severity: observability.Present(severity),
			LogLevel: observability.Present(level),
			Outcome:  observability.OutcomeCompleted,

			UserID:                                identity.UserID,
			DefenseClawUserIDKind:                 identity.IDKind,
			DefenseClawUserName:                   identity.UserName,
			DefenseClawUserLoginID:                identity.LoginID,
			DefenseClawAgentIdentityID:            identity.AgentIdentityID,
			DefenseClawAIRuntimeEventSource:       observability.Present(string(plane.SourceTetragon)),
			DefenseClawAIRuntimeKernelOutcome:     runtimeEnum(string(event.Outcome), runtimeKernelOutcomes),
			DefenseClawAIRuntimeAgent:             event.AgentName,
			DefenseClawAIRuntimeKernelPolicyOwner: plane.PolicyOwnerCustomer,
			DefenseClawAIRuntimeKernelPolicyName:  name,
			DefenseClawAIRuntimeProcess:           runtimeBoundedText(event.Process, kernelProcessMaxBytes),
			DefenseClawAIRuntimeKernelHookType:    runtimeEnum(event.HookType, runtimeKernelHookTypes),
			DefenseClawAIRuntimeKernelFunction:    runtimeBoundedText(event.Function, kernelFunctionMaxBytes),
			DefenseClawAIRuntimeKernelAction:      runtimeEnum(event.Action, runtimeKernelActions),
			DefenseClawAIRuntimeKernelPolicyMode:  runtimeEnum(event.PolicyMode, runtimeKernelPolicyModes),
			DefenseClawAIRuntimeKernelTags:        aiDiscoveryV8OptionalStrings(kernelTags(event.Tags)),
			DefenseClawAIRuntimeKernelMessage:     runtimeBoundedText(event.Message, kernelMessageMaxBytes),
			// Content class: each destination's redaction profile decides
			// whether the path or peer leaves the host.
			DefenseClawAIRuntimeKernelTarget: runtimeBoundedText(event.Target, kernelTargetMaxBytes),
			DefenseClawAIRuntimeKernelCount:  observability.Present(int64(min(max(event.Count, 1), kernelDeltaMax))),
		}
		if event.Hook != nil {
			input.DefenseClawAIRuntimeHookSeen = observability.Present(event.Hook.Seen)
			if event.Hook.Seen {
				input.DefenseClawAIRuntimeHookJoin = runtimeEnum(event.Hook.Confidence, runtimeHookJoins)
				input.DefenseClawAIRuntimeHookAction = runtimeEnum(event.Hook.Action, runtimeHookActions)
				input.Envelope.Correlation.SessionID = runtimeCorrelationID(event.Hook.SessionID)
				input.Envelope.Correlation.ToolInvocationID = runtimeCorrelationID(event.Hook.ToolInvocationID)
			}
		}
		identity.Directory.applyTo(&input)
		return builder.BuildLogAIRuntimeKernelEvent(input)
	})
	return err
}

// kernelTags bounds a policy's tags for the record.
func kernelTags(tags []string) []string {
	var out []string
	for _, tag := range tags {
		if len(out) == kernelMaxTags {
			break
		}
		if value, ok := runtimeBoundedText(tag, kernelTagMaxBytes).Get(); ok {
			out = append(out, value)
		}
	}
	return out
}

// kernelFleet is the plane c plane_health fleet view of the sensor helper's
// kernel_status: what each host's kernel controls are doing, so a fleet
// table needs nothing but the latest record per host.
type kernelFleet struct {
	present                                      bool
	helperMode, approval, policy, version        observability.Optional[string]
	enrolled, enforced, burnIn                   observability.Optional[int64]
	paused, installed                            observability.Optional[bool]
	wouldBlockDelta, blockedDelta, customerDelta observability.Optional[int64]
	// The raw values the kernel state gauge labels.
	helperModeValue, approvalValue string
	pausedValue                    bool
	installedValue                 *bool
}

// kernelDeltaCursor remembers the helper's counters at the previous cycle,
// so plane_health reports their growth. Process-wide, like the change
// cursor: an adapter is built per poll.
type kernelDeltaCursor struct {
	mu   sync.Mutex
	last map[string]int64
}

var defaultKernelDeltaCursor = &kernelDeltaCursor{}

// deltas returns each counter's growth since the previous call. The first
// call is a baseline (zero), and a counter that went down (the helper
// restarted) counts from zero.
func (cursor *kernelDeltaCursor) deltas(current map[string]int64) map[string]int64 {
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	out := make(map[string]int64, len(current))
	for key, value := range current {
		previous, seen := cursor.last[key]
		switch {
		case cursor.last == nil || !seen:
			out[key] = 0
		case value < previous:
			out[key] = value
		default:
			out[key] = value - previous
		}
	}
	cursor.last = current
	return out
}

// kernelFleetOf is the fleet view of a snapshot; not present without the
// helper's kernel_status (a gateway that is not a managed Linux one).
func (adapter *aiRuntimeV8Adapter) kernelFleetOf(snapshot sensor.Snapshot, now time.Time) kernelFleet {
	if snapshot.Kernel == nil || snapshot.Kernel.FetchedAt.IsZero() {
		return kernelFleet{}
	}
	status := snapshot.Kernel.Status
	fleet := kernelFleet{present: true}
	fleet.helperModeValue = firstNonEmpty(status.IntentMode, status.Mode)
	fleet.approvalValue = status.Approval
	fleet.helperMode = runtimeEnum(fleet.helperModeValue, kernelHelperModes)
	fleet.approval = runtimeEnum(fleet.approvalValue, kernelApprovals)
	fleet.policy = runtimeIdentifier(status.KernelPolicy)
	var enforced, burnIn int64
	for _, user := range status.Users {
		switch {
		case user.Mode == "enforce":
			enforced++
		case user.Mode != "observe_only" && !user.Ready && user.BurnInSeconds > 0:
			burnIn++
		}
	}
	fleet.enrolled = observability.Present(runtimeCount(int64(len(status.Users)), kernelUsersMax))
	fleet.enforced = observability.Present(runtimeCount(enforced, kernelUsersMax))
	fleet.burnIn = observability.Present(runtimeCount(burnIn, kernelUsersMax))
	if pause := status.Pause; pause != nil {
		fleet.pausedValue = pause.UntilReboot || pause.UntilUnixNano > now.UnixNano()
	}
	fleet.paused = observability.Present(fleet.pausedValue)
	if tetragon := status.Tetragon; tetragon != nil {
		fleet.version = runtimeBoundedText(tetragon.Version, tetragonVersionMaxBytes)
		if tetragon.Installed != nil {
			installed := *tetragon.Installed
			fleet.installedValue = &installed
			fleet.installed = observability.Present(installed)
		}
	}
	current := map[string]int64{
		"would_block": status.Counters["would_block_total"],
		"blocked":     status.Counters["blocked_total"],
	}
	if status.CustomerEvents != nil {
		current["customer"] = status.CustomerEvents.Seen
	}
	cursor := adapter.kernelDeltas
	if cursor == nil {
		cursor = defaultKernelDeltaCursor
	}
	deltas := cursor.deltas(current)
	fleet.wouldBlockDelta = observability.Present(runtimeCount(deltas["would_block"], kernelDeltaMax))
	fleet.blockedDelta = observability.Present(runtimeCount(deltas["blocked"], kernelDeltaMax))
	if _, ok := current["customer"]; ok {
		fleet.customerDelta = observability.Present(runtimeCount(deltas["customer"], kernelDeltaMax))
	}
	return fleet
}

// emitKernelMetrics records the kernel events counter (DefenseClaw's
// denials and would-blocks, and the attributed events of customer policies)
// and the kernel state gauge, where the runtime records generated metrics.
func (adapter *aiRuntimeV8Adapter) emitKernelMetrics(ctx context.Context, snapshot sensor.Snapshot, fleet kernelFleet) error {
	metrics, ok := adapter.runtime.(otlpGeneratedMetricRuntime)
	if !ok {
		return nil
	}
	type key struct{ owner, outcome, control string }
	counts := map[key]int64{}
	for _, event := range snapshot.KernelEvents {
		control := event.Control
		if !runtimeEnum(control, kernelControls).IsPresent() {
			control = ""
		}
		counts[key{plane.PolicyOwnerDefenseClaw, string(event.Outcome), control}]++
	}
	for _, event := range snapshot.CustomerKernelEvents {
		counts[key{plane.PolicyOwnerCustomer, string(event.Outcome), "customer"}] += int64(max(event.Count, 1))
	}
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owner != keys[j].owner {
			return keys[i].owner < keys[j].owner
		}
		if keys[i].outcome != keys[j].outcome {
			return keys[i].outcome < keys[j].outcome
		}
		return keys[i].control < keys[j].control
	})
	var firstErr error
	record := func(family string, build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) (observability.Record, error)) {
		_, err := metrics.RecordGeneratedMetric(ctx, observability.EventName(family), func(
			emitCtx observabilityruntime.EmitContext,
		) (observability.Record, error) {
			if emitCtx.Generation() > math.MaxInt64 {
				return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
			}
			builder, buildErr := aiDiscoveryV8Builder()
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return build(builder, aiDiscoveryV8EmitEnvelope(ctx, emitCtx, "metrics"))
		})
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, k := range keys {
		k, value := k, counts[k]
		record(observability.TelemetryInstrumentDefenseClawKernelEvents, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawKernelEvents(observability.MetricDefenseClawKernelEventsInput{
				Envelope: envelope, Value: value,
				DefenseClawAIRuntimeKernelPolicyOwner: runtimeEnum(k.owner, runtimeKernelPolicyOwners),
				DefenseClawAIRuntimeKernelOutcome:     runtimeEnum(k.outcome, runtimeKernelOutcomes),
				DefenseClawMetricKernelControl:        runtimeEnum(k.control, kernelMetricControls),
			})
		})
	}
	var current *observability.MetricDefenseClawKernelStateInput
	if fleet.present {
		backend := ""
		for _, health := range snapshot.Planes {
			if health.Plane == platform.PlaneC && health.Backend != nil {
				backend = health.Backend.Kind
			}
		}
		current = &observability.MetricDefenseClawKernelStateInput{
			Value:                                 1,
			DefenseClawAIRuntimeKernelHelperMode:  fleet.helperMode,
			DefenseClawAIRuntimeKernelApproval:    fleet.approval,
			DefenseClawAIRuntimeKernelPaused:      fleet.paused,
			DefenseClawAIRuntimePlaneBackend:      runtimeEnum(backend, runtimePlaneBackends),
			DefenseClawAIRuntimeTetragonInstalled: fleet.installed,
		}
	}
	cursor := adapter.kernelState
	if cursor == nil {
		cursor = defaultKernelStateCursor
	}
	for _, input := range cursor.next(current) {
		input := input
		record(observability.TelemetryInstrumentDefenseClawKernelState, func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			input.Envelope = envelope
			return builder.BuildMetricDefenseClawKernelState(input)
		})
	}
	return firstErr
}

// kernelStateCursor remembers the kernel state gauge's last label set: a
// gauge keeps its last value per label set, so when the state changes (an
// approval goes from stale to approved) the old series is set to 0 instead of
// staying at 1 and keeping an alert firing. Process-wide, like the other
// cursors.
type kernelStateCursor struct {
	mu   sync.Mutex
	last *observability.MetricDefenseClawKernelStateInput
}

var defaultKernelStateCursor = &kernelStateCursor{}

// next returns what to record this cycle: the previous label set at 0 when it
// changed or went away, then the current one at 1.
func (cursor *kernelStateCursor) next(current *observability.MetricDefenseClawKernelStateInput) []observability.MetricDefenseClawKernelStateInput {
	cursor.mu.Lock()
	defer cursor.mu.Unlock()
	var out []observability.MetricDefenseClawKernelStateInput
	if cursor.last != nil && (current == nil || kernelStateKey(*cursor.last) != kernelStateKey(*current)) {
		zero := *cursor.last
		zero.Value = 0
		out = append(out, zero)
	}
	cursor.last = nil
	if current != nil {
		out = append(out, *current)
		copied := *current
		cursor.last = &copied
	}
	return out
}

func kernelStateKey(input observability.MetricDefenseClawKernelStateInput) string {
	text := func(value observability.Optional[string]) string {
		v, ok := value.Get()
		return strconv.FormatBool(ok) + ":" + v
	}
	flag := func(value observability.Optional[bool]) string {
		v, ok := value.Get()
		return strconv.FormatBool(ok) + ":" + strconv.FormatBool(v)
	}
	return strings.Join([]string{
		text(input.DefenseClawAIRuntimeKernelHelperMode), text(input.DefenseClawAIRuntimeKernelApproval),
		flag(input.DefenseClawAIRuntimeKernelPaused), text(input.DefenseClawAIRuntimePlaneBackend),
		flag(input.DefenseClawAIRuntimeTetragonInstalled),
	}, "|")
}

// homeRelativeTarget names a file without the account's home directory: ~/...
// under the home of the process's own uid, ~name/... under another account's
// conventional home (/home/name, /root), else the path as it was. A denial
// record names the file a DefenseClaw control covered this way.
func homeRelativeTarget(path string, uid *int, user string) string {
	if home := strings.TrimRight(kernelUserHome(uid, user), "/"); home != "" {
		if rest, ok := strings.CutPrefix(path, home+"/"); ok && rest != "" {
			return "~/" + rest
		}
	}
	if rest, ok := strings.CutPrefix(path, "/root/"); ok && rest != "" {
		return "~root/" + rest
	}
	if rest, ok := strings.CutPrefix(path, "/home/"); ok {
		if name, tail, found := strings.Cut(rest, "/"); found && name != "" && tail != "" {
			return "~" + name + "/" + tail
		}
	}
	return path
}

// kernelUserHome is the home of a uid (else of a user name) through NSS,
// cached; "" when neither resolves.
var kernelUserHome = func(uid *int, user string) string {
	key := uidString(uid) + "|" + user
	if cached, ok := kernelHomes.Load(key); ok {
		return cached.(string)
	}
	home := ""
	if uid != nil {
		if account, err := osuser.LookupId(strconv.Itoa(*uid)); err == nil {
			home = account.HomeDir
		}
	} else if user != "" && !strings.ContainsAny(user, "/\x00") {
		if account, err := osuser.Lookup(user); err == nil {
			home = account.HomeDir
		}
	}
	if home == "/" {
		home = ""
	}
	kernelHomes.Store(key, home)
	return home
}

var kernelHomes sync.Map
