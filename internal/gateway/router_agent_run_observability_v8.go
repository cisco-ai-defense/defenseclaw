// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const (
	agentRunObservationConnector = "openclaw"
	agentRunObservationCapacity  = 4096
	agentRunObservationTTL       = 10 * time.Minute
	agentRunObservationProducer  = "gateway.event_router.agent_run"
	agentRunObservationErrorCode = "invalid_agent_run_observation"
)

type agentRunObservationEmission uint8

const (
	agentRunObservationRejected agentRunObservationEmission = iota
	agentRunObservationDuplicate
	agentRunObservationDropped
	agentRunObservationPersisted
	agentRunObservationFailed
)

type agentRunObservationKey struct {
	connector          string
	sessionKey         string
	conversationID     string
	runID              string
	agentID            string
	parentSession      string
	parentConversation string
	spawnDepth         int64
	spawnDepthSet      bool
	sequence           int64
	timestamp          int64
	stream             string
	event              string
}

type agentRunObservationCacheEntry struct {
	key        agentRunObservationKey
	insertedAt time.Time
}

type agentRunObservation struct {
	key         agentRunObservationKey
	observedAt  time.Time
	startedNano observability.Optional[int64]
	endedNano   observability.Optional[int64]
	errorText   observability.Optional[string]
	topology    agentRunTopology
}

// agentRunTopology contains only source-backed identity or identity resolved
// from another source-backed session observation. It never retains an OTel
// span, runtime generation, or request context between WebSocket deliveries.
type agentRunTopology struct {
	sessionKey       string
	conversationID   string
	agentID          string
	rootAgentID      string
	parentAgentID    string
	rootSessionID    string
	parentSessionKey string
	parentSessionID  string
	lifecycleID      string
	executionID      string
	lineage          string
	depth            observability.Optional[int64]
}

type agentRunTopologyState struct {
	topology   agentRunTopology
	insertedAt time.Time
}

type agentRunExecutionKey struct {
	conversationID string
	agentID        string
	runID          string
}

type agentRunExecutionState struct {
	executionID string
	terminal    bool
	insertedAt  time.Time
}

func (r *EventRouter) emitAgentRunObservationV8(
	envelope agentStreamEnvelope,
	data agentStreamData,
) agentRunObservationEmission {
	if r == nil {
		return agentRunObservationFailed
	}
	observation, ok := newAgentRunObservation(envelope, data)
	if !ok {
		r.emitAgentRunObservationRejectionV8()
		return agentRunObservationRejected
	}
	emitter := r.observabilityV8RuntimeEmitter()
	if emitter == nil {
		return agentRunObservationFailed
	}
	now := time.Now()
	if r.agentRunObservationNow != nil {
		now = r.agentRunObservationNow()
	}

	// The lock covers admission and local persistence so two concurrent exact
	// repeats cannot both pass the bounded dedupe window. It never retains a
	// runtime handle after Emit returns and is independent of graph reload.
	r.agentRunObservationMu.Lock()
	r.evictAgentRunObservationsLocked(now)
	if !r.resolveAgentRunTopologyLocked(&observation) {
		r.agentRunObservationMu.Unlock()
		r.emitAgentRunObservationRejectionV8()
		return agentRunObservationRejected
	}
	r.resolveAgentRunExecutionLocked(&observation)
	if _, duplicate := r.agentRunObservationCache[observation.key]; duplicate {
		r.agentRunObservationMu.Unlock()
		return agentRunObservationDuplicate
	}

	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey(gatewaylog.EventLifecycle),
		observability.ClassificationContext{
			Bucket:      observability.BucketAgentLifecycle,
			EventName:   observability.EventName(observability.TelemetryEventAgentRunObserved),
			RawSeverity: "INFO",
		},
		observability.SourceConnector,
		agentRunObservationConnector,
		observability.ProducerKey(gatewaylog.EventLifecycle),
	)
	if err != nil {
		r.agentRunObservationMu.Unlock()
		return agentRunObservationFailed
	}
	outcome, emitErr := emitter.Emit(context.Background(), metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(time.Now),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAgentRunObserved(observability.LogAgentRunObservedInput{
			Envelope: observability.FamilyEnvelopeInput{
				ObservedAt: observability.Present(observation.observedAt),
				Source:     observability.SourceConnector, Connector: agentRunObservationConnector,
				Action: string(gatewaylog.EventLifecycle), Phase: observation.key.event,
				Correlation: observability.Correlation{
					RunID: gatewaylog.ProcessRunID(), SessionID: observation.key.sessionKey,
					AgentID: observation.topology.agentID, ConnectorID: agentRunObservationConnector,
					SidecarInstanceID: gatewaylog.SidecarInstanceID(),
				},
				Provenance: observability.FamilyProvenanceInput{
					Producer:         agentRunObservationProducer,
					BinaryVersion:    version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Severity:                             observability.Present(observability.SeverityInfo),
			LogLevel:                             observability.Present(observability.LogLevelInfo),
			GenAIConversationID:                  hookV8OptionalIdentifier(observation.topology.conversationID),
			GenAIAgentID:                         hookV8OptionalIdentifier(observation.topology.agentID),
			DefenseClawAgentRootID:               hookV8OptionalIdentifier(observation.topology.rootAgentID),
			DefenseClawAgentParentID:             hookV8OptionalIdentifier(observation.topology.parentAgentID),
			DefenseClawAgentLineageProvenance:    hookV8OptionalLineageProvenance(observation.topology.lineage),
			DefenseClawSessionRootID:             hookV8OptionalIdentifier(observation.topology.rootSessionID),
			DefenseClawSessionParentID:           hookV8OptionalIdentifier(observation.topology.parentSessionID),
			DefenseClawAgentLifecycleID:          hookV8OptionalIdentifier(observation.topology.lifecycleID),
			DefenseClawAgentExecutionID:          hookV8OptionalIdentifier(observation.topology.executionID),
			DefenseClawAgentDepth:                observation.topology.depth,
			DefenseClawAgentRunID:                observation.key.runID,
			DefenseClawAgentRunEvent:             observation.key.event,
			DefenseClawAgentRunSequence:          observation.key.sequence,
			DefenseClawAgentRunStartedAtUnixNano: observation.startedNano,
			DefenseClawAgentRunEndedAtUnixNano:   observation.endedNano,
			DefenseClawAgentRunErrorMessage:      observation.errorText,
		})
	})
	if emitErr != nil {
		r.agentRunObservationMu.Unlock()
		return agentRunObservationFailed
	}
	emission := agentRunObservationFailed
	switch outcome.Admission() {
	case router.AdmissionDrop:
		if !outcome.LocalPersisted() {
			emission = agentRunObservationDropped
		}
	case router.AdmissionOrdinary:
		if outcome.LocalPersisted() {
			emission = agentRunObservationPersisted
		}
	}
	if emission == agentRunObservationFailed {
		r.agentRunObservationMu.Unlock()
		return emission
	}
	r.insertAgentRunObservationLocked(observation.key, now)
	r.rememberAgentRunTopologyLocked(observation.topology, now)
	r.rememberAgentRunExecutionLocked(observation, now)
	r.agentRunObservationMu.Unlock()
	return emission
}

// emitAgentRunObservationRejectionV8 records only a fixed, low-cardinality
// schema failure. None of the rejected envelope or payload is copied into the
// diagnostic, because those values have not crossed the generated contract.
// The mandatory floor keeps this accounting local when ordinary platform
// health collection is disabled.
func (r *EventRouter) emitAgentRunObservationRejectionV8() {
	if r == nil {
		return
	}
	emitter := r.observabilityV8RuntimeEmitter()
	if emitter == nil {
		return
	}
	producerKey := observability.ProducerKey(gatewaylog.EventError)
	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   observability.EventName(observability.TelemetryEventSchemaValidationFailed),
		RawSeverity: "ERROR",
		MandatoryFacts: observability.MandatoryFacts{
			SchemaValidationFailure: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		classification,
		observability.SourceConnector,
		agentRunObservationConnector,
		producerKey,
	)
	if err != nil {
		return
	}
	_, _ = emitter.Emit(context.Background(), metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		clock := observability.ClockFunc(func() time.Time { return time.Now().UTC() })
		ids := observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil })
		provenance := observability.Provenance{
			Producer:              agentRunObservationProducer,
			BinaryVersion:         version.Current().BinaryVersion,
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()),
			ConfigDigest:          snapshot.Digest(),
		}
		correlation := observability.Correlation{
			RunID: gatewaylog.ProcessRunID(), SidecarInstanceID: gatewaylog.SidecarInstanceID(),
		}
		if admission == router.AdmissionFloor {
			builder, buildErr := observability.NewRecordBuilder(clock, ids)
			if buildErr != nil {
				return observability.Record{}, buildErr
			}
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: observability.ProducerGatewayEvent, ProducerKey: producerKey,
				ClassificationContext: classification,
				Source:                observability.SourceConnector, Connector: agentRunObservationConnector,
				Action: string(producerKey), Phase: "validation", Outcome: observability.OutcomeRejected,
				Correlation: correlation, Provenance: provenance,
			})
		}
		if admission != router.AdmissionOrdinary {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(clock, ids)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogSchemaValidationFailed(observability.LogSchemaValidationFailedInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceConnector, Connector: agentRunObservationConnector,
				Action: string(producerKey), Phase: "validation", Correlation: correlation,
				Provenance: observability.FamilyProvenanceInput{
					Producer: agentRunObservationProducer, BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Severity:                         observability.Present(observability.SeverityHigh),
			LogLevel:                         observability.Present(observability.LogLevelError),
			Outcome:                          observability.OutcomeRejected,
			DefenseClawHealthSubsystem:       "event_router",
			DefenseClawHealthState:           "degraded",
			DefenseClawSchemaErrorCode:       observability.Present(agentRunObservationErrorCode),
			MandatorySchemaValidationFailure: true,
		})
	})
}

func newAgentRunObservation(
	envelope agentStreamEnvelope,
	data agentStreamData,
) (agentRunObservation, bool) {
	if envelope.Stream != "lifecycle" ||
		(data.Phase != "start" && data.Phase != "end" && data.Phase != "error") ||
		envelope.Seq <= 0 || envelope.Ts <= 0 ||
		!agentRunIdentifier(envelope.RunID) ||
		(envelope.SessionKey != "" && !agentRunIdentifier(envelope.SessionKey)) ||
		(envelope.SessionID != "" && !agentRunIdentifier(envelope.SessionID)) {
		return agentRunObservation{}, false
	}
	observedNano, ok := unixMilliToPositiveNano(envelope.Ts)
	if !ok {
		return agentRunObservation{}, false
	}
	started, ok := optionalUnixMilliToNano(data.StartedAt)
	if !ok {
		return agentRunObservation{}, false
	}
	ended, ok := optionalUnixMilliToNano(data.EndedAt)
	if !ok {
		return agentRunObservation{}, false
	}
	if start, present := started.Get(); present {
		if end, endPresent := ended.Get(); endPresent && start > end {
			return agentRunObservation{}, false
		}
	}
	errorText := observability.Absent[string]()
	if data.Phase == "error" {
		if data.Error != "" {
			if !utf8.ValidString(data.Error) || len(data.Error) > 4096 {
				return agentRunObservation{}, false
			}
			errorText = observability.Present(data.Error)
		}
	} else if data.Error != "" {
		return agentRunObservation{}, false
	}
	agentID, ok := agentRunReportedIdentifier(envelope.AgentID, data.AgentID)
	if !ok {
		return agentRunObservation{}, false
	}
	conversationID, ok := agentRunReportedIdentifier(envelope.SessionID, data.SessionID)
	if !ok {
		return agentRunObservation{}, false
	}
	parentSessionID, ok := agentRunReportedIdentifier(
		envelope.ParentSessionKey,
		envelope.SpawnedBy,
		data.ParentSessionKey,
		data.SpawnedBy,
	)
	if !ok {
		return agentRunObservation{}, false
	}
	parentConversationID, ok := agentRunReportedIdentifier(
		envelope.ParentSessionID,
		data.ParentSessionID,
	)
	if !ok || (parentConversationID != "" && parentSessionID == "") {
		return agentRunObservation{}, false
	}
	depth, ok := agentRunReportedDepth(envelope.SpawnDepth, data.SpawnDepth)
	if !ok {
		return agentRunObservation{}, false
	}
	sessionKey := strings.TrimSpace(envelope.SessionKey)
	topologyClaimed := agentID != "" || parentSessionID != "" || depth.IsPresent()
	if topologyClaimed && (agentID == "" || sessionKey == "") {
		return agentRunObservation{}, false
	}
	if conversationID != "" && sessionKey == "" {
		return agentRunObservation{}, false
	}
	if parentSessionID != "" && parentSessionID == sessionKey {
		return agentRunObservation{}, false
	}
	if reportedDepth, present := depth.Get(); present {
		if (reportedDepth == 0 && parentSessionID != "") ||
			(reportedDepth > 0 && parentSessionID == "") {
			return agentRunObservation{}, false
		}
	}
	topology := agentRunTopology{
		sessionKey:       sessionKey,
		conversationID:   conversationID,
		agentID:          agentID,
		parentSessionKey: parentSessionID,
		parentSessionID:  parentConversationID,
		depth:            depth,
	}
	if agentID != "" && conversationID != "" {
		topology.lifecycleID = stableLLMEventID(
			"lifecycle", agentRunObservationConnector, conversationID, agentID,
		)
	}
	if agentID != "" && parentSessionID == "" {
		topology.rootAgentID = agentID
		topology.rootSessionID = conversationID
		if reportedDepth, present := depth.Get(); present && reportedDepth == 0 {
			topology.lineage = "reported"
		} else {
			// Current OpenClaw broadcasts omit spawnedBy for non-subagent
			// sessions. That source-backed absence makes this the graph root,
			// even when the optional session-store spawnDepth was not copied
			// onto the event envelope.
			topology.depth = observability.Present[int64](0)
			topology.lineage = "inferred"
		}
	} else if parentSessionID != "" {
		// The upstream parent session and depth are reported facts. Agent and
		// root IDs are filled only after resolving that exact session against a
		// separately observed parent below.
		topology.lineage = "reported"
	}
	key := agentRunObservationKey{
		connector: agentRunObservationConnector, sessionKey: sessionKey,
		conversationID: conversationID,
		runID:          strings.TrimSpace(envelope.RunID), agentID: agentID,
		parentSession: parentSessionID, parentConversation: parentConversationID,
		sequence:  int64(envelope.Seq),
		timestamp: envelope.Ts, stream: envelope.Stream, event: data.Phase,
	}
	if reportedDepth, present := depth.Get(); present {
		key.spawnDepth = reportedDepth
		key.spawnDepthSet = true
	}
	return agentRunObservation{
		key:        key,
		observedAt: time.Unix(0, observedNano).UTC(), startedNano: started,
		endedNano: ended, errorText: errorText, topology: topology,
	}, true
}

func agentRunReportedIdentifier(values ...string) (string, bool) {
	selected := ""
	for _, value := range values {
		if value == "" {
			continue
		}
		if !agentRunIdentifier(value) || (selected != "" && selected != value) {
			return "", false
		}
		selected = value
	}
	return selected, true
}

func agentRunReportedDepth(values ...*int64) (observability.Optional[int64], bool) {
	var selected int64
	present := false
	for _, value := range values {
		if value == nil {
			continue
		}
		if *value < 0 || *value > 64 || (present && selected != *value) {
			return observability.Absent[int64](), false
		}
		selected = *value
		present = true
	}
	if !present {
		return observability.Absent[int64](), true
	}
	return observability.Present(selected), true
}

func (r *EventRouter) resolveAgentRunTopologyLocked(observation *agentRunObservation) bool {
	if r == nil || observation == nil {
		return false
	}
	topology := &observation.topology
	if topology.parentSessionKey == "" {
		return true
	}
	parentState, found := r.agentRunTopologies[topology.parentSessionKey]
	if !found {
		return true
	}
	parent := parentState.topology
	if topology.parentSessionID != "" && parent.conversationID != "" &&
		topology.parentSessionID != parent.conversationID {
		// The routing key was reused for another session incarnation. The
		// source-reported parent incarnation remains valid, but none of the
		// cached parent topology is safe to attach to this child.
		return true
	}
	childDepth, childDepthPresent := topology.depth.Get()
	parentDepth, parentDepthPresent := parent.depth.Get()
	if childDepthPresent && parentDepthPresent && childDepth != parentDepth+1 {
		return false
	}
	if !childDepthPresent && parentDepthPresent {
		topology.depth = observability.Present(parentDepth + 1)
	}
	if parent.agentID != "" {
		topology.parentAgentID = parent.agentID
	}
	topology.rootAgentID = firstNonEmpty(parent.rootAgentID, parent.agentID)
	if topology.parentSessionID != "" && topology.parentSessionID == parent.conversationID {
		topology.rootSessionID = firstNonEmpty(parent.rootSessionID, parent.conversationID)
	}
	if topology.parentAgentID != "" || topology.rootAgentID != "" || topology.rootSessionID != "" {
		topology.lineage = "inferred"
	}
	return true
}

func (r *EventRouter) resolveAgentRunExecutionLocked(observation *agentRunObservation) {
	if r == nil || observation == nil || observation.topology.conversationID == "" ||
		observation.topology.agentID == "" {
		return
	}
	key := agentRunExecutionKey{
		conversationID: observation.topology.conversationID,
		agentID:        observation.topology.agentID,
		runID:          observation.key.runID,
	}
	state, found := r.agentRunExecutions[key]
	if found && !(state.terminal && observation.key.event == "start") {
		observation.topology.executionID = state.executionID
		return
	}
	// Run IDs are caller-supplied and may be reused. The first source event's
	// own timestamp and sequence distinguish a later post-terminal reuse while
	// keeping every event in one observed run on the same execution identity.
	observation.topology.executionID = stableLLMEventID(
		"execution",
		agentRunObservationConnector,
		observation.topology.conversationID,
		observation.topology.agentID,
		observation.key.runID,
		strconv.FormatInt(observation.key.timestamp, 10),
		strconv.FormatInt(observation.key.sequence, 10),
	)
}

func (r *EventRouter) rememberAgentRunExecutionLocked(observation agentRunObservation, now time.Time) {
	if r == nil || observation.topology.executionID == "" {
		return
	}
	if r.agentRunExecutions == nil {
		r.agentRunExecutions = make(map[agentRunExecutionKey]agentRunExecutionState)
	}
	key := agentRunExecutionKey{
		conversationID: observation.topology.conversationID,
		agentID:        observation.topology.agentID,
		runID:          observation.key.runID,
	}
	if _, exists := r.agentRunExecutions[key]; !exists &&
		len(r.agentRunExecutions) >= agentRunObservationCapacity {
		oldestKey := agentRunExecutionKey{}
		var oldest time.Time
		found := false
		for candidate, state := range r.agentRunExecutions {
			if !found || state.insertedAt.Before(oldest) {
				oldestKey, oldest, found = candidate, state.insertedAt, true
			}
		}
		if found {
			delete(r.agentRunExecutions, oldestKey)
		}
	}
	r.agentRunExecutions[key] = agentRunExecutionState{
		executionID: observation.topology.executionID,
		terminal:    observation.key.event == "end" || observation.key.event == "error",
		insertedAt:  now,
	}
}

func (r *EventRouter) rememberAgentRunTopologyLocked(topology agentRunTopology, now time.Time) {
	if r == nil || topology.sessionKey == "" || topology.agentID == "" {
		return
	}
	if r.agentRunTopologies == nil {
		r.agentRunTopologies = make(map[string]agentRunTopologyState)
	}
	if _, exists := r.agentRunTopologies[topology.sessionKey]; !exists &&
		len(r.agentRunTopologies) >= agentRunObservationCapacity {
		oldestSession := ""
		var oldest time.Time
		for sessionID, state := range r.agentRunTopologies {
			if oldestSession == "" || state.insertedAt.Before(oldest) ||
				(state.insertedAt.Equal(oldest) && sessionID < oldestSession) {
				oldestSession = sessionID
				oldest = state.insertedAt
			}
		}
		delete(r.agentRunTopologies, oldestSession)
	}
	r.agentRunTopologies[topology.sessionKey] = agentRunTopologyState{
		topology: topology, insertedAt: now,
	}
}

func agentRunIdentifier(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && value != "" && len(value) <= 256 && utf8.ValidString(value) &&
		hookV8IdentifierPattern.MatchString(value)
}

func unixMilliToPositiveNano(value int64) (int64, bool) {
	if value <= 0 || value > math.MaxInt64/int64(time.Millisecond) {
		return 0, false
	}
	return value * int64(time.Millisecond), true
}

func optionalUnixMilliToNano(value int64) (observability.Optional[int64], bool) {
	if value == 0 {
		return observability.Absent[int64](), true
	}
	nano, ok := unixMilliToPositiveNano(value)
	if !ok {
		return observability.Absent[int64](), false
	}
	return observability.Present(nano), true
}

func (r *EventRouter) evictAgentRunObservationsLocked(now time.Time) {
	cutoff := now.Add(-agentRunObservationTTL)
	for sessionKey, state := range r.agentRunTopologies {
		if state.insertedAt.Before(cutoff) {
			delete(r.agentRunTopologies, sessionKey)
		}
	}
	for key, state := range r.agentRunExecutions {
		if state.insertedAt.Before(cutoff) {
			delete(r.agentRunExecutions, key)
		}
	}
	kept := r.agentRunObservationOrder[:0]
	for _, entry := range r.agentRunObservationOrder {
		inserted, exists := r.agentRunObservationCache[entry.key]
		if !exists || !inserted.Equal(entry.insertedAt) {
			continue
		}
		if inserted.Before(cutoff) {
			delete(r.agentRunObservationCache, entry.key)
			continue
		}
		kept = append(kept, entry)
	}
	r.agentRunObservationOrder = kept
}

func (r *EventRouter) insertAgentRunObservationLocked(key agentRunObservationKey, now time.Time) {
	for len(r.agentRunObservationCache) >= agentRunObservationCapacity && len(r.agentRunObservationOrder) > 0 {
		oldest := r.agentRunObservationOrder[0]
		r.agentRunObservationOrder = r.agentRunObservationOrder[1:]
		if inserted, exists := r.agentRunObservationCache[oldest.key]; exists && inserted.Equal(oldest.insertedAt) {
			delete(r.agentRunObservationCache, oldest.key)
		}
	}
	r.agentRunObservationCache[key] = now
	r.agentRunObservationOrder = append(r.agentRunObservationOrder, agentRunObservationCacheEntry{key: key, insertedAt: now})
}
