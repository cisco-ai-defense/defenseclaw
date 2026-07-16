// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const correlationReceiptTTL = 7 * 24 * time.Hour

// correlateHookOccurrence is the hook-side occurrence transaction boundary.
// Policy evaluation still runs for an exact transport replay, but the replay
// receipt suppresses duplicate telemetry/audit emission after incrementing its
// durable delivery count.
func (a *APIServer) correlateHookOccurrence(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	rawBody []byte,
) (context.Context, agentHookRequest, error) {
	if a == nil || a.store == nil {
		return ctx, req, nil
	}
	repo, err := a.store.CorrelationRepository()
	if err != nil {
		return ctx, req, err
	}
	spec := profile.Correlation
	if spec.Connector == "" || len(spec.HookBindings) == 0 {
		spec = connector.ExplicitCanonicalCorrelationSpec(req.ConnectorName)
	}
	// Reject contradictory aliases before resolving an instance, reading a
	// cursor, minting IDs, or writing any correlation state. Values of distinct
	// typed kinds remain valid independent evidence.
	if err := connector.ValidateCorrelationValues(req.CorrelationIdentifiers); err != nil {
		return ctx, req, err
	}
	custody := audit.ConnectorCustodyHookOnly
	if spec.NativeTelemetry.Stability != connector.NativeTelemetryNone {
		// Migration never rewrites a connector's exporter. Authenticated native
		// ingestion promotes this to defenseclaw; hook traffic only records the
		// unchanged external topology.
		custody = audit.ConnectorCustodyExternal
	}
	instance, err := repo.ResolveConnectorInstance(ctx, req.ConnectorName, string(spec.ProfileVersion), custody)
	if err != nil {
		return ctx, req, err
	}

	now := time.Now().UTC()
	lifecycle, hasLifecycle := spec.LifecycleForEvent(req.HookEventName)
	cursor, hasCursor := correlationCursorForHook(ctx, repo, instance.ConnectorInstanceID, req)
	if hasCursor {
		if req.AgentID == "" {
			req.AgentID = cursor.AgentID
			appendHookCorrelationValue(&req, connector.CorrelationTargetAgent, req.AgentID, connector.CorrelationOriginMinted)
		}
		if req.TurnID == "" && lifecycle != connector.CorrelationLifecycleTurnStart {
			req.TurnID = cursor.ActiveTurnID
			appendHookCorrelationValue(&req, connector.CorrelationTargetTurn, req.TurnID, connector.CorrelationOriginMinted)
		}
		if req.ExecutionID == "" {
			req.ExecutionID = cursor.ExecutionID
		}
	}

	// Mint only on a reviewed lifecycle boundary. UUIDv7 IDs are persisted in
	// the same transaction as the occurrence so restart never falls back to a
	// process-local "latest turn" map.
	if req.SessionID != "" && req.AgentID == "" &&
		(lifecycle == connector.CorrelationLifecycleSessionStart || lifecycle == connector.CorrelationLifecycleTurnStart) {
		if id, idErr := audit.NewSemanticEventID(); idErr == nil {
			req.AgentID = string(id)
			appendHookCorrelationValue(&req, connector.CorrelationTargetAgent, req.AgentID, connector.CorrelationOriginMinted)
		}
	}
	if req.TurnID == "" && lifecycle == connector.CorrelationLifecycleTurnStart &&
		spec.Allows(connector.CorrelationInferencePromptBoundaryTurn) {
		id, idErr := audit.NewSemanticEventID()
		if idErr != nil {
			return ctx, req, idErr
		}
		req.TurnID = string(id)
		appendHookCorrelationValue(&req, connector.CorrelationTargetTurn, req.TurnID, connector.CorrelationOriginMinted)
	}

	if req.ToolInvocationID == "" && lifecycle == connector.CorrelationLifecycleToolStart &&
		spec.Allows(connector.CorrelationInferenceUniquePendingTool) {
		id, idErr := audit.NewSemanticEventID()
		if idErr != nil {
			return ctx, req, idErr
		}
		req.ToolInvocationID = string(id)
		appendHookCorrelationValue(&req, connector.CorrelationTargetTool, req.ToolInvocationID, connector.CorrelationOriginMinted)
	}
	if req.ModelRequestID == "" && lifecycle == connector.CorrelationLifecycleModelStart &&
		spec.Allows(connector.CorrelationInferenceModelBoundary) {
		id, idErr := audit.NewSemanticEventID()
		if idErr != nil {
			return ctx, req, idErr
		}
		req.ModelRequestID = string(id)
		appendHookCorrelationValue(&req, connector.CorrelationTargetModelRequest, req.ModelRequestID, connector.CorrelationOriginMinted)
	}

	var pending *audit.CorrelationPendingMatch
	var pendingLocator *audit.CorrelationPendingLocator
	if lifecycle == connector.CorrelationLifecycleToolEnd && spec.Allows(connector.CorrelationInferenceUniquePendingTool) {
		operation, identity, found, findErr := findHookPendingOperation(
			ctx, repo, instance.ConnectorInstanceID, req, spec,
			connector.CorrelationTargetTool, audit.CorrelationOperationTool,
			req.ToolInvocationID, req.ToolName,
		)
		if findErr != nil && !errors.Is(findErr, audit.ErrCorrelationNotFound) &&
			!errors.Is(findErr, audit.ErrCorrelationConflict) {
			return ctx, req, findErr
		}
		if found {
			if req.ToolInvocationID == "" {
				req.ToolInvocationID = operation.OperationID
				appendHookCorrelationValue(&req, connector.CorrelationTargetTool, req.ToolInvocationID, connector.CorrelationOriginDerived)
			}
			restoreHookOperationContext(&req, operation)
		}
		if identity.valid() {
			pending = identity.pendingMatch(audit.CorrelationOperationTool, req.ToolInvocationID, req.ToolName, req)
			pendingLocator = identity.locator(instance.ConnectorInstanceID, audit.CorrelationOperationTool, req.ToolInvocationID)
		}
	}
	if lifecycle == connector.CorrelationLifecycleModelEnd && spec.Allows(connector.CorrelationInferenceModelBoundary) {
		operation, identity, found, findErr := findHookPendingOperation(
			ctx, repo, instance.ConnectorInstanceID, req, spec,
			connector.CorrelationTargetModelRequest, audit.CorrelationOperationModel,
			req.ModelRequestID, "",
		)
		if findErr != nil && !errors.Is(findErr, audit.ErrCorrelationNotFound) &&
			!errors.Is(findErr, audit.ErrCorrelationConflict) {
			return ctx, req, findErr
		}
		if found {
			if req.ModelRequestID == "" {
				req.ModelRequestID = operation.OperationID
				appendHookCorrelationValue(&req, connector.CorrelationTargetModelRequest, req.ModelRequestID, connector.CorrelationOriginDerived)
			}
			restoreHookOperationContext(&req, operation)
		}
		if identity.valid() {
			pending = identity.pendingMatch(audit.CorrelationOperationModel, req.ModelRequestID, "", req)
			pendingLocator = identity.locator(instance.ConnectorInstanceID, audit.CorrelationOperationModel, req.ModelRequestID)
		}
	}

	reportedSemantic := audit.SemanticEventID("")
	if req.SemanticEventID != "" && !validCorrelationUUIDv7(req.SemanticEventID) {
		return ctx, req, errors.New("reported semantic event id is not UUIDv7")
	}
	if validCorrelationUUIDv7(req.SemanticEventID) {
		reportedSemantic = audit.SemanticEventID(req.SemanticEventID)
	}
	semantic := reportedSemantic
	if semantic == "" {
		semantic, err = audit.NewSemanticEventID()
		if err != nil {
			return ctx, req, err
		}
	}
	fingerprint := sha256.Sum256(rawBody)
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	allValues := dedupeCorrelationValues(req.CorrelationIdentifiers, req.CorrelationValues)
	eventName := correlationCanonicalEventName(spec, req.HookEventName)
	preferredSource := connector.CorrelationValue{
		Target: connector.CorrelationTargetSourceEvent, Value: req.SourceEventID,
		Namespace: req.SourceNamespace, IDKind: req.SourceIDKind,
	}
	_, sourceDigest := correlationIdentifiersForValues(instance.ConnectorInstanceID, allValues, preferredSource)
	identifiers, _ := correlationIdentifiersForValues(instance.ConnectorInstanceID,
		correlationMatchValuesForRail(spec, audit.CorrelationRailHook, allValues), preferredSource)
	receipt := correlationReceiptForHook(spec, instance.ConnectorInstanceID, req, sourceDigest, fingerprintHex, now)
	matchInput := audit.CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		SemanticEventID:     reportedSemantic,
		Receipt:             receiptLookup(receipt),
		Identifiers:         identifiers,
		Pending:             pending,
	}
	var traceID, spanID string
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		traceID = spanContext.TraceID().String()
		spanID = spanContext.SpanID().String()
	}
	// A hook is a policy observation carried within trace topology, not the
	// trace span itself. Preserve the exact trace/span evidence below, but do
	// not use it as same-occurrence authority. Only native trace leaves may use
	// an exact trace+span pair for identity matching.
	if hasLifecycle {
		matchInput.MirrorCompatibility = mirrorCompatibilityForHook(spec, lifecycle)
	}
	match, err := repo.MatchOccurrence(ctx, matchInput)
	if err != nil {
		return ctx, req, err
	}
	logical := audit.LogicalEventID(semantic)
	if match.MergeAllowed && match.LogicalEventID != "" {
		logical = match.LogicalEventID
	}
	sourceTime := parseCorrelationSourceTime(req.SourceTimestamp)
	envelope := audit.EnvelopeFromContext(ctx)
	exactIdentityClaims := []audit.CorrelationExactIdentityClaim(nil)
	if hasLifecycle && !match.Conflict {
		exactIdentityClaims = correlationExactIdentityClaims(
			spec, instance.ConnectorInstanceID, audit.CorrelationRailHook, lifecycle, allValues,
		)
	}
	tx, occurrence, err := repo.BeginOccurrence(ctx, audit.CorrelationOccurrenceInput{
		Event: audit.CorrelationEvent{
			SemanticEventID: semantic, LogicalEventID: logical, Connector: req.ConnectorName,
			ConnectorInstanceID: instance.ConnectorInstanceID, Rail: audit.CorrelationRailHook,
			EventName: eventName, SourceTime: sourceTime,
			ReceivedTime: now, SourceEventDigest: sourceDigest, FingerprintSHA256: fingerprintHex,
			FirstRequestID: envelope.RequestID, ProfileVersion: string(spec.ProfileVersion),
			Completeness: correlationCompleteness(spec.Completeness),
		},
		Receipt: receipt, ExactIdentityClaims: exactIdentityClaims,
	})
	if err != nil {
		return ctx, req, err
	}
	defer tx.Rollback() //nolint:errcheck
	if occurrence.Status == audit.CorrelationOccurrenceReplay {
		if err := tx.Commit(); err != nil {
			return ctx, req, err
		}
		resolved, resolveErr := repo.MatchOccurrence(ctx, audit.CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID, SemanticEventID: occurrence.SemanticEventID,
		})
		if resolveErr == nil && resolved.LogicalEventID != "" {
			logical = resolved.LogicalEventID
		} else {
			logical = audit.LogicalEventID(occurrence.SemanticEventID)
		}
		req.SemanticEventID = string(occurrence.SemanticEventID)
		req.LogicalEventID = string(logical)
		req.ConnectorInstanceID = string(instance.ConnectorInstanceID)
		req.SuppressCorrelationEmit = occurrence.SuppressEmission
		req.CorrelationReceipt = occurrence.Receipt
		return contextWithHookCorrelation(ctx, req, traceID), req, nil
	}
	semantic = occurrence.SemanticEventID
	logical = occurrence.LogicalEventID
	if occurrence.Status == audit.CorrelationOccurrenceConflict {
		logical = audit.LogicalEventID(semantic)
	}
	req.SemanticEventID = string(semantic)
	req.LogicalEventID = string(logical)
	req.ConnectorInstanceID = string(instance.ConnectorInstanceID)
	req.CorrelationReceipt = occurrence.Receipt

	for _, value := range dedupeCorrelationValues(req.CorrelationIdentifiers, req.CorrelationValues) {
		digest := correlationValueDigest(instance.ConnectorInstanceID, value)
		kind, ok := auditIdentifierKind(value)
		if digest == "" || !ok || value.Target == connector.CorrelationTargetSemanticEvent {
			continue
		}
		if _, err := tx.PutIdentifier(ctx, audit.CorrelationIdentifier{
			SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: typedCorrelationNamespace(value), Kind: kind, ValueDigest: digest,
			NormalizedValue: value.Value, SourceField: value.Path,
			Origin: correlationIdentityOrigin(value.Origin), ProfileVersion: string(spec.ProfileVersion), ObservedAt: now,
		}); err != nil {
			return ctx, req, err
		}
	}
	var relationships []audit.CorrelationRelationship
	matchRelationships, err := putCorrelationMatchRelationships(ctx, tx, semantic, occurrence, match, now)
	if err != nil {
		return ctx, req, err
	}
	relationships = append(relationships, matchRelationships...)
	traceRelationships, err := putCorrelationTraceTopology(ctx, tx, semantic, traceID, spanID, now)
	if err != nil {
		return ctx, req, err
	}
	relationships = append(relationships, traceRelationships...)
	stateAdmissible := occurrence.Status != audit.CorrelationOccurrenceConflict
	if stateAdmissible {
		identityRelationships, identityErr := putHookIdentityRelationships(ctx, tx, semantic, req, spec, lifecycle, now)
		if identityErr != nil {
			return ctx, req, identityErr
		}
		relationships = append(relationships, identityRelationships...)
	}
	if stateAdmissible && req.SessionID != "" && req.AgentID != "" && hasLifecycle {
		cursor = nextHookCorrelationCursor(cursor, hasCursor, instance.ConnectorInstanceID, req, spec, lifecycle, semantic, now)
		if err := tx.PutCursor(ctx, cursor); err != nil {
			return ctx, req, err
		}
	}
	if stateAdmissible && lifecycle == connector.CorrelationLifecycleToolStart && req.ToolInvocationID != "" {
		identity := hookOperationIdentityForValue(instance.ConnectorInstanceID,
			req.CorrelationValues[connector.CorrelationTargetTool], connector.CorrelationTargetTool)
		if !identity.valid() {
			return ctx, req, errors.New("tool start is missing a typed pending-operation identity")
		}
		if err := tx.PutPendingOperation(ctx, audit.CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: identity.namespace,
			Kind: identity.kind, OperationID: req.ToolInvocationID,
			Type: audit.CorrelationOperationTool, Name: req.ToolName, SessionID: req.SessionID,
			ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
			TurnID: req.TurnID, AgentID: req.AgentID, ExecutionID: req.ExecutionID,
			StartSemanticEventID: semantic, StartedAt: now, InputDigest: fingerprintHex,
			Status: audit.CorrelationOperationActive, UpdatedAt: now,
		}); err != nil {
			return ctx, req, err
		}
	}
	if stateAdmissible && lifecycle == connector.CorrelationLifecycleModelStart && req.ModelRequestID != "" {
		identity := hookOperationIdentityForValue(instance.ConnectorInstanceID,
			req.CorrelationValues[connector.CorrelationTargetModelRequest], connector.CorrelationTargetModelRequest)
		if !identity.valid() {
			return ctx, req, errors.New("model start is missing a typed pending-operation identity")
		}
		if err := tx.PutPendingOperation(ctx, audit.CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: identity.namespace,
			Kind: identity.kind, OperationID: req.ModelRequestID,
			Type: audit.CorrelationOperationModel, SessionID: req.SessionID, TurnID: req.TurnID,
			ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
			AgentID: req.AgentID, ExecutionID: req.ExecutionID, StartSemanticEventID: semantic,
			StartedAt: now, InputDigest: fingerprintHex, Status: audit.CorrelationOperationActive, UpdatedAt: now,
		}); err != nil {
			return ctx, req, err
		}
	}
	if stateAdmissible && lifecycle == connector.CorrelationLifecycleToolEnd && pendingLocator != nil &&
		pendingLocator.OperationID != "" {
		if resolveErr := tx.ResolvePendingOperation(ctx, *pendingLocator,
			semantic, audit.CorrelationOperationCompleted, now); resolveErr != nil &&
			!errors.Is(resolveErr, audit.ErrCorrelationStale) &&
			!errors.Is(resolveErr, audit.ErrCorrelationNotFound) {
			return ctx, req, resolveErr
		}
	}
	if stateAdmissible && lifecycle == connector.CorrelationLifecycleModelEnd && pendingLocator != nil &&
		pendingLocator.OperationID != "" {
		if resolveErr := tx.ResolvePendingOperation(ctx, *pendingLocator,
			semantic, audit.CorrelationOperationCompleted, now); resolveErr != nil &&
			!errors.Is(resolveErr, audit.ErrCorrelationStale) &&
			!errors.Is(resolveErr, audit.ErrCorrelationNotFound) {
			return ctx, req, resolveErr
		}
	}
	if err := tx.Commit(); err != nil {
		return ctx, req, err
	}
	if emitErr := a.emitCorrelationRelationshipsV8(
		ctx, observability.SourceConnector, req.ConnectorName, semantic, logical,
		instance.ConnectorInstanceID, relationships,
	); emitErr != nil {
		fmt.Fprintln(os.Stderr, "[gateway] committed correlation relationship export incomplete")
	}
	return contextWithHookCorrelation(ctx, req, traceID), req, nil
}

// finalizeHookCorrelationReceipt authorizes exact replay suppression only
// after the handler's canonical local audit row has committed. Keeping this
// marker separate from the occurrence transaction makes a crash between
// correlation acceptance and canonical persistence safely retryable.
func (a *APIServer) finalizeHookCorrelationReceipt(
	ctx context.Context,
	receipt *audit.CorrelationReceiptLocator,
) error {
	if receipt == nil {
		return nil
	}
	if a == nil || a.store == nil {
		return errors.New("hook correlation store is unavailable")
	}
	repo, err := a.store.CorrelationRepository()
	if err != nil {
		return err
	}
	return repo.MarkOccurrenceCanonicalPersisted(ctx, *receipt, time.Now().UTC())
}

func correlationCursorForHook(ctx context.Context, repo *audit.CorrelationRepository, instance audit.ConnectorInstanceID, req agentHookRequest) (audit.CorrelationCursor, bool) {
	if req.SessionID == "" {
		return audit.CorrelationCursor{}, false
	}
	var cursor audit.CorrelationCursor
	var err error
	if req.AgentID != "" {
		cursor, err = repo.GetCursor(ctx, instance, req.SessionID, req.AgentID)
	} else {
		cursor, err = repo.FindActiveCursor(ctx, instance, req.SessionID)
	}
	return cursor, err == nil
}

func appendHookCorrelationValue(req *agentHookRequest, target connector.CorrelationTarget, value string, origin connector.CorrelationOrigin) {
	if req == nil || value == "" {
		return
	}
	entry := connector.CorrelationValue{Target: target, Value: value, Path: "defenseclaw.minted." + string(target),
		Origin: origin, Namespace: "defenseclaw", IDKind: string(target)}
	req.CorrelationIdentifiers = append(req.CorrelationIdentifiers, entry)
	if req.CorrelationValues == nil {
		req.CorrelationValues = make(map[connector.CorrelationTarget]connector.CorrelationValue)
	}
	req.CorrelationValues[target] = entry
	if req.CorrelationOrigins == nil {
		req.CorrelationOrigins = make(map[connector.CorrelationTarget]connector.CorrelationOrigin)
	}
	req.CorrelationOrigins[target] = origin
}

type hookOperationIdentity struct {
	namespace string
	kind      audit.CorrelationIdentifierKind
	scopeKind audit.CorrelationOperationScopeKind
	scopeID   string
}

func (identity hookOperationIdentity) valid() bool {
	return identity.namespace != "" && identity.kind != "" &&
		identity.scopeKind != "" && identity.scopeID != ""
}

func (identity hookOperationIdentity) pendingMatch(
	operationType audit.CorrelationOperationType,
	operationID string,
	name string,
	req agentHookRequest,
) *audit.CorrelationPendingMatch {
	if !identity.valid() {
		return nil
	}
	return &audit.CorrelationPendingMatch{
		Namespace: identity.namespace, Kind: identity.kind, OperationID: operationID,
		Type: operationType, ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
		Name: name, SessionID: req.SessionID, TurnID: req.TurnID,
		AgentID: req.AgentID, ExecutionID: req.ExecutionID,
	}
}

func (identity hookOperationIdentity) locator(
	instance audit.ConnectorInstanceID,
	operationType audit.CorrelationOperationType,
	operationID string,
) *audit.CorrelationPendingLocator {
	if !identity.valid() {
		return nil
	}
	return &audit.CorrelationPendingLocator{
		ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
		OperationID: operationID, Type: operationType,
		ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
	}
}

// Pending-operation identity is always scoped by the authenticated connector
// instance in addition to the provider namespace and canonical ID kind. This
// permits an exact terminal ID to recover its start even when the terminal
// hook omits session/turn context, while a provider reusing the same ID in a
// second session fails closed as an identity collision instead of merging two
// operations.
func hookOperationIdentityForValue(
	instance audit.ConnectorInstanceID,
	value connector.CorrelationValue,
	target connector.CorrelationTarget,
) hookOperationIdentity {
	if value.Target == "" {
		value.Target = target
	}
	if value.Namespace == "" {
		value.Namespace = "defenseclaw"
	}
	if value.IDKind == "" {
		value.IDKind = string(target)
	}
	kind, ok := auditIdentifierKind(value)
	if !ok || instance == "" {
		return hookOperationIdentity{}
	}
	return hookOperationIdentity{
		namespace: typedCorrelationNamespace(value), kind: kind,
		scopeKind: audit.CorrelationOperationScopeConnectorInstance, scopeID: string(instance),
	}
}

func hookOperationIdentityCandidates(
	instance audit.ConnectorInstanceID,
	req agentHookRequest,
	spec connector.CorrelationSpec,
	target connector.CorrelationTarget,
	exactOperationID string,
) []hookOperationIdentity {
	if exactOperationID != "" {
		return []hookOperationIdentity{hookOperationIdentityForValue(instance, req.CorrelationValues[target], target)}
	}
	values := make([]connector.CorrelationValue, 0, len(spec.HookBindings)+1)
	for _, binding := range spec.HookBindings {
		if binding.Target != target {
			continue
		}
		values = append(values, connector.CorrelationValue{
			Target: target, Namespace: binding.Namespace, IDKind: binding.IDKind,
		})
	}
	// A lifecycle-minted start uses the DefenseClaw namespace even when the
	// connector also has a provider-native binding for this operation kind.
	values = append(values, connector.CorrelationValue{
		Target: target, Namespace: "defenseclaw", IDKind: string(target),
	})
	identities := make([]hookOperationIdentity, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		identity := hookOperationIdentityForValue(instance, value, target)
		key := identity.namespace + "\x00" + string(identity.kind) + "\x00" + identity.scopeID
		if !identity.valid() || seen[key] {
			continue
		}
		seen[key] = true
		identities = append(identities, identity)
	}
	return identities
}

func findHookPendingOperation(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstanceID,
	req agentHookRequest,
	spec connector.CorrelationSpec,
	target connector.CorrelationTarget,
	operationType audit.CorrelationOperationType,
	exactOperationID string,
	name string,
) (audit.CorrelationPendingOperation, hookOperationIdentity, bool, error) {
	identities := hookOperationIdentityCandidates(instance, req, spec, target, exactOperationID)
	if len(identities) == 0 {
		return audit.CorrelationPendingOperation{}, hookOperationIdentity{}, false, audit.ErrCorrelationNotFound
	}
	var matched audit.CorrelationPendingOperation
	var matchedIdentity hookOperationIdentity
	found := false
	for _, identity := range identities {
		query := audit.CorrelationPendingQuery{
			ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
			OperationID: exactOperationID, Type: operationType,
			ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
		}
		if exactOperationID == "" {
			query.Name = name
			query.SessionID = req.SessionID
			query.TurnID = req.TurnID
			query.AgentID = req.AgentID
			query.ExecutionID = req.ExecutionID
		}
		operation, err := repo.FindUniquePendingOperation(ctx, query)
		if errors.Is(err, audit.ErrCorrelationNotFound) {
			continue
		}
		if err != nil {
			return audit.CorrelationPendingOperation{}, identity, false, err
		}
		if found && (matched.OperationID != operation.OperationID ||
			matched.Namespace != operation.Namespace || matched.Kind != operation.Kind) {
			return audit.CorrelationPendingOperation{}, hookOperationIdentity{}, false, audit.ErrCorrelationConflict
		}
		matched = operation
		matchedIdentity = identity
		found = true
	}
	if found {
		return matched, matchedIdentity, true, nil
	}
	// Retain an exact provider identity as unresolved evidence. Crucially, it
	// never falls through to the current cursor or a name/time-only operation.
	if exactOperationID != "" {
		return audit.CorrelationPendingOperation{}, identities[0], false, audit.ErrCorrelationNotFound
	}
	return audit.CorrelationPendingOperation{}, hookOperationIdentity{}, false, audit.ErrCorrelationNotFound
}

func restoreHookOperationContext(req *agentHookRequest, operation audit.CorrelationPendingOperation) {
	if req == nil {
		return
	}
	req.SessionID = firstNonEmpty(req.SessionID, operation.SessionID)
	req.TurnID = firstNonEmpty(req.TurnID, operation.TurnID)
	req.AgentID = firstNonEmpty(req.AgentID, operation.AgentID)
	req.ExecutionID = firstNonEmpty(req.ExecutionID, operation.ExecutionID)
}

func correlationIdentifiersForValues(
	instance audit.ConnectorInstanceID,
	values []connector.CorrelationValue,
	preferredSource connector.CorrelationValue,
) ([]audit.CorrelationMatchIdentifier, string) {
	identifiers := make([]audit.CorrelationMatchIdentifier, 0, len(values))
	seen := make(map[string]bool, len(values))
	sourceDigest := ""
	for _, value := range values {
		kind, ok := auditIdentifierKind(value)
		if !ok || value.Target == connector.CorrelationTargetSemanticEvent {
			continue
		}
		digest := correlationValueDigest(instance, value)
		if digest == "" {
			continue
		}
		key := typedCorrelationNamespace(value) + "\x00" + string(kind) + "\x00" + digest
		if seen[key] {
			continue
		}
		seen[key] = true
		identifiers = append(identifiers, audit.CorrelationMatchIdentifier{
			Namespace: typedCorrelationNamespace(value), Kind: kind, ValueDigest: digest,
		})
		if value.Target == connector.CorrelationTargetSourceEvent &&
			(preferredSource.Value == "" || sameTypedCorrelationValue(value, preferredSource)) && sourceDigest == "" {
			sourceDigest = digest
		}
	}
	// A malformed or incomplete caller preference cannot make an otherwise
	// exact source occurrence disappear. Fall back deterministically to the
	// first reviewed source binding only when no preferred typed value matched.
	if sourceDigest == "" {
		for _, value := range values {
			if value.Target == connector.CorrelationTargetSourceEvent {
				sourceDigest = correlationValueDigest(instance, value)
				if sourceDigest != "" {
					break
				}
			}
		}
	}
	return identifiers, sourceDigest
}

// correlationMatchValuesForRail separates preservation from authority. Every
// reviewed value is retained in correlation_identifiers and projected to the
// canonical record. Membership IDs may produce only typed, non-collapsing graph
// links. Occurrence-level IDs enter the cross-rail matcher only when this exact
// path has immutable mirror evidence; a target-level capability never grants
// authority to every alias. Same-rail replay remains governed by the rail-
// scoped durable receipt built from the complete value set.
func correlationMatchValuesForRail(
	spec connector.CorrelationSpec,
	rail audit.CorrelationRail,
	values []connector.CorrelationValue,
) []connector.CorrelationValue {
	surface, surfaceOK := correlationSurfaceForRail(rail)
	result := make([]connector.CorrelationValue, 0, len(values))
	for _, value := range values {
		if correlationOccurrenceIdentityTarget(value.Target) {
			if !surfaceOK {
				continue
			}
			if _, ok := spec.MirrorProofForValue(surface, value); !ok {
				continue
			}
			if rail == audit.CorrelationRailNativeOTLP &&
				!spec.IsAuthoritativeValue(surface, value) {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func correlationSurfaceForRail(rail audit.CorrelationRail) (connector.CorrelationSurface, bool) {
	switch rail {
	case audit.CorrelationRailHook:
		return connector.CorrelationSurfaceHook, true
	case audit.CorrelationRailNativeOTLP:
		return connector.CorrelationSurfaceNativeOTLP, true
	case audit.CorrelationRailProxy:
		return connector.CorrelationSurfaceProxy, true
	case audit.CorrelationRailStream:
		return connector.CorrelationSurfaceStream, true
	default:
		return "", false
	}
}

func correlationOccurrenceIdentityTarget(target connector.CorrelationTarget) bool {
	switch target {
	case connector.CorrelationTargetSourceEvent, connector.CorrelationTargetModelRequest,
		connector.CorrelationTargetModelResponse, connector.CorrelationTargetTool:
		return true
	default:
		return false
	}
}

func sameTypedCorrelationValue(left, right connector.CorrelationValue) bool {
	return left.Target == right.Target && left.Value == right.Value &&
		typedCorrelationNamespace(left) == typedCorrelationNamespace(right)
}

func correlationValueDigest(instance audit.ConnectorInstanceID, value connector.CorrelationValue) string {
	return gatewaylog.ComputePayloadHMAC(struct {
		Domain    string `json:"domain"`
		Instance  string `json:"connector_instance_id"`
		Namespace string `json:"namespace"`
		IDKind    string `json:"id_kind"`
		Target    string `json:"target"`
		Value     string `json:"value"`
	}{
		"correlation-identifier-v2", string(instance), normalizedCorrelationNamespace(value),
		normalizedCorrelationIDKind(value), string(value.Target), value.Value,
	})
}

func typedCorrelationNamespace(value connector.CorrelationValue) string {
	return normalizedCorrelationNamespace(value) + "/" + normalizedCorrelationIDKind(value)
}

func normalizedCorrelationNamespace(value connector.CorrelationValue) string {
	namespace := strings.TrimSpace(value.Namespace)
	if namespace == "" {
		namespace = "unknown"
	}
	return namespace
}

func normalizedCorrelationIDKind(value connector.CorrelationValue) string {
	kind := strings.TrimSpace(value.IDKind)
	if kind == "" {
		kind = string(value.Target)
	}
	return kind
}

func auditIdentifierKind(value connector.CorrelationValue) (audit.CorrelationIdentifierKind, bool) {
	if value.Target == connector.CorrelationTargetTurn && value.IDKind == "prompt" {
		return audit.CorrelationIdentifierPrompt, true
	}
	switch value.Target {
	case connector.CorrelationTargetSourceEvent:
		return audit.CorrelationIdentifierSourceEvent, true
	case connector.CorrelationTargetSourceSeq:
		return audit.CorrelationIdentifierSourceSequence, true
	case connector.CorrelationTargetSourceTime:
		return audit.CorrelationIdentifierSourceTimestamp, true
	case connector.CorrelationTargetMessage:
		return audit.CorrelationIdentifierMessage, true
	case connector.CorrelationTargetThread:
		return audit.CorrelationIdentifierThread, true
	case connector.CorrelationTargetStep:
		return audit.CorrelationIdentifierStep, true
	case connector.CorrelationTargetSession:
		return audit.CorrelationIdentifierSession, true
	case connector.CorrelationTargetRootSession:
		return audit.CorrelationIdentifierRootSession, true
	case connector.CorrelationTargetParentSession:
		return audit.CorrelationIdentifierParentSession, true
	case connector.CorrelationTargetChildSession:
		return audit.CorrelationIdentifierChildSession, true
	case connector.CorrelationTargetTurn:
		return audit.CorrelationIdentifierTurn, true
	case connector.CorrelationTargetAgent:
		return audit.CorrelationIdentifierAgent, true
	case connector.CorrelationTargetRootAgent:
		return audit.CorrelationIdentifierRootAgent, true
	case connector.CorrelationTargetParentAgent:
		return audit.CorrelationIdentifierParentAgent, true
	case connector.CorrelationTargetChildAgent:
		return audit.CorrelationIdentifierChildAgent, true
	case connector.CorrelationTargetExecution:
		return audit.CorrelationIdentifierExecution, true
	case connector.CorrelationTargetModelRequest:
		return audit.CorrelationIdentifierModelRequest, true
	case connector.CorrelationTargetModelResponse:
		return audit.CorrelationIdentifierModelResponse, true
	case connector.CorrelationTargetAction:
		return audit.CorrelationIdentifierAction, true
	case connector.CorrelationTargetTool:
		return audit.CorrelationIdentifierTool, true
	default:
		return "", false
	}
}

func correlationIdentityOrigin(origin connector.CorrelationOrigin) audit.CorrelationIdentityOrigin {
	switch origin {
	case connector.CorrelationOriginMinted:
		return audit.CorrelationOriginDefenseClawMinted
	case connector.CorrelationOriginDerived, connector.CorrelationOriginInferred:
		return audit.CorrelationOriginDerived
	case connector.CorrelationOriginTraceExact:
		return audit.CorrelationOriginTraceExact
	default:
		return audit.CorrelationOriginReported
	}
}

func dedupeCorrelationValues(slices []connector.CorrelationValue, canonical map[connector.CorrelationTarget]connector.CorrelationValue) []connector.CorrelationValue {
	values := append([]connector.CorrelationValue(nil), slices...)
	for _, value := range canonical {
		values = append(values, value)
	}
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		key := string(value.Target) + "\x00" + typedCorrelationNamespace(value) + "\x00" + value.Value
		if value.Value == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func correlationReceiptForHook(
	spec connector.CorrelationSpec,
	instance audit.ConnectorInstanceID,
	req agentHookRequest,
	sourceDigest, fingerprint string,
	now time.Time,
) *audit.CorrelationReceiptClaim {
	if sourceDigest == "" || req.SourceEventID == "" || !spec.AllowsReceiptTarget(connector.CorrelationTargetSourceEvent) {
		return nil
	}
	return &audit.CorrelationReceiptClaim{SourceKeyDigest: correlationReceiptSourceKey(
		instance, audit.CorrelationRailHook, string(connector.CorrelationSurfaceHook), sourceDigest,
	), FingerprintSHA256: fingerprint,
		ReceivedAt: now, ExpiresAt: now.Add(correlationReceiptTTL)}
}

// correlationReceiptSourceKey scopes delivery idempotency to one authenticated
// rail and channel. The unsalted typed identifier remains in
// correlation_identifiers so a hook and native OTLP leaf that report the same
// provider occurrence can be retained separately and joined as same_as. If the
// receipt reused that rail-agnostic digest, their necessarily different wire
// fingerprints would be misclassified as an integrity conflict.
func correlationReceiptSourceKey(
	instance audit.ConnectorInstanceID,
	rail audit.CorrelationRail,
	channel, sourceDigest string,
) string {
	if instance == "" || rail == "" || strings.TrimSpace(channel) == "" || sourceDigest == "" {
		return ""
	}
	return gatewaylog.ComputePayloadHMAC(struct {
		Domain       string `json:"domain"`
		Instance     string `json:"connector_instance_id"`
		Rail         string `json:"rail"`
		Channel      string `json:"channel"`
		SourceDigest string `json:"source_digest"`
	}{
		Domain: "correlation-delivery-receipt-v2", Instance: string(instance),
		Rail: string(rail), Channel: channel, SourceDigest: sourceDigest,
	})
}

func receiptLookup(receipt *audit.CorrelationReceiptClaim) *audit.CorrelationReceiptLookup {
	if receipt == nil {
		return nil
	}
	return &audit.CorrelationReceiptLookup{SourceKeyDigest: receipt.SourceKeyDigest, FingerprintSHA256: receipt.FingerprintSHA256}
}

func mirrorCompatibilityForHook(spec connector.CorrelationSpec, lifecycle connector.CorrelationLifecycle) *audit.CorrelationMirrorCompatibility {
	return mirrorCompatibilityForRail(spec, audit.CorrelationRailHook, lifecycle)
}

func mirrorCompatibilityForRail(
	spec connector.CorrelationSpec,
	rail audit.CorrelationRail,
	lifecycle connector.CorrelationLifecycle,
) *audit.CorrelationMirrorCompatibility {
	kinds := make([]audit.CorrelationIdentifierKind, 0, len(spec.MirrorIdentityTargets))
	seen := make(map[audit.CorrelationIdentifierKind]bool, len(spec.MirrorIdentityTargets))
	proofIDs := make([]string, 0, len(spec.MirrorIdentityTargets))
	seenProof := make(map[string]bool, len(spec.MirrorIdentityTargets))
	for _, target := range spec.MirrorIdentityTargets {
		if !spec.NativeTelemetry.IsAuthoritative(target) {
			continue
		}
		proofID, proven := spec.MirrorProofIDForTarget(target)
		if !proven {
			continue
		}
		if !correlationMirrorTargetAppliesToLifecycle(target, lifecycle) {
			continue
		}
		kind, ok := auditIdentifierKind(connector.CorrelationValue{Target: target})
		occurrenceLevel := kind == audit.CorrelationIdentifierModelRequest ||
			kind == audit.CorrelationIdentifierModelResponse || kind == audit.CorrelationIdentifierTool ||
			kind == audit.CorrelationIdentifierSourceEvent
		if ok && occurrenceLevel && !seen[kind] {
			seen[kind] = true
			kinds = append(kinds, kind)
			if !seenProof[proofID] {
				seenProof[proofID] = true
				proofIDs = append(proofIDs, proofID)
			}
		}
	}
	if len(kinds) == 0 {
		return nil
	}
	return &audit.CorrelationMirrorCompatibility{Rail: rail, EventName: string(lifecycle),
		RuleID: strings.Join(proofIDs, "+"), RuleVersion: string(spec.ProfileVersion),
		EquivalentIdentifierKinds: kinds}
}

func exactIdentityCompatibleRails(
	spec connector.CorrelationSpec,
	rail audit.CorrelationRail,
) []audit.CorrelationRail {
	if spec.NativeTelemetry.Stability == connector.NativeTelemetryNone {
		return nil
	}
	if rail != audit.CorrelationRailNativeOTLP {
		return []audit.CorrelationRail{audit.CorrelationRailNativeOTLP}
	}
	result := make([]audit.CorrelationRail, 0, len(spec.Surfaces))
	seen := make(map[audit.CorrelationRail]bool, len(spec.Surfaces))
	for _, surface := range spec.Surfaces {
		var candidate audit.CorrelationRail
		switch surface {
		case connector.CorrelationSurfaceHook:
			candidate = audit.CorrelationRailHook
		case connector.CorrelationSurfaceProxy:
			candidate = audit.CorrelationRailProxy
		case connector.CorrelationSurfaceStream:
			candidate = audit.CorrelationRailStream
		default:
			continue
		}
		if !seen[candidate] {
			seen[candidate] = true
			result = append(result, candidate)
		}
	}
	return result
}

func validExactIdentityClaimKind(kind audit.CorrelationIdentifierKind) bool {
	switch kind {
	case audit.CorrelationIdentifierSourceEvent, audit.CorrelationIdentifierModelRequest,
		audit.CorrelationIdentifierModelResponse, audit.CorrelationIdentifierTool:
		return true
	default:
		return false
	}
}

// correlationExactIdentityClaims converts only reviewed, same-phase provider
// occurrence IDs into atomic cross-rail claims. Membership IDs (session, turn,
// message, agent, execution) are preserved and linked as typed graph nodes but
// can never collapse two occurrences. Minted or cursor-derived IDs are also
// excluded because they were not independently reported on this rail.
func correlationExactIdentityClaims(
	spec connector.CorrelationSpec,
	instance audit.ConnectorInstanceID,
	rail audit.CorrelationRail,
	lifecycle connector.CorrelationLifecycle,
	values []connector.CorrelationValue,
) []audit.CorrelationExactIdentityClaim {
	surface, surfaceOK := correlationSurfaceForRail(rail)
	if !surfaceOK {
		return nil
	}
	compatibleRails := exactIdentityCompatibleRails(spec, rail)
	if len(compatibleRails) == 0 {
		return nil
	}
	claims := make([]audit.CorrelationExactIdentityClaim, 0, len(values)*len(compatibleRails))
	seen := make(map[string]bool, len(values)*len(compatibleRails))
	for _, value := range values {
		if value.Origin != connector.CorrelationOriginReported &&
			value.Origin != connector.CorrelationOriginTraceExact {
			continue
		}
		proofID, proven := spec.MirrorProofForValue(surface, value)
		if !proven || !correlationMirrorTargetAppliesToLifecycle(value.Target, lifecycle) ||
			(rail == audit.CorrelationRailNativeOTLP && !spec.IsAuthoritativeValue(surface, value)) {
			continue
		}
		kind, ok := auditIdentifierKind(value)
		if !ok || !validExactIdentityClaimKind(kind) {
			continue
		}
		digest := correlationValueDigest(instance, value)
		if digest == "" {
			continue
		}
		for _, compatibleRail := range compatibleRails {
			claim := audit.CorrelationExactIdentityClaim{
				Namespace: typedCorrelationNamespace(value), Kind: kind, ValueDigest: digest,
				EventName: string(lifecycle), Rail: rail, CompatibleRail: compatibleRail,
				RuleID: proofID, RuleVersion: string(spec.ProfileVersion),
			}
			key := claim.Namespace + "\x00" + string(claim.Kind) + "\x00" + claim.ValueDigest +
				"\x00" + string(claim.CompatibleRail)
			if seen[key] {
				continue
			}
			seen[key] = true
			claims = append(claims, claim)
		}
	}
	return claims
}

// A provider ID can be authoritative while still describing an enclosing
// operation instead of the current occurrence. In particular, response and
// interaction IDs often appear on every tool event produced by that response.
// Restrict mirror authority to the lifecycle whose boundary the ID names so
// two tool calls sharing one response can never collapse into one event.
func correlationMirrorTargetAppliesToLifecycle(
	target connector.CorrelationTarget,
	lifecycle connector.CorrelationLifecycle,
) bool {
	if target == connector.CorrelationTargetSourceEvent {
		return true
	}
	switch lifecycle {
	case connector.CorrelationLifecycleModelStart:
		return target == connector.CorrelationTargetModelRequest ||
			target == connector.CorrelationTargetMessage
	case connector.CorrelationLifecycleModelEnd:
		return target == connector.CorrelationTargetModelResponse ||
			target == connector.CorrelationTargetMessage
	case connector.CorrelationLifecycleToolStart, connector.CorrelationLifecycleToolEnd:
		return target == connector.CorrelationTargetTool
	case connector.CorrelationLifecycleTurnStart, connector.CorrelationLifecycleTurnEnd:
		return target == connector.CorrelationTargetMessage
	default:
		return false
	}
}

func putCorrelationMatchRelationships(
	ctx context.Context,
	tx *audit.CorrelationTx,
	semantic audit.SemanticEventID,
	occurrence audit.CorrelationOccurrenceResult,
	match audit.CorrelationMatchResult,
	now time.Time,
) ([]audit.CorrelationRelationship, error) {
	if occurrence.Status == audit.CorrelationOccurrenceConflict || len(occurrence.IdentityEvidence) == 0 {
		relationship, err := putCorrelationMatchRelationship(ctx, tx, semantic, occurrence, match, now)
		if err != nil || relationship == nil {
			return nil, err
		}
		return []audit.CorrelationRelationship{*relationship}, nil
	}
	relationships := make([]audit.CorrelationRelationship, 0, len(occurrence.IdentityEvidence))
	seen := make(map[audit.SemanticEventID]bool, len(occurrence.IdentityEvidence))
	for _, evidence := range occurrence.IdentityEvidence {
		if evidence.SemanticEventID == "" || evidence.SemanticEventID == semantic || seen[evidence.SemanticEventID] {
			continue
		}
		seen[evidence.SemanticEventID] = true
		exactMatch := audit.CorrelationMatchResult{
			Rank:                   audit.CorrelationMatchNativeIdentifier,
			MatchedSemanticEventID: evidence.SemanticEventID,
			LogicalEventID:         occurrence.LogicalEventID, Method: audit.CorrelationMethodReported,
			RuleID: evidence.RuleID, RuleVersion: evidence.RuleVersion,
			MergeAllowed: true, RelationshipType: audit.CorrelationSameAs, CandidateCount: 1,
		}
		relationship, err := putCorrelationMatchRelationship(ctx, tx, semantic, occurrence, exactMatch, now)
		if err != nil {
			return nil, err
		}
		if relationship != nil {
			relationships = append(relationships, *relationship)
		}
	}
	return relationships, nil
}

func putCorrelationMatchRelationship(ctx context.Context, tx *audit.CorrelationTx, semantic audit.SemanticEventID, occurrence audit.CorrelationOccurrenceResult, match audit.CorrelationMatchResult, now time.Time) (*audit.CorrelationRelationship, error) {
	target := match.MatchedSemanticEventID
	relationType := match.RelationshipType
	method := match.Method
	ruleID, ruleVersion := match.RuleID, match.RuleVersion
	status := audit.CorrelationRelationshipActive
	if occurrence.Status == audit.CorrelationOccurrenceConflict {
		target = occurrence.ConflictsWith
		relationType = audit.CorrelationCorrelatesWith
		method = audit.CorrelationMethodReported
		ruleID, ruleVersion = "source-receipt-conflict", "v1"
		status = audit.CorrelationRelationshipConflicted
	} else if match.CandidateOnly {
		status = audit.CorrelationRelationshipCandidate
	}
	// A grouping identifier or pending start proves membership in a typed
	// session/turn/model/tool node, not membership in another semantic event.
	// Those typed edges are materialized separately. Emitting semantic-event
	// -> semantic-event belongs_to here would give an arbitrary observation the
	// meaning of the shared business identity.
	if !match.MergeAllowed && relationType == audit.CorrelationBelongsTo {
		return nil, nil
	}
	if target == "" || target == semantic || relationType == "" || method == "" {
		return nil, nil
	}
	relationship, err := tx.PutRelationship(ctx, audit.CorrelationRelationshipInput{
		FromKind: audit.CorrelationNodeSemanticEvent, FromID: string(semantic),
		ToKind: audit.CorrelationNodeSemanticEvent, ToID: string(target), Type: relationType,
		Method: method, RuleID: ruleID, RuleVersion: ruleVersion, Status: status, ObservedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if err := putCorrelationRelationshipEvidence(
		ctx, tx, &relationship, semantic, now,
	); err != nil {
		return nil, err
	}
	return &relationship, nil
}

func putCorrelationRelationshipEvidence(
	ctx context.Context,
	tx *audit.CorrelationTx,
	relationship *audit.CorrelationRelationship,
	semantic audit.SemanticEventID,
	now time.Time,
) error {
	if relationship == nil {
		return fmt.Errorf("correlation relationship evidence requires relationship")
	}
	if _, err := tx.PutRelationshipEvidence(ctx, audit.CorrelationRelationshipEvidence{
		RelationshipID: relationship.RelationshipID, SemanticEventID: semantic,
		Role: audit.CorrelationEvidenceSource, Integrity: audit.CorrelationIntegrityVerified, CreatedAt: now,
	}); err != nil {
		return err
	}
	evidenceCount, err := tx.RelationshipEvidenceCount(ctx, relationship.RelationshipID)
	if err != nil {
		return err
	}
	if evidenceCount <= 0 {
		return fmt.Errorf("correlation relationship has no durable evidence")
	}
	relationship.EvidenceCount = evidenceCount
	return nil
}

func putCorrelationTraceTopology(ctx context.Context, tx *audit.CorrelationTx, semantic audit.SemanticEventID, traceID, spanID string, now time.Time) ([]audit.CorrelationRelationship, error) {
	var relationships []audit.CorrelationRelationship
	nodes := make([]struct {
		kind audit.CorrelationNodeKind
		id   string
		rule string
	}, 0, 2)
	traceValid := validCorrelationHexID(traceID, 16)
	if traceValid {
		nodes = append(nodes, struct {
			kind audit.CorrelationNodeKind
			id   string
			rule string
		}{audit.CorrelationNodeTrace, traceID, "reported-trace-membership"})
	}
	if traceValid && validCorrelationHexID(spanID, 8) {
		nodes = append(nodes, struct {
			kind audit.CorrelationNodeKind
			id   string
			rule string
		}{audit.CorrelationNodeSpan, traceID + ":" + spanID, "reported-span-membership"})
	}
	for _, node := range nodes {
		relationship, err := tx.PutRelationship(ctx, audit.CorrelationRelationshipInput{
			FromKind: audit.CorrelationNodeSemanticEvent, FromID: string(semantic),
			ToKind: node.kind, ToID: node.id, Type: audit.CorrelationBelongsTo,
			Method: audit.CorrelationMethodTraceExact, RuleID: node.rule, RuleVersion: "v1",
			Status: audit.CorrelationRelationshipActive, ObservedAt: now,
		})
		if err != nil {
			return nil, err
		}
		if err := putCorrelationRelationshipEvidence(
			ctx, tx, &relationship, semantic, now,
		); err != nil {
			return nil, err
		}
		relationships = append(relationships, relationship)
	}
	return relationships, nil
}

type hookIdentityRelationshipFact struct {
	fromKind   audit.CorrelationNodeKind
	fromID     string
	fromTarget connector.CorrelationTarget
	toKind     audit.CorrelationNodeKind
	toID       string
	toTarget   connector.CorrelationTarget
	typeName   audit.CorrelationRelationshipType
	ruleID     string
}

// putHookIdentityRelationships materializes only relationships supported by
// reviewed connector identities or deterministic lifecycle state. Trace
// parentage is deliberately absent: an OTLP parent span is causal topology,
// never agent lineage. Missing or inferred parent claims remain unresolved
// instead of creating a graph edge.
func putHookIdentityRelationships(
	ctx context.Context,
	tx *audit.CorrelationTx,
	semantic audit.SemanticEventID,
	req agentHookRequest,
	spec connector.CorrelationSpec,
	lifecycle connector.CorrelationLifecycle,
	now time.Time,
) ([]audit.CorrelationRelationship, error) {
	semanticID := string(semantic)
	facts := []hookIdentityRelationshipFact{
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeSession, req.SessionID, connector.CorrelationTargetSession, audit.CorrelationBelongsTo, "occurrence-session-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeTurn, req.TurnID, connector.CorrelationTargetTurn, audit.CorrelationBelongsTo, "occurrence-turn-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent, audit.CorrelationBelongsTo, "occurrence-agent-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeExecution, req.ExecutionID, connector.CorrelationTargetExecution, audit.CorrelationBelongsTo, "occurrence-execution-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeTool, req.ToolInvocationID, connector.CorrelationTargetTool, audit.CorrelationBelongsTo, "occurrence-tool-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeModelRequest, req.ModelRequestID, connector.CorrelationTargetModelRequest, audit.CorrelationBelongsTo, "occurrence-model-request-membership"},
		{audit.CorrelationNodeSemanticEvent, semanticID, "", audit.CorrelationNodeModelResponse, req.ModelResponseID, connector.CorrelationTargetModelResponse, audit.CorrelationBelongsTo, "occurrence-model-response-membership"},
		{audit.CorrelationNodeTurn, req.TurnID, connector.CorrelationTargetTurn, audit.CorrelationNodeSession, req.SessionID, connector.CorrelationTargetSession, audit.CorrelationBelongsTo, "turn-session-membership"},
		{audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent, audit.CorrelationNodeSession, req.SessionID, connector.CorrelationTargetSession, audit.CorrelationBelongsTo, "agent-session-membership"},
	}

	if req.ParentSessionID != "" && req.SessionID != "" && req.ParentSessionID != req.SessionID {
		facts = append(facts, hookIdentityRelationshipFact{
			audit.CorrelationNodeSession, req.ParentSessionID, connector.CorrelationTargetParentSession,
			audit.CorrelationNodeSession, req.SessionID, connector.CorrelationTargetSession,
			audit.CorrelationParentOf, "reported-session-lineage",
		})
	}
	if req.ParentAgentID != "" && req.AgentID != "" && req.ParentAgentID != req.AgentID {
		facts = append(facts,
			hookIdentityRelationshipFact{
				audit.CorrelationNodeAgent, req.ParentAgentID, connector.CorrelationTargetParentAgent,
				audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent,
				audit.CorrelationParentOf, "reported-agent-lineage",
			},
			hookIdentityRelationshipFact{
				audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent,
				audit.CorrelationNodeAgent, req.ParentAgentID, connector.CorrelationTargetParentAgent,
				audit.CorrelationDelegatedBy, "reported-agent-delegation",
			},
		)
	}
	if req.AgentID != "" && req.ToolInvocationID != "" &&
		(lifecycle == connector.CorrelationLifecycleToolStart || lifecycle == connector.CorrelationLifecycleToolEnd) {
		facts = append(facts, hookIdentityRelationshipFact{
			audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent,
			audit.CorrelationNodeTool, req.ToolInvocationID, connector.CorrelationTargetTool,
			audit.CorrelationInvokes, "agent-tool-invocation",
		})
	}
	if req.AgentID != "" && req.ModelRequestID != "" &&
		(lifecycle == connector.CorrelationLifecycleModelStart || lifecycle == connector.CorrelationLifecycleModelEnd) {
		facts = append(facts, hookIdentityRelationshipFact{
			audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent,
			audit.CorrelationNodeModelRequest, req.ModelRequestID, connector.CorrelationTargetModelRequest,
			audit.CorrelationInvokes, "agent-model-invocation",
		})
	}
	if req.ModelResponseID != "" && req.ModelRequestID != "" {
		facts = append(facts, hookIdentityRelationshipFact{
			audit.CorrelationNodeModelResponse, req.ModelResponseID, connector.CorrelationTargetModelResponse,
			audit.CorrelationNodeModelRequest, req.ModelRequestID, connector.CorrelationTargetModelRequest,
			audit.CorrelationRespondsTo, "model-response-request",
		})
	}
	if lifecycle == connector.CorrelationLifecycleSubagentStart && req.AgentID != "" && req.ToolInvocationID != "" {
		facts = append(facts, hookIdentityRelationshipFact{
			audit.CorrelationNodeAgent, req.AgentID, connector.CorrelationTargetAgent,
			audit.CorrelationNodeTool, req.ToolInvocationID, connector.CorrelationTargetTool,
			audit.CorrelationCausedBy, "spawned-agent-tool-cause",
		})
	}

	profileVersion := string(spec.ProfileVersion)
	if profileVersion == "" {
		profileVersion = "unknown"
	}
	relationships := make([]audit.CorrelationRelationship, 0, len(facts))
	for _, fact := range facts {
		if fact.fromID == "" || fact.toID == "" ||
			(fact.fromKind == fact.toKind && fact.fromID == fact.toID) || fact.typeName == "" {
			continue
		}
		method, ok := hookRelationshipMethod(req, fact.fromTarget, fact.toTarget)
		if !ok {
			continue
		}
		relationship, err := tx.PutRelationship(ctx, audit.CorrelationRelationshipInput{
			FromKind: fact.fromKind, FromID: fact.fromID, ToKind: fact.toKind, ToID: fact.toID,
			Type: fact.typeName, Method: method, RuleID: fact.ruleID, RuleVersion: profileVersion,
			Status: audit.CorrelationRelationshipActive, ObservedAt: now,
		})
		if err != nil {
			return nil, err
		}
		if err := putCorrelationRelationshipEvidence(
			ctx, tx, &relationship, semantic, now,
		); err != nil {
			return nil, err
		}
		relationships = append(relationships, relationship)
	}
	return relationships, nil
}

func hookRelationshipMethod(
	req agentHookRequest,
	targets ...connector.CorrelationTarget,
) (audit.CorrelationRelationshipMethod, bool) {
	method := audit.CorrelationMethodReported
	for _, target := range targets {
		if target == "" {
			continue
		}
		origin, found := req.CorrelationOrigins[target]
		if !found {
			// Cursor restoration and lifecycle-owned parent/session handoff are
			// deterministic associations, not provider-reported facts.
			method = audit.CorrelationMethodDerived
			continue
		}
		switch origin {
		case connector.CorrelationOriginReported:
		case connector.CorrelationOriginMinted, connector.CorrelationOriginDerived:
			method = audit.CorrelationMethodDerived
		case connector.CorrelationOriginTraceExact:
			// Trace evidence is persisted through putCorrelationTraceTopology;
			// it cannot by itself prove a business-identity or lineage edge.
			method = audit.CorrelationMethodDerived
		case connector.CorrelationOriginInferred:
			return "", false
		default:
			return "", false
		}
	}
	return method, true
}

func nextHookCorrelationCursor(existing audit.CorrelationCursor, found bool, instance audit.ConnectorInstanceID, req agentHookRequest, spec connector.CorrelationSpec, lifecycle connector.CorrelationLifecycle, semantic audit.SemanticEventID, now time.Time) audit.CorrelationCursor {
	cursor := existing
	if !found {
		cursor = audit.CorrelationCursor{ConnectorInstanceID: instance, SessionID: req.SessionID, AgentID: req.AgentID, Active: true}
	}
	cursor.Sequence++
	cursor.Phase = string(lifecycle)
	cursor.LastSemanticEventID = semantic
	cursor.ProfileVersion = string(spec.ProfileVersion)
	cursor.UpdatedAt = now
	cursor.ExecutionID = firstNonEmpty(req.ExecutionID, cursor.ExecutionID)
	cursor.RootAgentID = firstNonEmpty(req.RootAgentID, cursor.RootAgentID)
	cursor.ParentAgentID = firstNonEmpty(req.ParentAgentID, cursor.ParentAgentID)
	cursor.RootSessionID = firstNonEmpty(req.RootSessionID, cursor.RootSessionID)
	cursor.ParentSessionID = firstNonEmpty(req.ParentSessionID, cursor.ParentSessionID)
	switch lifecycle {
	case connector.CorrelationLifecycleSessionStart:
		cursor.Active = true
	case connector.CorrelationLifecycleSessionEnd:
		cursor.Active = false
		cursor.ActiveTurnID = ""
		cursor.ActivePromptID = ""
	case connector.CorrelationLifecycleTurnStart:
		cursor.ActiveTurnID = req.TurnID
		if value := req.CorrelationValues[connector.CorrelationTargetTurn]; value.IDKind == "prompt" {
			cursor.ActivePromptID = req.TurnID
		}
	case connector.CorrelationLifecycleTurnEnd:
		cursor.ActiveTurnID = ""
		cursor.ActivePromptID = ""
	}
	return cursor
}

func correlationCanonicalEventName(spec connector.CorrelationSpec, event string) string {
	if lifecycle, ok := spec.LifecycleForEvent(event); ok {
		return string(lifecycle)
	}
	event = strings.TrimSpace(event)
	if event == "" {
		return "unknown"
	}
	return event
}

func correlationCompleteness(value connector.CorrelationCompleteness) audit.CorrelationCompleteness {
	levels := []connector.CorrelationCompletenessLevel{value.Session, value.Turn, value.AgentLifecycle, value.Tool, value.Model, value.NativeOTLP}
	allComplete := true
	for _, level := range levels {
		if level == connector.CorrelationCompletenessUnknown {
			return audit.CorrelationUnknown
		}
		allComplete = allComplete && level == connector.CorrelationCompletenessComplete
	}
	if allComplete {
		return audit.CorrelationComplete
	}
	return audit.CorrelationPartial
}

func parseCorrelationSourceTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func validCorrelationUUIDv7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.Version() == 7 && parsed.String() == strings.ToLower(value)
}

func contextWithHookCorrelation(ctx context.Context, req agentHookRequest, traceID string) context.Context {
	envelope := audit.EnvelopeFromContext(ctx)
	envelope.SemanticEventID = req.SemanticEventID
	envelope.LogicalEventID = req.LogicalEventID
	envelope.ConnectorInstanceID = req.ConnectorInstanceID
	envelope.Connector = req.ConnectorName
	if req.SessionID != "" {
		envelope.SessionID = req.SessionID
	}
	if req.TurnID != "" {
		envelope.TurnID = req.TurnID
	}
	if req.AgentID != "" {
		envelope.AgentID = req.AgentID
	}
	if req.ToolInvocationID != "" {
		envelope.ToolID = req.ToolInvocationID
	}
	if traceID != "" {
		envelope.TraceID = traceID
	}
	return audit.ContextWithEnvelope(ctx, envelope)
}
