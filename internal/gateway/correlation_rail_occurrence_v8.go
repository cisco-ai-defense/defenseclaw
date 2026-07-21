// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

// llmRailCorrelationResult is the durable handoff from a proxy or authenticated
// stream adapter to the shared model/tool emitters. The returned context and
// meta must be used together: the context owns occurrence identity while meta
// owns the connector's typed model/tool facts.
type llmRailCorrelationResult struct {
	ctx              context.Context
	meta             llmEventMeta
	receipt          *audit.CorrelationReceiptLocator
	suppressEmission bool
}

type llmRailCorrelationInput struct {
	store      *audit.Store
	emitter    sidecarRuntimeEmitter
	spec       connector.CorrelationSpec
	rail       audit.CorrelationRail
	surface    connector.CorrelationSurface
	lifecycle  connector.CorrelationLifecycle
	meta       llmEventMeta
	rawPayload []byte
}

// correlateLLMRailOccurrence gives proxy and stream observations the same
// commit-before-export guarantee as hook and native OTLP ingestion. The
// surface adapter supplies only normalized fields; the versioned registry
// decides which of those fields are provider evidence.
func correlateLLMRailOccurrence(
	ctx context.Context,
	input llmRailCorrelationInput,
) (llmRailCorrelationResult, error) {
	result := llmRailCorrelationResult{ctx: ctx, meta: input.meta}
	if ctx == nil {
		ctx = context.Background()
		result.ctx = ctx
	}
	if input.store == nil {
		return result, errors.New("correlation store is unavailable")
	}
	if input.rail != audit.CorrelationRailProxy && input.rail != audit.CorrelationRailStream {
		return result, errors.New("unsupported LLM correlation rail")
	}
	if (input.rail == audit.CorrelationRailProxy) != (input.surface == connector.CorrelationSurfaceProxy) ||
		(input.rail == audit.CorrelationRailStream) != (input.surface == connector.CorrelationSurfaceStream) {
		return result, errors.New("correlation rail and surface disagree")
	}
	if err := input.spec.Validate(); err != nil {
		return result, fmt.Errorf("invalid correlation profile: %w", err)
	}
	if !correlationSpecDeclaresSurface(input.spec, input.surface) {
		return result, fmt.Errorf("connector %s does not declare %s correlation", input.spec.Connector, input.surface)
	}

	repo, err := input.store.CorrelationRepository()
	if err != nil {
		return result, err
	}
	custody := audit.ConnectorCustodyHookOnly
	if input.spec.NativeTelemetry.Stability != connector.NativeTelemetryNone {
		custody = audit.ConnectorCustodyExternal
	}
	instance, err := repo.ResolveConnectorInstance(ctx, input.spec.Connector,
		string(input.spec.ProfileVersion), custody)
	if err != nil {
		return result, err
	}

	meta := input.meta
	meta = restoreLLMRailPendingState(ctx, repo, instance.ConnectorInstanceID,
		input.spec, input.surface, input.lifecycle, meta)
	if meta.TurnID == "" && input.lifecycle == connector.CorrelationLifecycleModelStart &&
		input.spec.Allows(connector.CorrelationInferencePromptBoundaryTurn) {
		turn, turnErr := audit.NewSemanticEventID()
		if turnErr != nil {
			return result, turnErr
		}
		meta.TurnID = string(turn)
	}
	if meta.TurnID == "" && input.rail == audit.CorrelationRailStream && meta.SessionID != "" {
		if cursor, found := uniqueLLMRailCursor(ctx, repo, instance.ConnectorInstanceID, meta); found {
			meta.TurnID = cursor.ActiveTurnID
			if meta.PromptID == "" {
				meta.PromptID = cursor.ActivePromptID
			}
		}
	}

	attributes := normalizedLLMRailAttributes(meta)
	var values []connector.CorrelationValue
	switch input.surface {
	case connector.CorrelationSurfaceProxy:
		values = input.spec.ProxyValues(attributes)
	case connector.CorrelationSurfaceStream:
		values = input.spec.StreamValues(attributes)
	}
	if err := connector.ValidateCorrelationValues(values); err != nil {
		return result, err
	}
	values = appendLLMMintedCorrelationValues(values, meta, input.lifecycle)

	now := time.Now().UTC()
	// Fingerprint only the adapter's authenticated input. Locally restored or
	// minted cursor/turn IDs are durable correlation state, not delivery bytes;
	// including them would turn an exact replay into a false conflict.
	fingerprintHex, err := llmRailFingerprint(input, input.meta)
	if err != nil {
		return result, err
	}
	preferredSource := connector.CorrelationValue{Target: connector.CorrelationTargetSourceEvent,
		Value: meta.SourceEventID, Namespace: input.spec.Connector, IDKind: "source_event"}
	_, sourceDigest := correlationIdentifiersForValues(instance.ConnectorInstanceID, values, preferredSource)
	matchValues := correlationMatchValuesForRail(input.spec, input.rail, values)
	identifiers, _ := correlationIdentifiersForValues(instance.ConnectorInstanceID, matchValues, preferredSource)
	receipt := correlationReceiptForRail(input.spec, instance.ConnectorInstanceID, input.rail,
		input.surface, meta.SourceEventID, sourceDigest, fingerprintHex, now)
	matchInput := audit.CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Receipt:             receiptLookup(receipt),
		Identifiers:         identifiers,
		MirrorCompatibility: mirrorCompatibilityForRail(input.spec, input.rail, input.lifecycle),
	}
	match, err := repo.MatchOccurrence(ctx, matchInput)
	if err != nil {
		return result, err
	}
	semantic, err := audit.NewSemanticEventID()
	if err != nil {
		return result, err
	}
	logical := audit.LogicalEventID(semantic)
	if match.MergeAllowed && match.LogicalEventID != "" {
		logical = match.LogicalEventID
	}
	envelope := audit.EnvelopeFromContext(ctx)
	exactIdentityClaims := []audit.CorrelationExactIdentityClaim(nil)
	if !match.Conflict {
		exactIdentityClaims = correlationExactIdentityClaims(
			input.spec, instance.ConnectorInstanceID, input.rail, input.lifecycle, values,
		)
	}
	tx, occurrence, err := repo.BeginOccurrence(ctx, audit.CorrelationOccurrenceInput{
		Event: audit.CorrelationEvent{
			SemanticEventID: semantic, LogicalEventID: logical,
			Connector: input.spec.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
			Rail: input.rail, EventName: string(input.lifecycle), ReceivedTime: now,
			SourceEventDigest: sourceDigest, FingerprintSHA256: fingerprintHex,
			FirstRequestID: envelope.RequestID, ProfileVersion: string(input.spec.ProfileVersion),
			Completeness: correlationCompleteness(input.spec.Completeness),
		},
		Receipt: receipt, ExactIdentityClaims: exactIdentityClaims,
	})
	if err != nil {
		return result, err
	}
	defer tx.Rollback() //nolint:errcheck
	if occurrence.Status == audit.CorrelationOccurrenceReplay {
		if err := tx.Commit(); err != nil {
			return result, err
		}
		resolved, resolveErr := repo.MatchOccurrence(ctx, audit.CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID,
			SemanticEventID:     occurrence.SemanticEventID,
		})
		if resolveErr == nil && resolved.LogicalEventID != "" {
			logical = resolved.LogicalEventID
		} else {
			logical = audit.LogicalEventID(occurrence.SemanticEventID)
		}
		result.ctx = contextWithLLMRailCorrelation(ctx, meta, input.spec.Connector, instance,
			occurrence.SemanticEventID, logical)
		result.meta = meta
		result.receipt = occurrence.Receipt
		result.suppressEmission = occurrence.SuppressEmission
		return result, nil
	}
	semantic = occurrence.SemanticEventID
	logical = occurrence.LogicalEventID
	if occurrence.Status == audit.CorrelationOccurrenceConflict {
		logical = audit.LogicalEventID(semantic)
	}

	for _, value := range values {
		digest := correlationValueDigest(instance.ConnectorInstanceID, value)
		kind, ok := auditIdentifierKind(value)
		if digest == "" || !ok || value.Target == connector.CorrelationTargetSemanticEvent {
			continue
		}
		if _, err := tx.PutIdentifier(ctx, audit.CorrelationIdentifier{
			SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: typedCorrelationNamespace(value), Kind: kind, ValueDigest: digest,
			NormalizedValue: value.Value, SourceField: value.Path,
			Origin: correlationIdentityOrigin(value.Origin), ProfileVersion: string(input.spec.ProfileVersion),
			ObservedAt: now,
		}); err != nil {
			return result, err
		}
	}
	var relationships []audit.CorrelationRelationship
	matchRelationships, err := putCorrelationMatchRelationships(ctx, tx, semantic, occurrence, match, now)
	if err != nil {
		return result, err
	}
	relationships = append(relationships, matchRelationships...)
	var traceID, spanID string
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		traceID, spanID = spanContext.TraceID().String(), spanContext.SpanID().String()
	}
	traceRelationships, err := putCorrelationTraceTopology(ctx, tx, semantic, traceID, spanID, now)
	if err != nil {
		return result, err
	}
	relationships = append(relationships, traceRelationships...)
	stateAdmissible := occurrence.Status != audit.CorrelationOccurrenceConflict
	if stateAdmissible {
		identityRelationships, identityErr := putHookIdentityRelationships(
			ctx, tx, semantic, llmRailIdentityRequest(meta, values), input.spec, input.lifecycle, now,
		)
		if identityErr != nil {
			return result, identityErr
		}
		relationships = append(relationships, identityRelationships...)
		if err := updateLLMRailState(ctx, tx, instance.ConnectorInstanceID, input.spec,
			input.surface, input.lifecycle, meta, semantic, fingerprintHex, now); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}

	result.ctx = contextWithLLMRailCorrelation(ctx, meta, input.spec.Connector, instance, semantic, logical)
	result.meta = meta
	result.receipt = occurrence.Receipt
	if err := emitCorrelationRelationshipsV8WithEmitter(result.ctx, input.emitter,
		observability.SourceConnector, input.spec.Connector, semantic, logical,
		instance.ConnectorInstanceID, relationships); err != nil {
		fmt.Fprintln(os.Stderr, "[gateway] committed correlation relationship export incomplete")
	}
	return result, nil
}

func correlationSpecDeclaresSurface(spec connector.CorrelationSpec, surface connector.CorrelationSurface) bool {
	for _, candidate := range spec.Surfaces {
		if candidate == surface {
			return true
		}
	}
	return false
}

func llmRailFingerprint(input llmRailCorrelationInput, meta llmEventMeta) (string, error) {
	payload, err := json.Marshal(struct {
		Domain         string                         `json:"domain"`
		Rail           audit.CorrelationRail          `json:"rail"`
		Surface        connector.CorrelationSurface   `json:"surface"`
		Lifecycle      connector.CorrelationLifecycle `json:"lifecycle"`
		Connector      string                         `json:"connector"`
		SessionID      string                         `json:"session_id,omitempty"`
		TurnID         string                         `json:"turn_id,omitempty"`
		SourceEventID  string                         `json:"source_event_id,omitempty"`
		SourceSequence string                         `json:"source_sequence,omitempty"`
		PromptID       string                         `json:"prompt_id,omitempty"`
		ResponseID     string                         `json:"response_id,omitempty"`
		ToolID         string                         `json:"tool_id,omitempty"`
		RawPayload     []byte                         `json:"raw_payload"`
	}{
		Domain: "llm-rail-occurrence-v1", Rail: input.rail, Surface: input.surface,
		Lifecycle: input.lifecycle, Connector: input.spec.Connector,
		SessionID: meta.SessionID, TurnID: meta.TurnID,
		SourceEventID: meta.SourceEventID, SourceSequence: meta.SourceSequence,
		PromptID: meta.PromptID, ResponseID: meta.ResponseID, ToolID: meta.ToolID,
		RawPayload: input.rawPayload,
	})
	if err != nil {
		return "", fmt.Errorf("encode LLM correlation fingerprint: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func llmRailIdentityRequest(
	meta llmEventMeta,
	values []connector.CorrelationValue,
) agentHookRequest {
	origins := make(map[connector.CorrelationTarget]connector.CorrelationOrigin, len(values))
	for _, value := range values {
		if _, exists := origins[value.Target]; !exists || value.Origin == connector.CorrelationOriginReported {
			origins[value.Target] = value.Origin
		}
	}
	return agentHookRequest{
		SessionID: meta.SessionID, TurnID: meta.TurnID, AgentID: meta.AgentID,
		RootAgentID: meta.RootAgentID, ParentAgentID: meta.ParentAgentID,
		RootSessionID: meta.RootSessionID, ParentSessionID: meta.ParentSessionID,
		ExecutionID: meta.ExecutionID, ToolInvocationID: meta.ToolID,
		ModelRequestID: meta.PromptID, ModelResponseID: meta.ResponseID,
		CorrelationOrigins: origins,
	}
}

func llmRailBindingsForSurface(
	spec connector.CorrelationSpec,
	surface connector.CorrelationSurface,
) []connector.CorrelationFieldBinding {
	switch surface {
	case connector.CorrelationSurfaceProxy:
		return spec.ProxyBindings
	case connector.CorrelationSurfaceStream:
		return spec.StreamBindings
	default:
		return nil
	}
}

func llmRailOperationIdentity(
	instance audit.ConnectorInstanceID,
	spec connector.CorrelationSpec,
	surface connector.CorrelationSurface,
	target connector.CorrelationTarget,
	reported bool,
) hookOperationIdentity {
	if reported {
		for _, binding := range llmRailBindingsForSurface(spec, surface) {
			if binding.Target != target {
				continue
			}
			return hookOperationIdentityForValue(instance, connector.CorrelationValue{
				Target: target, Namespace: binding.Namespace, IDKind: binding.IDKind,
			}, target)
		}
	}
	return hookOperationIdentityForValue(instance, connector.CorrelationValue{
		Target: target, Namespace: "defenseclaw", IDKind: string(target),
	}, target)
}

func normalizedLLMRailAttributes(meta llmEventMeta) map[string]interface{} {
	return map[string]interface{}{
		"session_id": meta.SessionID, "sessionKey": meta.SessionID,
		"response_id": meta.reportedResponseID(), "provider_response_id": meta.reportedResponseID(),
		"tool_call_id": meta.reportedToolID(), "provider_tool_call_id": meta.reportedToolID(),
		"messageId": meta.MessageID, "runId": meta.RunID,
		"sequence": meta.SourceSequence,
	}
}

func appendLLMMintedCorrelationValues(
	values []connector.CorrelationValue,
	meta llmEventMeta,
	lifecycle connector.CorrelationLifecycle,
) []connector.CorrelationValue {
	appendValue := func(target connector.CorrelationTarget, value string, origin connector.CorrelationOrigin) {
		if value == "" {
			return
		}
		values = append(values, connector.CorrelationValue{
			Target: target, Value: value, Path: "defenseclaw." + string(origin) + "." + string(target),
			Origin: origin, Namespace: "defenseclaw", IDKind: string(target),
		})
	}
	appendValue(connector.CorrelationTargetTurn, meta.TurnID, connector.CorrelationOriginMinted)
	appendValue(connector.CorrelationTargetAgent, meta.AgentID, connector.CorrelationOriginDerived)
	if lifecycle == connector.CorrelationLifecycleModelStart || lifecycle == connector.CorrelationLifecycleModelEnd {
		appendValue(connector.CorrelationTargetModelRequest, meta.PromptID, connector.CorrelationOriginMinted)
	}
	if lifecycle == connector.CorrelationLifecycleModelEnd && !meta.ResponseIDReported {
		appendValue(connector.CorrelationTargetModelResponse, meta.ResponseID, connector.CorrelationOriginMinted)
	}
	if (lifecycle == connector.CorrelationLifecycleToolStart || lifecycle == connector.CorrelationLifecycleToolEnd) &&
		!meta.ToolIDReported {
		appendValue(connector.CorrelationTargetTool, meta.ToolID, connector.CorrelationOriginMinted)
	}
	return dedupeCorrelationValues(values, nil)
}

func correlationReceiptForRail(
	spec connector.CorrelationSpec,
	instance audit.ConnectorInstanceID,
	rail audit.CorrelationRail,
	surface connector.CorrelationSurface,
	sourceEventID, sourceDigest, fingerprint string,
	now time.Time,
) *audit.CorrelationReceiptClaim {
	if sourceEventID == "" || sourceDigest == "" || !spec.AllowsReceiptTarget(connector.CorrelationTargetSourceEvent) {
		return nil
	}
	return &audit.CorrelationReceiptClaim{
		SourceKeyDigest:   correlationReceiptSourceKey(instance, rail, string(surface), sourceDigest),
		FingerprintSHA256: fingerprint, ReceivedAt: now, ExpiresAt: now.Add(correlationReceiptTTL),
	}
}

func restoreLLMRailPendingState(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstanceID,
	spec connector.CorrelationSpec,
	surface connector.CorrelationSurface,
	lifecycle connector.CorrelationLifecycle,
	meta llmEventMeta,
) llmEventMeta {
	var operationID string
	var operationType audit.CorrelationOperationType
	var target connector.CorrelationTarget
	var reported bool
	switch lifecycle {
	case connector.CorrelationLifecycleModelEnd:
		operationID, operationType = meta.PromptID, audit.CorrelationOperationModel
		target = connector.CorrelationTargetModelRequest
	case connector.CorrelationLifecycleToolStart:
		// A proxy tool proposal is emitted from the same provider response as
		// the model end, but the tool record is intentionally committed first
		// so policy can inspect it before the response leaves the gateway. Join
		// it to the turn only through the exact prompt operation ID retained at
		// model start; never consult a session's latest turn here.
		operationID, operationType = meta.PromptID, audit.CorrelationOperationModel
		target = connector.CorrelationTargetModelRequest
	case connector.CorrelationLifecycleToolEnd:
		operationID, operationType = meta.ToolID, audit.CorrelationOperationTool
		target, reported = connector.CorrelationTargetTool, meta.ToolIDReported
	default:
		return meta
	}
	if operationID == "" {
		return meta
	}
	identity := llmRailOperationIdentity(instance, spec, surface, target, reported)
	if !identity.valid() {
		return meta
	}
	operation, err := repo.FindUniquePendingOperation(ctx, audit.CorrelationPendingQuery{
		ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
		OperationID: operationID, Type: operationType,
		ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
	})
	if err != nil {
		return meta
	}
	if meta.SessionID == "" {
		meta.SessionID = operation.SessionID
	}
	if meta.TurnID == "" {
		meta.TurnID = operation.TurnID
	}
	if meta.AgentID == "" {
		meta.AgentID = operation.AgentID
	}
	if meta.ExecutionID == "" {
		meta.ExecutionID = operation.ExecutionID
	}
	return meta
}

func uniqueLLMRailCursor(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstanceID,
	meta llmEventMeta,
) (audit.CorrelationCursor, bool) {
	var cursor audit.CorrelationCursor
	var err error
	if meta.AgentID != "" {
		cursor, err = repo.GetCursor(ctx, instance, meta.SessionID, meta.AgentID)
	} else {
		cursor, err = repo.FindActiveCursor(ctx, instance, meta.SessionID)
	}
	return cursor, err == nil
}

func updateLLMRailState(
	ctx context.Context,
	tx *audit.CorrelationTx,
	instance audit.ConnectorInstanceID,
	spec connector.CorrelationSpec,
	surface connector.CorrelationSurface,
	lifecycle connector.CorrelationLifecycle,
	meta llmEventMeta,
	semantic audit.SemanticEventID,
	fingerprint string,
	now time.Time,
) error {
	if meta.SessionID != "" && meta.AgentID != "" && meta.TurnID != "" {
		sequence := uint64(1)
		if value, err := strconv.ParseUint(strings.TrimSpace(meta.SourceSequence), 10, 64); err == nil && value > 0 {
			sequence = value
		} else if meta.Sequence > 0 {
			sequence = uint64(meta.Sequence)
		}
		cursor := audit.CorrelationCursor{
			ConnectorInstanceID: instance, SessionID: meta.SessionID, AgentID: meta.AgentID,
			ExecutionID: meta.ExecutionID, ActiveTurnID: meta.TurnID, ActivePromptID: meta.PromptID,
			Phase: string(lifecycle), Sequence: sequence, LastSemanticEventID: semantic,
			ProfileVersion: string(spec.ProfileVersion), Active: true, UpdatedAt: now,
		}
		if err := tx.PutCursor(ctx, cursor); err != nil && !errors.Is(err, audit.ErrCorrelationStale) {
			return err
		}
	}
	switch lifecycle {
	case connector.CorrelationLifecycleModelStart:
		if meta.PromptID != "" {
			identity := llmRailOperationIdentity(instance, spec, surface,
				connector.CorrelationTargetModelRequest, false)
			if !identity.valid() {
				return errors.New("model rail start is missing a typed pending-operation identity")
			}
			return tx.PutPendingOperation(ctx, audit.CorrelationPendingOperation{
				ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
				OperationID: meta.PromptID, ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
				Type: audit.CorrelationOperationModel, SessionID: meta.SessionID, TurnID: meta.TurnID,
				AgentID: meta.AgentID, ExecutionID: meta.ExecutionID, StartSemanticEventID: semantic,
				StartedAt: now, InputDigest: fingerprint, Status: audit.CorrelationOperationActive, UpdatedAt: now,
			})
		}
	case connector.CorrelationLifecycleModelEnd:
		if meta.PromptID != "" {
			identity := llmRailOperationIdentity(instance, spec, surface,
				connector.CorrelationTargetModelRequest, false)
			locator := identity.locator(instance, audit.CorrelationOperationModel, meta.PromptID)
			if locator == nil {
				return errors.New("model rail end is missing a typed pending-operation identity")
			}
			err := tx.ResolvePendingOperation(ctx, *locator,
				semantic, audit.CorrelationOperationCompleted, now)
			if err != nil && !errors.Is(err, audit.ErrCorrelationStale) && !errors.Is(err, audit.ErrCorrelationNotFound) {
				return err
			}
		}
	case connector.CorrelationLifecycleToolStart:
		if meta.ToolID != "" {
			identity := llmRailOperationIdentity(instance, spec, surface,
				connector.CorrelationTargetTool, meta.ToolIDReported)
			if !identity.valid() {
				return errors.New("tool rail start is missing a typed pending-operation identity")
			}
			return tx.PutPendingOperation(ctx, audit.CorrelationPendingOperation{
				ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
				OperationID: meta.ToolID, ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
				Type: audit.CorrelationOperationTool, Name: meta.ToolName,
				SessionID: meta.SessionID, TurnID: meta.TurnID, AgentID: meta.AgentID,
				ExecutionID: meta.ExecutionID, StartSemanticEventID: semantic,
				StartedAt: now, InputDigest: fingerprint, Status: audit.CorrelationOperationActive, UpdatedAt: now,
			})
		}
	case connector.CorrelationLifecycleToolEnd:
		if meta.ToolID != "" {
			identity := llmRailOperationIdentity(instance, spec, surface,
				connector.CorrelationTargetTool, meta.ToolIDReported)
			locator := identity.locator(instance, audit.CorrelationOperationTool, meta.ToolID)
			if locator == nil {
				return errors.New("tool rail end is missing a typed pending-operation identity")
			}
			err := tx.ResolvePendingOperation(ctx, *locator,
				semantic, audit.CorrelationOperationCompleted, now)
			if err != nil && !errors.Is(err, audit.ErrCorrelationStale) && !errors.Is(err, audit.ErrCorrelationNotFound) {
				return err
			}
		}
	}
	return nil
}

func contextWithLLMRailCorrelation(
	ctx context.Context,
	meta llmEventMeta,
	connectorName string,
	instance audit.ConnectorInstance,
	semantic audit.SemanticEventID,
	logical audit.LogicalEventID,
) context.Context {
	envelope := audit.EnvelopeFromContext(ctx)
	envelope.SemanticEventID = string(semantic)
	envelope.LogicalEventID = string(logical)
	envelope.ConnectorInstanceID = string(instance.ConnectorInstanceID)
	envelope.Connector = connectorName
	if meta.SessionID != "" {
		envelope.SessionID = meta.SessionID
	}
	if meta.TurnID != "" {
		envelope.TurnID = meta.TurnID
	}
	if meta.AgentID != "" {
		envelope.AgentID = meta.AgentID
	}
	if meta.ToolID != "" {
		envelope.ToolID = meta.ToolID
	}
	return audit.ContextWithEnvelope(ctx, envelope)
}

func finalizeLLMRailCorrelationReceipt(
	ctx context.Context,
	store *audit.Store,
	receipt *audit.CorrelationReceiptLocator,
) error {
	if receipt == nil {
		return nil
	}
	if store == nil {
		return errors.New("correlation store is unavailable")
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		return err
	}
	return repo.MarkOccurrenceCanonicalPersisted(ctx, *receipt, time.Now().UTC())
}

// finalizeLLMRailCanonicalEmission makes replay suppression contingent on the
// canonical log actually reaching the SQLite-first local pipeline. A failed or
// policy-dropped emission leaves the receipt pending, so a later exact replay
// can retry rather than being silently discarded.
func finalizeLLMRailCanonicalEmission(
	ctx context.Context,
	store *audit.Store,
	receipt *audit.CorrelationReceiptLocator,
	localPersisted bool,
	emitErr error,
) error {
	if emitErr != nil {
		return emitErr
	}
	if !localPersisted {
		return nil
	}
	return finalizeLLMRailCorrelationReceipt(ctx, store, receipt)
}
