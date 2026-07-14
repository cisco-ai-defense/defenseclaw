// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

var errNativeOTLPCorrelationV8 = errors.New("native OTLP correlation persistence failed")
var errNativeOTLPCorrelationInputV8 = errors.New("native OTLP correlation input rejected")

type nativeOTLPCorrelationResult struct {
	ctx              context.Context
	suppressEmission bool
	connector        string
	profileVersion   string
	instance         audit.ConnectorInstance
	semantic         audit.SemanticEventID
	receipt          *audit.CorrelationReceiptLocator
}

// nativeOTLPContextualMatch carries a non-collapsing relationship from a
// native leaf to one durable hook boundary. Exact provider identity remains
// the only authority that can merge logical groups; this structure is used
// only after exact matching has found no merge.
type nativeOTLPContextualMatch struct {
	match   audit.CorrelationMatchResult
	pending *audit.CorrelationPendingLocator
}

type nativeOTLPCorrelationValuesContextKey struct{}

type nativeOTLPCorrelationValuesContext struct {
	connector string
	values    []connector.CorrelationValue
}

// correlateNativeOTLPLeafV8 is the native-rail transaction boundary. The
// caller invokes it only after the existing source-aware classifier has
// accepted the leaf. No classifier alias is visible here: business identity
// is resolved from the authenticated connector's reviewed NativeOTLPBindings.
//
// The occurrence, identifiers, exact relationships, and trace topology commit
// before a provider/import callback can run. A committed exact replay returns
// suppressEmission after its durable receipt delivery count has advanced.
func (a *APIServer) correlateNativeOTLPLeafV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	authenticatedSource string,
	receiptTime time.Time,
) (nativeOTLPCorrelationResult, error) {
	result := nativeOTLPCorrelationResult{ctx: ctx}
	if a == nil {
		return result, nil
	}
	if ctx == nil || receiptTime.IsZero() {
		return result, errNativeOTLPCorrelationV8
	}
	spec, err := a.correlationSpecForConnectorV8(authenticatedSource)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	if spec.Connector != authenticatedSource || spec.NativeTelemetry.Stability == connector.NativeTelemetryNone {
		// Custom test catalogs and hook/proxy-only connectors do not acquire
		// native correlation authority merely because a leaf was decoded. Carry
		// an explicit empty resolution marker so canonical construction cannot
		// fall back to an offline/default profile after the versioned runtime
		// profile failed closed.
		result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource,
			audit.ConnectorInstance{}, "", "", nil, "")
		return result, nil
	}
	if !nativeOTLPSignalDeclared(spec.NativeTelemetry, leaf.signal) {
		return result, fmt.Errorf("%w: %s does not declare %s", errNativeOTLPCorrelationV8,
			authenticatedSource, leaf.signal)
	}
	attributes, err := nativeOTLPDeclaredAttributes(leaf, spec)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationInputV8, err)
	}
	values := spec.NativeOTLPValues(attributes)
	if err := validateNativeOTLPValueConsistency(values); err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationInputV8, err)
	}
	if a.store == nil {
		// Reduced mapping fixtures may intentionally omit the audit store. Carry
		// the already validated runtime-registry values forward so even that
		// path cannot re-resolve a different offline/default profile. Production
		// v8 startup requires the local audit store before native ingestion.
		traceID, _ := nativeOTLPTraceSpan(leaf)
		result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource,
			audit.ConnectorInstance{}, "", "", values, traceID)
		return result, nil
	}
	repo, err := a.store.CorrelationRepository()
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	instance, err := repo.ResolveConnectorInstance(ctx, authenticatedSource,
		string(spec.ProfileVersion), audit.ConnectorCustodyExternal)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	result.connector = authenticatedSource
	result.profileVersion = string(spec.ProfileVersion)
	result.instance = instance

	reportedSemantic, err := nativeOTLPReportedSemantic(values)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationInputV8, err)
	}
	reportedLogical, err := nativeOTLPReportedLogical(leaf, reportedSemantic != "")
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationInputV8, err)
	}
	semantic := reportedSemantic
	if semantic == "" {
		semantic, err = audit.NewSemanticEventID()
		if err != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
		}
	}
	fingerprint, err := nativeOTLPLeafFingerprint(leaf)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	now := receiptTime.UTC()
	traceID, spanID := nativeOTLPTraceSpan(leaf)
	preferredSource, _ := spec.NativeOTLPValue(attributes, connector.CorrelationTargetSourceEvent)
	_, sourceDigest := correlationIdentifiersForValues(instance.ConnectorInstanceID, values, preferredSource)
	identifiers, _ := correlationIdentifiersForValues(instance.ConnectorInstanceID,
		correlationMatchValuesForRail(spec, audit.CorrelationRailNativeOTLP, values), preferredSource)
	receipt := nativeOTLPReceipt(spec, instance.ConnectorInstanceID, leaf.signal,
		sourceDigest, traceID, spanID, fingerprint, now)
	eventName := nativeOTLPCorrelationEventName(match)
	lifecycle, hasOccurrenceLifecycle := nativeOTLPOccurrenceLifecycle(leaf.signal, eventName)
	matchInput := audit.CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Receipt:             receiptLookup(receipt),
		Identifiers:         identifiers,
	}
	// Let a durable receipt win on replay so BeginOccurrence can advance its
	// delivery count. An independently reported semantic ID is queried below
	// for the cross-rail attach path; it is passed through the main resolver
	// only when no receipt can account for delivery.
	if receipt == nil {
		matchInput.SemanticEventID = reportedSemantic
	}
	// A trace+span pair identifies one span leaf, but not an arbitrary log
	// record carried inside that span. Logs retain topology below without
	// receiving same-as authority from trace context alone.
	if leaf.signal == otelSignalTraces && traceID != "" && spanID != "" {
		matchInput.TraceID, matchInput.SpanID = traceID, spanID
	}
	if compatibility := nativeOTLPMirrorCompatibility(spec, leaf.signal, eventName); compatibility != nil {
		matchInput.MirrorCompatibility = compatibility
	}
	matched, err := repo.MatchOccurrence(ctx, matchInput)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	contextual := nativeOTLPContextualMatch{}
	if hasOccurrenceLifecycle && !matched.MergeAllowed && !matched.Conflict {
		contextual, err = resolveNativeOTLPContextualMatchV8(
			ctx, repo, instance, spec, values, lifecycle,
		)
		if err != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
		}
		if contextual.match.Rank != audit.CorrelationMatchNone {
			// Membership matches are materialized as typed identity-node edges.
			// A unique pending operation or prompt boundary adds the stronger
			// non-collapsing semantic-event relationship for this occurrence.
			matched = contextual.match
		}
	}
	if matched.Conflict && reportedSemantic != "" {
		// The same exact source key with a different fingerprint is a new,
		// conflicted observation. It must not attach to or rewrite the sender's
		// previously reported semantic occurrence.
		semantic, err = audit.NewSemanticEventID()
		if err != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
		}
		reportedSemantic, reportedLogical = "", ""
	}
	logical := audit.LogicalEventID(semantic)
	if reportedLogical != "" {
		logical = reportedLogical
	}
	if matched.MergeAllowed && matched.LogicalEventID != "" {
		if reportedLogical != "" && reportedLogical != matched.LogicalEventID {
			return result, fmt.Errorf("%w: reported logical event conflicts with exact match", errNativeOTLPCorrelationInputV8)
		}
		logical = matched.LogicalEventID
	}
	var existingSemantic audit.CorrelationMatchResult
	if reportedSemantic != "" && !matched.Conflict {
		existingSemantic, err = repo.MatchOccurrence(ctx, audit.CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID,
			SemanticEventID:     reportedSemantic,
		})
		if err != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
		}
		if existingSemantic.Rank == audit.CorrelationMatchSemanticEvent {
			if reportedLogical != "" && reportedLogical != existingSemantic.LogicalEventID {
				return result, fmt.Errorf("%w: reported logical event conflicts with stored occurrence", errNativeOTLPCorrelationInputV8)
			}
			logical = existingSemantic.LogicalEventID
		}
	}
	if reportedLogical != "" && existingSemantic.Rank != audit.CorrelationMatchSemanticEvent &&
		reportedLogical != audit.LogicalEventID(reportedSemantic) {
		return result, fmt.Errorf("%w: a new semantic occurrence cannot invent a logical group", errNativeOTLPCorrelationInputV8)
	}
	if reportedSemantic != "" && existingSemantic.Rank != audit.CorrelationMatchSemanticEvent &&
		matched.Rank == audit.CorrelationMatchReceipt && matched.MatchedSemanticEventID != reportedSemantic {
		return result, fmt.Errorf("%w: reported semantic event conflicts with exact receipt", errNativeOTLPCorrelationInputV8)
	}
	if existingSemantic.Rank == audit.CorrelationMatchSemanticEvent {
		// A later rail can attach evidence to the immutable occurrence without
		// rewriting its original rail/event/profile metadata.
		var tx *audit.CorrelationTx
		var stored audit.CorrelationEvent
		attachOccurrence := audit.CorrelationOccurrenceResult{
			SemanticEventID: reportedSemantic, Status: audit.CorrelationOccurrenceExisting,
		}
		var attachErr error
		if receipt == nil {
			tx, stored, attachErr = repo.BeginExistingOccurrence(ctx, reportedSemantic)
		} else {
			tx, stored, attachOccurrence, attachErr = repo.BeginExistingOccurrenceWithReceipt(
				ctx, reportedSemantic, *receipt,
			)
		}
		if attachErr != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, attachErr)
		}
		if stored.ConnectorInstanceID != instance.ConnectorInstanceID || stored.Connector != authenticatedSource {
			_ = tx.Rollback()
			return result, fmt.Errorf("%w: reported semantic event belongs to a different connector", errNativeOTLPCorrelationInputV8)
		}
		if attachOccurrence.Status == audit.CorrelationOccurrenceConflict {
			// The receipt claim detected an integrity conflict inside the write
			// transaction. Roll it back before creating the distinct conflicting
			// occurrence through BeginOccurrence, which repeats the claim and
			// closes any preflight race atomically.
			_ = tx.Rollback()
			semantic = attachOccurrence.SemanticEventID
			logical = audit.LogicalEventID(semantic)
			reportedSemantic, reportedLogical = "", ""
			existingSemantic = audit.CorrelationMatchResult{}
			matched = audit.CorrelationMatchResult{
				Rank: audit.CorrelationMatchReceipt, Conflict: true,
				ConflictsWith: attachOccurrence.ConflictsWith,
			}
		} else {
			defer tx.Rollback() //nolint:errcheck
			if attachOccurrence.Status == audit.CorrelationOccurrenceReplay {
				if err := tx.Commit(); err != nil {
					return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
				}
				result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource, instance,
					stored.SemanticEventID, stored.LogicalEventID, values, traceID)
				result.semantic = stored.SemanticEventID
				result.receipt = attachOccurrence.Receipt
				result.suppressEmission = attachOccurrence.SuppressEmission
				return result, nil
			}
			evidenceOccurrence := audit.CorrelationOccurrenceResult{
				SemanticEventID: stored.SemanticEventID, Status: audit.CorrelationOccurrenceExisting,
			}
			relationships, err := persistNativeOTLPEvidence(ctx, tx, stored.SemanticEventID, instance,
				spec, values, evidenceOccurrence, matched, lifecycle, hasOccurrenceLifecycle,
				traceID, spanID, now)
			if err != nil {
				return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
			}
			if err := tx.Commit(); err != nil {
				return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
			}
			result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource, instance,
				stored.SemanticEventID, stored.LogicalEventID, values, traceID)
			result.semantic = stored.SemanticEventID
			result.receipt = attachOccurrence.Receipt
			if err := a.emitCorrelationRelationshipsV8(result.ctx, observability.SourceOTelReceiver,
				authenticatedSource, stored.SemanticEventID, stored.LogicalEventID,
				instance.ConnectorInstanceID, relationships); err != nil {
				// The ledger is authoritative after commit. Optional relationship-log
				// delivery health cannot roll the occurrence back or admit it twice.
				fmt.Fprintln(os.Stderr, "[otel-ingest] committed correlation relationship export incomplete")
			}
			return result, nil
		}
	}

	exactIdentityClaims := []audit.CorrelationExactIdentityClaim(nil)
	if hasOccurrenceLifecycle && !matched.Conflict {
		exactIdentityClaims = correlationExactIdentityClaims(
			spec, instance.ConnectorInstanceID, audit.CorrelationRailNativeOTLP, lifecycle, values,
		)
	}
	envelope := audit.EnvelopeFromContext(ctx)
	tx, occurrence, err := repo.BeginOccurrence(ctx, audit.CorrelationOccurrenceInput{
		Event: audit.CorrelationEvent{
			SemanticEventID: semantic, LogicalEventID: logical,
			Connector: authenticatedSource, ConnectorInstanceID: instance.ConnectorInstanceID,
			Rail: audit.CorrelationRailNativeOTLP, EventName: eventName,
			SourceTime: nativeOTLPSourceTime(leaf), ReceivedTime: now,
			SourceEventDigest: sourceDigest, FingerprintSHA256: fingerprint,
			FirstRequestID: envelope.RequestID, ProfileVersion: string(spec.ProfileVersion),
			Completeness: correlationCompleteness(spec.Completeness),
		},
		Receipt: receipt, ExactIdentityClaims: exactIdentityClaims,
	})
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	defer tx.Rollback() //nolint:errcheck
	if occurrence.Status == audit.CorrelationOccurrenceReplay {
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
		}
		replayLogical := matched.LogicalEventID
		if replayLogical == "" {
			resolved, resolveErr := repo.MatchOccurrence(ctx, audit.CorrelationMatchInput{
				ConnectorInstanceID: instance.ConnectorInstanceID,
				SemanticEventID:     occurrence.SemanticEventID,
			})
			if resolveErr != nil {
				return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, resolveErr)
			}
			replayLogical = resolved.LogicalEventID
		}
		if replayLogical == "" {
			replayLogical = audit.LogicalEventID(occurrence.SemanticEventID)
		}
		result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource, instance,
			occurrence.SemanticEventID, replayLogical, values, traceID)
		result.semantic = occurrence.SemanticEventID
		result.receipt = occurrence.Receipt
		// Suppression is authorized only by this exact receipt's durable
		// canonical-persistence canary, never by connector-level custody.
		result.suppressEmission = occurrence.SuppressEmission
		return result, nil
	}
	semantic = occurrence.SemanticEventID
	logical = occurrence.LogicalEventID
	if occurrence.Status == audit.CorrelationOccurrenceConflict {
		logical = audit.LogicalEventID(semantic)
	}

	relationships, err := persistNativeOTLPEvidence(ctx, tx, semantic, instance, spec, values,
		occurrence, matched, lifecycle, hasOccurrenceLifecycle, traceID, spanID, now)
	if err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	if occurrence.Status != audit.CorrelationOccurrenceConflict &&
		contextual.pending != nil && contextual.pending.OperationID != "" &&
		(lifecycle == connector.CorrelationLifecycleToolEnd ||
			lifecycle == connector.CorrelationLifecycleModelEnd) {
		if resolveErr := tx.ResolvePendingOperation(ctx, *contextual.pending,
			semantic, audit.CorrelationOperationCompleted, now); resolveErr != nil &&
			!errors.Is(resolveErr, audit.ErrCorrelationStale) &&
			!errors.Is(resolveErr, audit.ErrCorrelationNotFound) {
			return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, resolveErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("%w: %v", errNativeOTLPCorrelationV8, err)
	}
	result.ctx = contextWithNativeOTLPCorrelation(ctx, authenticatedSource, instance,
		semantic, logical, values, traceID)
	result.semantic = semantic
	result.receipt = occurrence.Receipt
	if err := a.emitCorrelationRelationshipsV8(result.ctx, observability.SourceOTelReceiver,
		authenticatedSource, semantic, logical, instance.ConnectorInstanceID, relationships); err != nil {
		fmt.Fprintln(os.Stderr, "[otel-ingest] committed correlation relationship export incomplete")
	}
	return result, nil
}

func (a *APIServer) finalizeNativeOTLPCustodyV8(ctx context.Context, result nativeOTLPCorrelationResult) error {
	if a == nil || a.store == nil || result.connector == "" {
		return nil
	}
	repo, err := a.store.CorrelationRepository()
	if err != nil {
		return err
	}
	if result.receipt != nil {
		acceptedAt := time.Now().UTC()
		if err := repo.MarkOccurrenceCanonicalPersisted(ctx, *result.receipt, acceptedAt); err != nil {
			return err
		}
	}
	if result.instance.ExportCustody == audit.ConnectorCustodyDefenseClaw {
		return nil
	}
	promoted, err := repo.ResolveConnectorInstance(ctx, result.connector,
		result.profileVersion, audit.ConnectorCustodyDefenseClaw)
	if err != nil {
		return err
	}
	if promoted.ConnectorInstanceID != result.instance.ConnectorInstanceID ||
		promoted.ExportCustody != audit.ConnectorCustodyDefenseClaw {
		return audit.ErrCorrelationConflict
	}
	return nil
}

func nativeOTLPLeafCanarySucceeded(result otlpInboundLeafResult) bool {
	terminal := func(target otlpInboundTargetResult) bool {
		if target.persistenceFailed || target.invalidMapped || target.invalidRecord || !target.collected {
			return false
		}
		return target.recorded || target.deduplicated || target.acceptedNoObservation
	}
	seen := false
	if result.hasImportTarget {
		if result.primary == nil || !terminal(*result.primary) {
			return false
		}
		seen = true
	} else if result.primary != nil {
		return false
	}
	if result.hasDerivedTarget && len(result.derivatives) == 0 {
		return false
	}
	for _, derivative := range result.derivatives {
		if !terminal(derivative) {
			return false
		}
		seen = true
	}
	return seen
}

func persistNativeOTLPEvidence(
	ctx context.Context,
	tx *audit.CorrelationTx,
	semantic audit.SemanticEventID,
	instance audit.ConnectorInstance,
	spec connector.CorrelationSpec,
	values []connector.CorrelationValue,
	occurrence audit.CorrelationOccurrenceResult,
	matched audit.CorrelationMatchResult,
	lifecycle connector.CorrelationLifecycle,
	hasOccurrenceLifecycle bool,
	traceID, spanID string,
	now time.Time,
) ([]audit.CorrelationRelationship, error) {
	var relationships []audit.CorrelationRelationship
	for _, value := range values {
		kind, ok := auditIdentifierKind(value)
		digest := correlationValueDigest(instance.ConnectorInstanceID, value)
		if !ok || digest == "" || value.Target == connector.CorrelationTargetSemanticEvent {
			continue
		}
		if _, err := tx.PutIdentifier(ctx, audit.CorrelationIdentifier{
			SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: typedCorrelationNamespace(value), Kind: kind, ValueDigest: digest,
			NormalizedValue: value.Value, SourceField: value.Path,
			Origin: correlationIdentityOrigin(value.Origin), ProfileVersion: string(spec.ProfileVersion),
			ObservedAt: now,
		}); err != nil {
			return nil, err
		}
	}
	matchRelationships, err := putCorrelationMatchRelationships(ctx, tx, semantic, occurrence, matched, now)
	if err != nil {
		return nil, err
	}
	relationships = append(relationships, matchRelationships...)
	traceRelationships, err := putCorrelationTraceTopology(ctx, tx, semantic, traceID, spanID, now)
	if err != nil {
		return nil, err
	}
	relationships = append(relationships, traceRelationships...)
	if occurrence.Status != audit.CorrelationOccurrenceConflict && hasOccurrenceLifecycle {
		identityRelationships, identityErr := putHookIdentityRelationships(
			ctx, tx, semantic, nativeOTLPIdentityRequest(values), spec, lifecycle, now,
		)
		if identityErr != nil {
			return nil, identityErr
		}
		relationships = append(relationships, identityRelationships...)
	}
	return relationships, nil
}

func nativeOTLPOccurrenceLifecycle(
	signal otelIngestSignal,
	eventName string,
) (connector.CorrelationLifecycle, bool) {
	if signal == otelSignalMetrics {
		return "", false
	}
	lifecycle := connector.CorrelationLifecycle(eventName)
	switch lifecycle {
	case connector.CorrelationLifecycleModelStart, connector.CorrelationLifecycleModelEnd,
		connector.CorrelationLifecycleToolStart, connector.CorrelationLifecycleToolEnd:
		return lifecycle, true
	default:
		return "", false
	}
}

func nativeOTLPIdentityRequest(values []connector.CorrelationValue) agentHookRequest {
	req := agentHookRequest{
		CorrelationOrigins: make(map[connector.CorrelationTarget]connector.CorrelationOrigin),
		CorrelationValues:  make(map[connector.CorrelationTarget]connector.CorrelationValue),
	}
	for _, value := range values {
		if value.Value == "" {
			continue
		}
		req.CorrelationOrigins[value.Target] = value.Origin
		req.CorrelationValues[value.Target] = value
		switch value.Target {
		case connector.CorrelationTargetSession:
			req.SessionID = value.Value
		case connector.CorrelationTargetRootSession:
			req.RootSessionID = value.Value
		case connector.CorrelationTargetParentSession:
			req.ParentSessionID = value.Value
		case connector.CorrelationTargetTurn:
			req.TurnID = value.Value
		case connector.CorrelationTargetAgent:
			req.AgentID = value.Value
		case connector.CorrelationTargetRootAgent:
			req.RootAgentID = value.Value
		case connector.CorrelationTargetParentAgent:
			req.ParentAgentID = value.Value
		case connector.CorrelationTargetExecution:
			req.ExecutionID = value.Value
		case connector.CorrelationTargetModelRequest:
			req.ModelRequestID = value.Value
		case connector.CorrelationTargetModelResponse:
			req.ModelResponseID = value.Value
		case connector.CorrelationTargetTool:
			req.ToolInvocationID = value.Value
		}
	}
	return req
}

// resolveNativeOTLPContextualMatchV8 joins rails only through causal evidence
// when the native leaf and hook do not share an occurrence-level provider ID.
// The session is required exact scope; operation type and the versioned
// connector allow-list define compatibility. A unique result produces a
// derived caused_by edge but never a logical-group merge.
func resolveNativeOTLPContextualMatchV8(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstance,
	spec connector.CorrelationSpec,
	values []connector.CorrelationValue,
	lifecycle connector.CorrelationLifecycle,
) (nativeOTLPContextualMatch, error) {
	if repo == nil || instance.ConnectorInstanceID == "" || spec.ProfileVersion == "" {
		return nativeOTLPContextualMatch{}, nil
	}
	req := nativeOTLPIdentityRequest(values)
	if req.SessionID == "" {
		// Never use connector-global recency as cross-rail evidence.
		return nativeOTLPContextualMatch{}, nil
	}

	target, operationType, pendingAllowed := nativeOTLPPendingKind(spec, lifecycle)
	if pendingAllowed {
		operation, locator, count, err := findNativeOTLPPendingOperationV8(
			ctx, repo, instance.ConnectorInstanceID, req, spec, target, operationType,
		)
		if err != nil {
			return nativeOTLPContextualMatch{}, err
		}
		if count > 1 {
			return nativeOTLPContextualMatch{match: audit.CorrelationMatchResult{
				Rank: audit.CorrelationMatchUniquePending, Method: audit.CorrelationMethodDerived,
				RuleID: "unique-compatible-native-pending", RuleVersion: string(spec.ProfileVersion),
				Ambiguous: true, CandidateCount: count,
			}}, nil
		}
		if count == 1 {
			return nativeOTLPContextualMatch{
				match: audit.CorrelationMatchResult{
					Rank:                   audit.CorrelationMatchUniquePending,
					MatchedSemanticEventID: operation.StartSemanticEventID,
					Method:                 audit.CorrelationMethodDerived,
					RuleID:                 "unique-compatible-native-pending", RuleVersion: string(spec.ProfileVersion),
					RelationshipType: audit.CorrelationCausedBy, CandidateCount: 1,
				},
				pending: locator,
			}, nil
		}
	}

	if (lifecycle != connector.CorrelationLifecycleModelStart &&
		lifecycle != connector.CorrelationLifecycleModelEnd) ||
		!spec.Allows(connector.CorrelationInferencePromptBoundaryTurn) {
		return nativeOTLPContextualMatch{}, nil
	}
	cursor, err := nativeOTLPActiveCursorV8(
		ctx, repo, instance.ConnectorInstanceID, req.SessionID, req.AgentID,
	)
	if errors.Is(err, audit.ErrCorrelationNotFound) {
		return nativeOTLPContextualMatch{}, nil
	}
	if errors.Is(err, audit.ErrCorrelationConflict) {
		return nativeOTLPContextualMatch{match: audit.CorrelationMatchResult{
			Rank: audit.CorrelationMatchProfileComposite, Method: audit.CorrelationMethodDerived,
			RuleID: "unique-active-prompt-boundary", RuleVersion: string(spec.ProfileVersion),
			Ambiguous: true, CandidateCount: 2,
		}}, nil
	}
	if err != nil {
		return nativeOTLPContextualMatch{}, err
	}
	if !cursor.Active || cursor.ActiveTurnID == "" || cursor.LastSemanticEventID == "" ||
		cursor.ProfileVersion != string(spec.ProfileVersion) ||
		cursor.Phase != string(connector.CorrelationLifecycleTurnStart) {
		return nativeOTLPContextualMatch{}, nil
	}
	return nativeOTLPContextualMatch{match: audit.CorrelationMatchResult{
		Rank:                   audit.CorrelationMatchProfileComposite,
		MatchedSemanticEventID: cursor.LastSemanticEventID,
		Method:                 audit.CorrelationMethodDerived,
		RuleID:                 "unique-active-prompt-boundary", RuleVersion: string(spec.ProfileVersion),
		RelationshipType: audit.CorrelationCausedBy, CandidateCount: 1,
	}}, nil
}

func nativeOTLPPendingKind(
	spec connector.CorrelationSpec,
	lifecycle connector.CorrelationLifecycle,
) (connector.CorrelationTarget, audit.CorrelationOperationType, bool) {
	switch lifecycle {
	case connector.CorrelationLifecycleToolStart, connector.CorrelationLifecycleToolEnd:
		return connector.CorrelationTargetTool, audit.CorrelationOperationTool,
			spec.Allows(connector.CorrelationInferenceUniquePendingTool)
	case connector.CorrelationLifecycleModelStart, connector.CorrelationLifecycleModelEnd:
		return connector.CorrelationTargetModelRequest, audit.CorrelationOperationModel,
			spec.Allows(connector.CorrelationInferenceModelBoundary)
	default:
		return "", "", false
	}
}

func findNativeOTLPPendingOperationV8(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstanceID,
	req agentHookRequest,
	spec connector.CorrelationSpec,
	target connector.CorrelationTarget,
	operationType audit.CorrelationOperationType,
) (audit.CorrelationPendingOperation, *audit.CorrelationPendingLocator, int, error) {
	identities := hookOperationIdentityCandidates(instance, req, spec, target, "")
	if len(identities) == 0 || req.SessionID == "" {
		return audit.CorrelationPendingOperation{}, nil, 0, nil
	}
	candidates := make([]audit.CorrelationPendingOperation, 0, 2)
	seen := make(map[string]bool, 2)
	for _, identity := range identities {
		operations, err := repo.ListPendingOperations(ctx, audit.CorrelationPendingQuery{
			ConnectorInstanceID: instance, Namespace: identity.namespace, Kind: identity.kind,
			Type: operationType, ScopeKind: identity.scopeKind, ScopeID: identity.scopeID,
			Status: audit.CorrelationOperationActive, SessionID: req.SessionID, Limit: 2,
		})
		if err != nil {
			return audit.CorrelationPendingOperation{}, nil, 0, err
		}
		for _, operation := range operations {
			key := operation.Namespace + "\x00" + string(operation.Kind) + "\x00" +
				operation.OperationID + "\x00" + string(operation.Type) + "\x00" +
				string(operation.ScopeKind) + "\x00" + operation.ScopeID
			if seen[key] {
				continue
			}
			seen[key] = true
			candidates = append(candidates, operation)
			if len(candidates) > 1 {
				return audit.CorrelationPendingOperation{}, nil, len(candidates), nil
			}
		}
	}
	if len(candidates) != 1 {
		return audit.CorrelationPendingOperation{}, nil, len(candidates), nil
	}
	operation := candidates[0]
	locator := &audit.CorrelationPendingLocator{
		ConnectorInstanceID: operation.ConnectorInstanceID,
		Namespace:           operation.Namespace, Kind: operation.Kind, OperationID: operation.OperationID,
		Type: operation.Type, ScopeKind: operation.ScopeKind, ScopeID: operation.ScopeID,
	}
	return operation, locator, 1, nil
}

func nativeOTLPActiveCursorV8(
	ctx context.Context,
	repo *audit.CorrelationRepository,
	instance audit.ConnectorInstanceID,
	sessionID string,
	agentID string,
) (audit.CorrelationCursor, error) {
	if agentID != "" {
		return repo.GetCursor(ctx, instance, sessionID, agentID)
	}
	return repo.FindActiveCursor(ctx, instance, sessionID)
}

// validateNativeOTLPValueConsistency rejects only contradictory aliases of
// the same typed identity. A profile may preserve multiple differently typed
// IDs under one broad target without making those IDs equal.
func validateNativeOTLPValueConsistency(values []connector.CorrelationValue) error {
	return connector.ValidateCorrelationValues(values)
}

func nativeOTLPSignalDeclared(spec connector.NativeTelemetrySpec, signal otelIngestSignal) bool {
	want := connector.NativeTelemetrySignal(signal)
	for _, declared := range spec.Signals {
		if declared == want {
			return true
		}
	}
	return false
}

// nativeOTLPDeclaredAttributes materializes only literal dotted keys declared
// in NativeOTLPBindings. Duplicate, structured, or type-conflicting identity
// attributes fail closed instead of becoming first/last-value wins.
func nativeOTLPDeclaredAttributes(leaf otlpDecodedLeaf, spec connector.CorrelationSpec) (map[string]interface{}, error) {
	attributes := make(map[string]interface{})
	seen := make(map[string]bool)
	index := leaf.attributes()
	for _, binding := range spec.NativeOTLPBindings {
		for _, key := range binding.Paths {
			if seen[key] {
				continue
			}
			seen[key] = true
			value, state := index.lookup(key)
			switch state {
			case otlpTypedAttributeAbsent:
				continue
			case otlpTypedAttributeUnique:
			default:
				return nil, fmt.Errorf("native identity attribute %q is not unique", key)
			}
			switch typed := value.GetValue().(type) {
			case *commonpb.AnyValue_StringValue:
				attributes[key] = typed.StringValue
			case *commonpb.AnyValue_IntValue:
				attributes[key] = typed.IntValue
			default:
				return nil, fmt.Errorf("native identity attribute %q has a non-scalar identifier type", key)
			}
		}
	}
	return attributes, nil
}

func nativeOTLPReportedSemantic(values []connector.CorrelationValue) (audit.SemanticEventID, error) {
	var semantic audit.SemanticEventID
	for _, value := range values {
		if value.Target != connector.CorrelationTargetSemanticEvent {
			continue
		}
		if !validCorrelationUUIDv7(value.Value) {
			return "", errors.New("reported semantic event id is not UUIDv7")
		}
		if semantic != "" && semantic != audit.SemanticEventID(value.Value) {
			return "", errors.New("reported semantic event ids conflict")
		}
		semantic = audit.SemanticEventID(value.Value)
	}
	return semantic, nil
}

func nativeOTLPReportedLogical(leaf otlpDecodedLeaf, semanticReported bool) (audit.LogicalEventID, error) {
	value, state := leaf.attributes().stringValue("defenseclaw.logical_event.id")
	switch state {
	case otlpTypedAttributeAbsent:
		return "", nil
	case otlpTypedAttributeUnique:
	default:
		return "", errors.New("reported logical event id is not a unique string")
	}
	if !semanticReported {
		return "", errors.New("reported logical event id requires a reported semantic event id")
	}
	if !validCorrelationUUIDv7(value) {
		return "", errors.New("reported logical event id is not UUIDv7")
	}
	return audit.LogicalEventID(value), nil
}

func nativeOTLPReceipt(
	spec connector.CorrelationSpec,
	instance audit.ConnectorInstanceID,
	signal otelIngestSignal,
	sourceDigest, traceID, spanID, fingerprint string,
	now time.Time,
) *audit.CorrelationReceiptClaim {
	key := ""
	if sourceDigest != "" && spec.AllowsReceiptTarget(connector.CorrelationTargetSourceEvent) {
		key = correlationReceiptSourceKey(instance, audit.CorrelationRailNativeOTLP, string(signal), sourceDigest)
	} else if signal == otelSignalTraces && traceID != "" && spanID != "" {
		key = gatewaylog.ComputePayloadHMAC(struct {
			Domain   string `json:"domain"`
			Instance string `json:"connector_instance_id"`
			TraceID  string `json:"trace_id"`
			SpanID   string `json:"span_id"`
		}{"native-otlp-span-receipt-v1", string(instance), traceID, spanID})
	}
	if key == "" {
		return nil
	}
	return &audit.CorrelationReceiptClaim{
		SourceKeyDigest: key, FingerprintSHA256: fingerprint,
		ReceivedAt: now, ExpiresAt: now.Add(correlationReceiptTTL),
	}
}

func nativeOTLPCorrelationEventName(match observability.InboundMatch) string {
	eventName := "native_otlp"
	for _, role := range []observability.InboundTargetRole{
		observability.InboundTargetImport, observability.InboundTargetDerive,
	} {
		for _, target := range match.Targets() {
			if target.Role() == role && target.EventName() != "" {
				eventName = string(target.EventName())
				break
			}
		}
		if eventName != "native_otlp" {
			break
		}
	}
	switch eventName {
	case "model.request":
		return string(connector.CorrelationLifecycleModelStart)
	case "model.response", "span.model.chat":
		return string(connector.CorrelationLifecycleModelEnd)
	case "tool.invocation.requested", "tool.invocation.started":
		return string(connector.CorrelationLifecycleToolStart)
	case "tool.invocation.blocked", "tool.invocation.completed", "tool.invocation.failed", "span.tool.execute":
		return string(connector.CorrelationLifecycleToolEnd)
	default:
		return eventName
	}
}

func nativeOTLPMirrorCompatibility(spec connector.CorrelationSpec, signal otelIngestSignal, eventName string) *audit.CorrelationMirrorCompatibility {
	// A metric point is its own numeric observation, not automatically the
	// same semantic occurrence as a hook simply because both belong to one
	// response/tool. Exact source-event receipts still work for metrics.
	if signal == otelSignalMetrics {
		return nil
	}
	switch connector.CorrelationLifecycle(eventName) {
	case connector.CorrelationLifecycleModelStart, connector.CorrelationLifecycleModelEnd,
		connector.CorrelationLifecycleToolStart, connector.CorrelationLifecycleToolEnd:
	default:
		return nil
	}
	return mirrorCompatibilityForRail(spec, audit.CorrelationRailNativeOTLP,
		connector.CorrelationLifecycle(eventName))
}

func contextWithNativeOTLPCorrelation(
	ctx context.Context,
	connectorName string,
	instance audit.ConnectorInstance,
	semantic audit.SemanticEventID,
	logical audit.LogicalEventID,
	values []connector.CorrelationValue,
	traceID string,
) context.Context {
	envelope := audit.EnvelopeFromContext(ctx)
	envelope.SemanticEventID = string(semantic)
	envelope.LogicalEventID = string(logical)
	envelope.ConnectorInstanceID = string(instance.ConnectorInstanceID)
	envelope.Connector = connectorName
	set := func(target connector.CorrelationTarget, destination *string) {
		for _, value := range values {
			if value.Target == target && value.Value != "" {
				// Connector-specific bindings are declared after generic fallbacks;
				// keep walking so context and the canonical import projection use
				// the same provider-preferred value.
				*destination = value.Value
			}
		}
	}
	set(connector.CorrelationTargetSession, &envelope.SessionID)
	set(connector.CorrelationTargetTurn, &envelope.TurnID)
	set(connector.CorrelationTargetAgent, &envelope.AgentID)
	set(connector.CorrelationTargetTool, &envelope.ToolID)
	if traceID != "" {
		envelope.TraceID = traceID
	}
	ctx = audit.ContextWithEnvelope(ctx, envelope)
	return context.WithValue(ctx, nativeOTLPCorrelationValuesContextKey{}, nativeOTLPCorrelationValuesContext{
		connector: connectorName,
		values:    append([]connector.CorrelationValue(nil), values...),
	})
}

func nativeOTLPCorrelationValuesFromContext(
	ctx context.Context,
	connectorName string,
) ([]connector.CorrelationValue, bool) {
	if ctx == nil {
		return nil, false
	}
	stored, ok := ctx.Value(nativeOTLPCorrelationValuesContextKey{}).(nativeOTLPCorrelationValuesContext)
	if !ok || stored.connector != connectorName {
		return nil, false
	}
	return append([]connector.CorrelationValue(nil), stored.values...), true
}

func nativeOTLPTraceSpan(leaf otlpDecodedLeaf) (string, string) {
	var traceBytes, spanBytes []byte
	switch {
	case leaf.span != nil:
		traceBytes, spanBytes = leaf.span.GetTraceId(), leaf.span.GetSpanId()
	case leaf.logRecord != nil:
		traceBytes, spanBytes = leaf.logRecord.GetTraceId(), leaf.logRecord.GetSpanId()
	}
	traceID, spanID := hex.EncodeToString(traceBytes), hex.EncodeToString(spanBytes)
	if len(traceID) != 32 {
		traceID = ""
	}
	if len(spanID) != 16 {
		spanID = ""
	}
	return traceID, spanID
}

func nativeOTLPSourceTime(leaf otlpDecodedLeaf) time.Time {
	var nanos uint64
	switch {
	case leaf.logRecord != nil:
		nanos = leaf.logRecord.GetTimeUnixNano()
		if nanos == 0 {
			nanos = leaf.logRecord.GetObservedTimeUnixNano()
		}
	case leaf.span != nil:
		nanos = leaf.span.GetEndTimeUnixNano()
	case leaf.numberPoint != nil:
		nanos = leaf.numberPoint.GetTimeUnixNano()
	case leaf.histogramPoint != nil:
		nanos = leaf.histogramPoint.GetTimeUnixNano()
	case leaf.exponentialHistogram != nil:
		nanos = leaf.exponentialHistogram.GetTimeUnixNano()
	case leaf.summaryPoint != nil:
		nanos = leaf.summaryPoint.GetTimeUnixNano()
	}
	if nanos == 0 || nanos > uint64(^uint64(0)>>1) {
		return time.Time{}
	}
	return time.Unix(0, int64(nanos)).UTC()
}

func nativeOTLPLeafFingerprint(leaf otlpDecodedLeaf) (string, error) {
	hasher := sha256.New()
	writeCorrelationFingerprintFrame(hasher, "domain", []byte("native-otlp-leaf-v1"))
	writeCorrelationFingerprintFrame(hasher, "signal", []byte(leaf.signal))
	writeCorrelationFingerprintFrame(hasher, "resource-schema", []byte(leaf.resource.schemaURL))
	writeCorrelationFingerprintFrame(hasher, "resource-dropped", []byte(strconv.FormatUint(uint64(leaf.resource.droppedAttributesCount), 10)))
	if err := writeCorrelationAttributeIndex(hasher, "resource", leaf.resource.attributes); err != nil {
		return "", err
	}
	writeCorrelationFingerprintFrame(hasher, "scope-name", []byte(leaf.scope.name))
	writeCorrelationFingerprintFrame(hasher, "scope-version", []byte(leaf.scope.version))
	writeCorrelationFingerprintFrame(hasher, "scope-schema", []byte(leaf.scope.schemaURL))
	writeCorrelationFingerprintFrame(hasher, "scope-dropped", []byte(strconv.FormatUint(uint64(leaf.scope.droppedAttributesCount), 10)))
	if err := writeCorrelationAttributeIndex(hasher, "scope", leaf.scope.attributes); err != nil {
		return "", err
	}
	message, err := nativeOTLPLeafMessage(leaf)
	if err != nil {
		return "", err
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return "", fmt.Errorf("marshal native OTLP leaf fingerprint: %w", err)
	}
	writeCorrelationFingerprintFrame(hasher, "leaf", wire)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func nativeOTLPLeafMessage(leaf otlpDecodedLeaf) (proto.Message, error) {
	switch {
	case leaf.logRecord != nil && leaf.signal == otelSignalLogs:
		return leaf.logRecord, nil
	case leaf.span != nil && leaf.signal == otelSignalTraces:
		return leaf.span, nil
	case leaf.metric != nil && leaf.signal == otelSignalMetrics:
		metric := proto.Clone(leaf.metric).(*metricspb.Metric)
		switch leaf.metricShape {
		case otlpTypedMetricGauge:
			metric.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{proto.Clone(leaf.numberPoint).(*metricspb.NumberDataPoint)}}}
		case otlpTypedMetricSum:
			source := leaf.metric.GetSum()
			metric.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
				DataPoints:             []*metricspb.NumberDataPoint{proto.Clone(leaf.numberPoint).(*metricspb.NumberDataPoint)},
				AggregationTemporality: source.GetAggregationTemporality(), IsMonotonic: source.GetIsMonotonic(),
			}}
		case otlpTypedMetricHistogram:
			source := leaf.metric.GetHistogram()
			metric.Data = &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
				DataPoints:             []*metricspb.HistogramDataPoint{proto.Clone(leaf.histogramPoint).(*metricspb.HistogramDataPoint)},
				AggregationTemporality: source.GetAggregationTemporality(),
			}}
		case otlpTypedMetricExponentialHistogram:
			source := leaf.metric.GetExponentialHistogram()
			metric.Data = &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{
				DataPoints:             []*metricspb.ExponentialHistogramDataPoint{proto.Clone(leaf.exponentialHistogram).(*metricspb.ExponentialHistogramDataPoint)},
				AggregationTemporality: source.GetAggregationTemporality(),
			}}
		case otlpTypedMetricSummary:
			metric.Data = &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{proto.Clone(leaf.summaryPoint).(*metricspb.SummaryDataPoint)}}}
		default:
			return nil, errors.New("native OTLP metric leaf shape is invalid")
		}
		return metric, nil
	default:
		return nil, errors.New("native OTLP leaf is invalid")
	}
}

func writeCorrelationAttributeIndex(hasher hash.Hash, prefix string, index otlpTypedAttributeIndex) error {
	writeCorrelationFingerprintFrame(hasher, prefix+"-invalid", []byte(strconv.Itoa(index.invalidCount())))
	for _, key := range index.keys() {
		value, state := index.lookup(key)
		writeCorrelationFingerprintFrame(hasher, prefix+"-key", []byte(key))
		writeCorrelationFingerprintFrame(hasher, prefix+"-state", []byte(strconv.Itoa(int(state))))
		if state != otlpTypedAttributeUnique {
			continue
		}
		wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
		if err != nil {
			return fmt.Errorf("marshal %s OTLP attribute fingerprint: %w", prefix, err)
		}
		writeCorrelationFingerprintFrame(hasher, prefix+"-value", wire)
	}
	return nil
}

func writeCorrelationFingerprintFrame(hasher hash.Hash, label string, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(label)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write([]byte(label))
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hasher.Write(size[:])
	_, _ = hasher.Write(value)
}
