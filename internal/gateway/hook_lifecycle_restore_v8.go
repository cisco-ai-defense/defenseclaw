// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type hookLifecycleHistoryRuntime interface {
	LatestLifecycleProjection(
		context.Context,
		audit.LifecycleProjectionQuery,
	) (audit.LifecycleProjection, bool, error)
}

// restoreHookSessionLifecycle lazily recovers one exact underdetermined hook
// agent after process-local correlation state is lost. The active runtime owns
// integrity verification; this layer consumes only the returned identifiers
// and cursor, never projected bytes or request-local trace handles.
func (a *APIServer) restoreHookSessionLifecycle(ctx context.Context, meta llmEventMeta) llmEventMeta {
	if a == nil || ctx == nil || !hookLifecycleRestoreEligible(meta) {
		return meta
	}
	snapshot, exists := a.hookSessionStateSnapshot(meta.Source, meta.SessionID, meta.AgentID)
	if exists && hookLifecycleRetainedLineageVerified(snapshot.meta) &&
		meta.LineageProvenance != "reported" && !meta.ParentAgentReported {
		return restoreRetainedHookLineage(meta, snapshot.meta)
	}
	if exists && !hookLifecycleUnresolvedSelfRoot(snapshot.meta) {
		return meta
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleHistoryRuntime)
	if !ok || runtime == nil {
		return meta
	}
	projection, found, err := runtime.LatestLifecycleProjection(ctx, audit.LifecycleProjectionQuery{
		Connector: meta.Source, SessionID: meta.SessionID, AgentID: meta.AgentID,
	})
	if err != nil || !found {
		return meta
	}
	if !hookLifecycleProjectionCompatible(meta, projection) {
		return meta
	}
	return a.installRestoredHookSessionLifecycle(meta, projection)
}

// hookLifecycleRetainedLineageVerified admits only topology that was either
// reported completely by the connector or correlated to a concrete parent by
// the live spawn/session resolver. A depth-one fallback inferred solely from a
// shared root session is intentionally not authoritative: real Codex stop
// hooks have exactly that shape, and ambiguous children must remain unresolved.
func hookLifecycleRetainedLineageVerified(meta llmEventMeta) bool {
	return strings.TrimSpace(meta.AgentID) != "" && strings.TrimSpace(meta.RootAgentID) != "" &&
		meta.RootAgentID != meta.AgentID && strings.TrimSpace(meta.ParentAgentID) != "" &&
		meta.ParentAgentID != meta.AgentID && meta.AgentDepth > 0 &&
		(meta.LineageProvenance == "reported" || meta.ParentLineageResolved)
}

// restoreRetainedHookLineage repairs only immutable topology. The current
// delivery continues to own its execution/event/state/cursor/trace and content
// correlation; mergeHookSessionLifecycle applies the ordinary active-execution
// rules later in the pipeline.
func restoreRetainedHookLineage(meta, retained llmEventMeta) llmEventMeta {
	meta.RootAgentID = retained.RootAgentID
	meta.ParentAgentID = retained.ParentAgentID
	meta.RootSessionID = retained.RootSessionID
	meta.ParentSessionID = retained.ParentSessionID
	meta.AgentDepth = retained.AgentDepth
	meta.LineageProvenance = retained.LineageProvenance
	meta.ParentLineageResolved = retained.ParentLineageResolved
	return meta
}

func hookLifecycleUnresolvedSelfRoot(meta llmEventMeta) bool {
	return strings.TrimSpace(meta.AgentID) != "" && meta.RootAgentID == meta.AgentID &&
		strings.TrimSpace(meta.ParentAgentID) == "" && meta.AgentDepth == 0 &&
		meta.LineageProvenance != "reported" && !meta.ParentAgentReported && !meta.ParentLineageResolved
}

func hookLifecycleProjectionRepairsSelfRoot(
	meta llmEventMeta,
	projection audit.LifecycleProjection,
) bool {
	return hookLifecycleUnresolvedSelfRoot(meta) && strings.TrimSpace(projection.RootAgentID) != "" &&
		projection.RootAgentID != meta.AgentID && strings.TrimSpace(projection.ParentAgentID) != "" &&
		projection.Depth > 0
}

func hookLifecycleRestoreEligible(meta llmEventMeta) bool {
	if strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.SessionID) == "" ||
		strings.TrimSpace(meta.AgentID) == "" {
		return false
	}
	if meta.LifecycleEvent == "session_start" || meta.LifecycleEvent == "subagent_start" {
		return false
	}
	// Every non-start hook is underdetermined with respect to the process-local
	// execution cursor. Complete reported topology is retained only when it
	// agrees with verified history; explicit starts above always rotate instead.
	return true
}

func hookLifecycleProjectionCompatible(meta llmEventMeta, projection audit.LifecycleProjection) bool {
	if meta.LineageProvenance == "reported" || meta.ParentLineageResolved {
		return meta.RootAgentID == projection.RootAgentID &&
			meta.ParentAgentID == projection.ParentAgentID &&
			meta.AgentDepth == projection.Depth
	}
	if meta.ParentAgentReported && meta.ParentAgentID != projection.ParentAgentID {
		return false
	}
	if meta.ParentAgentReported && meta.ParentSessionID != "" &&
		meta.ParentSessionID != projection.ParentSessionID {
		return false
	}
	return true
}

func lifecycleProjectionTerminal(projection audit.LifecycleProjection) bool {
	return projection.Event == "session_end" || projection.Event == "subagent_stop"
}

func restoreLifecycleImmutable(meta llmEventMeta, projection audit.LifecycleProjection) llmEventMeta {
	meta.RootAgentID = projection.RootAgentID
	meta.ParentAgentID = projection.ParentAgentID
	meta.RootSessionID = projection.RootSessionID
	meta.ParentSessionID = projection.ParentSessionID
	meta.LifecycleID = projection.LifecycleID
	meta.AgentDepth = projection.Depth
	meta.LineageProvenance = projection.LineageProvenance
	return meta
}

// installRestoredHookSessionLifecycle double-checks the memory miss and
// installs identity plus the active cursor under one lock. Concurrent first
// hooks therefore cannot both reset the same recovered sequence.
func (a *APIServer) installRestoredHookSessionLifecycle(
	meta llmEventMeta,
	projection audit.LifecycleProjection,
) llmEventMeta {
	key := hookSessionStateKey(meta)
	if a == nil || key == "" {
		return meta
	}
	restored := restoreLifecycleImmutable(meta, projection)
	terminal := lifecycleProjectionTerminal(projection)
	if !terminal {
		restored.ExecutionID = projection.ExecutionID
	} else {
		restored.ExecutionID = newHookExecutionID(restored)
	}

	a.llmPromptMu.Lock()
	if existing, exists := a.hookSessionStates[key]; exists {
		if !hookLifecycleProjectionRepairsSelfRoot(existing.meta, projection) {
			a.llmPromptMu.Unlock()
			return a.mergeHookSessionLifecycle(meta)
		}
		// Preserve the live execution/cursor and request-local trace anchor;
		// signed history repairs only the immutable topology that an earlier
		// post-restart hook could not report.
		repairedSnapshot := restoreLifecycleImmutable(existing.meta, projection)
		a.hookSessionStates[key] = hookSessionState{
			meta: repairedSnapshot, traceEventID: existing.traceEventID,
		}
		repairedIncoming := restoreLifecycleImmutable(meta, projection)
		repairedIncoming.ExecutionID = repairedSnapshot.ExecutionID
		a.llmPromptMu.Unlock()
		return repairedIncoming
	}
	if a.hookSessionStates == nil {
		a.hookSessionStates = make(map[string]hookSessionState)
	}
	for len(a.hookSessionStates) >= hookPromptCacheMaxEntries && len(a.hookSessionStateOrder) > 0 {
		oldest := a.hookSessionStateOrder[0]
		a.hookSessionStateOrder = a.hookSessionStateOrder[1:]
		delete(a.hookSessionStates, oldest)
	}
	a.hookSessionStateOrder = append(a.hookSessionStateOrder, key)

	snapshotMeta := restored
	snapshotMeta.TraceEventID = ""
	if !terminal {
		snapshotMeta.LifecycleEvent = projection.Event
		snapshotMeta.LifecycleState = projection.State
		snapshotMeta.Phase = projection.Phase
		snapshotMeta.PreviousPhase = ""
		snapshotMeta.Sequence = projection.Sequence
		if a.hookPhaseStates == nil {
			a.hookPhaseStates = make(map[string]hookPhaseState)
		}
		cursorKey := hookPhaseStateKey(snapshotMeta)
		if cursorKey != "" {
			a.putHookPhaseCursorLocked(cursorKey, hookPhaseState{
				phase: projection.Phase, sequence: projection.Sequence,
			})
		}
	}
	a.hookSessionStates[key] = hookSessionState{meta: snapshotMeta}
	a.llmPromptMu.Unlock()
	return restored
}
