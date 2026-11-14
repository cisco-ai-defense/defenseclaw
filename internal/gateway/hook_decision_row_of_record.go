// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// hookDecisionIsRowOfRecord reports a hook call whose hook_decision record
// is its only local row, its row of record: the connector-hook row is
// exported unchanged but not written locally (#1384, bar H1, DESIGN 11).
// That is a benign allow of a per-user gateway: action and raw action allow,
// not would-block, not enforced, no panic, no bounded-prefix review, a live
// call (not a journal recovery, a pending occurrence or a sandbox receipt),
// not a sandbox relay, not Cowork, not managed or Secure Client, with a
// correlation event the local readers pair the rows by, inside an open call
// write batch. Every other call keeps the connector-hook row of 1.0.9, which
// the alert queries, the GAP-1060 replay check, the Cowork status and a
// 1.0.9 binary after a rollback read.
func (a *APIServer) hookDecisionIsRowOfRecord(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
	panicked bool,
) bool {
	if a == nil || a.store == nil || a.logger == nil || panicked || env.Result != "ok" {
		return false
	}
	if req.pendingRecovery || req.pendingOccurrenceID != "" || req.sandboxReceiptAcknowledgment ||
		req.CorrelationUnavailable || strings.TrimSpace(req.SemanticEventID) == "" {
		return false
	}
	if resp.Action != "allow" || !strings.EqualFold(resp.RawAction, "allow") || resp.WouldBlock ||
		env.Enforced || env.Action != "allow" || env.Extra["bounded_prefix_review"] == "true" {
		return false
	}
	cfg := a.decisionConfig(ctx)
	if cfg == nil || managed.IsManagedEnterprise(cfg.DeploymentMode) || cfg.SecureClientIntegration() ||
		a.managedAIDOnly() || a.journalsHookDeliveries() || sandboxHookForConnector(ctx, req.ConnectorName) {
		return false
	}
	if _, cowork := coworkFromContext(ctx); cowork {
		// coworkaudit.LastEvents reads the connector-hook rows of Cowork.
		return false
	}
	return audit.CallWritesOpen(ctx, a.store)
}

// errHookAuditSectionPanicked abandons the row of record of a call whose
// audit section panicked before its flush.
var errHookAuditSectionPanicked = errors.New("gateway: the hook audit section panicked")

// errHookDecisionNotRowOfRecord abandons whatever a decision record that was
// not kept as the row of record may have queued.
var errHookDecisionNotRowOfRecord = errors.New("gateway: the hook decision record was not kept")

// writeHookDecisionRowOfRecord queues the hook_decision record of a call
// whose row of record it is (hookDecisionIsRowOfRecord) on the call's open
// batch, before the connector-hook record, with an outcome of its own:
// decisionOutcome holds exactly this write, so the verdict, the record's
// export and the connector-hook export all follow whether this one row
// committed (one write in one savepoint, so it never commits in part). The
// exports wait for the batch to commit and are dropped when it did not
// (observability.WithExportAfterCallCommit): the call then answers with its
// fail-mode verdict and exports a new decision record carrying it.
// connectorCtx writes the connector-hook record export only. ok is false
// when the record was not queued (it could not be built, its collection is
// off, or the runtime failed it at once): the connector-hook row of 1.0.9 is
// written then.
func (a *APIServer) writeHookDecisionRowOfRecord(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
) (connectorCtx, decisionCtx context.Context, decisionOutcome *audit.CallWriteOutcome, ok bool) {
	meta, connectorName, built := a.hookDecisionMeta(ctx, req)
	if !built {
		return ctx, nil, nil, false
	}
	// The row of record is the decision's only local hook row: it is listed
	// in audit_hook_lone with its write (rel-1-0-10:GAP-0316).
	attemptCtx, attemptOutcome := audit.WithCallWriteOutcome(audit.WithLoneHookDecision(observability.WithExportAfterCallCommit(ctx)))
	handedBack := false
	defer func() {
		if handedBack {
			return
		}
		if recovered := recover(); recovered != nil {
			// A panic after the record was queued and before the audit
			// section holds it: drop it here, since the section's own guard
			// does not know of it yet (S8 R4 review P1).
			audit.AbandonCallWrites(attemptCtx, errHookAuditSectionPanicked)
			panic(recovered)
		}
	}()
	if a.emitHookDecisionLogV8(attemptCtx, req, resp, env, false, meta, connectorName) != hookDecisionLogPersisted {
		audit.AbandonCallWrites(attemptCtx, errHookDecisionNotRowOfRecord)
		handedBack = true
		return ctx, nil, nil, false
	}
	hookStageForTest(ctx, "finalize_audit_row_queued")
	handedBack = true
	return observability.WithExportOnlyInCall(attemptCtx), attemptCtx, attemptOutcome, true
}

// hookLogsCollectedRuntime reports whether the active plan collects the
// logs of a bucket.
type hookLogsCollectedRuntime interface {
	LogsCollected(observability.Bucket) bool
}

// hookDecisionRecordsKept reports whether the active plan keeps hook_decision
// records (the guardrail.evaluation logs). The records a hook call exports
// only (tool_start, tool.invocation.requested) are exported only when it
// does: their facts are then in the call's hook_decision row. With that
// collection off they stay local, as in 1.0.9 (S8 R4 review P3-5).
func (a *APIServer) hookDecisionRecordsKept() bool {
	runtime, ok := a.observabilityV8RuntimeEmitter().(hookLogsCollectedRuntime)
	return ok && runtime.LogsCollected(observability.BucketGuardrailEvaluation)
}

// recordHookDecisionMetricsOfCall records the hook decision metrics of a
// live call whose decision record was written as its row of record.
func (a *APIServer) recordHookDecisionMetricsOfCall(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
	panicked bool,
) {
	meta, connectorName, ok := a.hookDecisionMeta(ctx, req)
	if !ok {
		return
	}
	a.recordHookDecisionMetricsV8(ctx, req, resp, env, panicked, meta, connectorName)
}
