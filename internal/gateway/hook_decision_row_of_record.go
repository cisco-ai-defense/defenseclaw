// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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

// writeHookDecisionRowOfRecord queues the hook_decision record of a call
// whose row of record it is (hookDecisionIsRowOfRecord) on the call's open
// batch, before the connector-hook record. Its export waits for the batch to
// commit and is dropped when it did not: the call then answers with its
// fail-mode verdict and exports a new decision record carrying it. It
// returns the context the connector-hook record is written with: export only
// when the decision record was queued, else unchanged (the connector-hook
// row of 1.0.9 is written: the record could not be built, its collection is
// off, or the runtime failed it at once).
func (a *APIServer) writeHookDecisionRowOfRecord(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	env HookAuditEnvelope,
) (context.Context, bool) {
	meta, connectorName, ok := a.hookDecisionMeta(ctx, req)
	if !ok {
		return ctx, false
	}
	decision := a.emitHookDecisionLogV8(observability.WithExportAfterCallCommit(ctx), req, resp, env, false, meta, connectorName)
	if decision != hookDecisionLogPersisted {
		return ctx, false
	}
	return observability.WithExportOnlyInCall(ctx), true
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
