// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// Root-scope tool-call chains (issue #1391).
//
// With guardrail.chains.root_scope on, a trusted connector's call on the
// agent-gateway route whose root_session_id was honoured (issue #1392: a
// listed service account on the hook socket, the person pinned to the root
// id) is evaluated in a second chain window next to its session window. The
// root window holds the calls of every session and sub-agent the connector
// ran for that person under that root id, so a download in one sub-agent
// followed by running the file in the parent completes the chain. Root ids
// from anyone else are ignored and audited by the route (root_session_ignored)
// and never reach this code. The root window has the session window's bounds
// (eight events, the same time horizon); session ends and turn boundaries
// reset only the session window. A chain the root window completes gives the
// verdict, rule ids and receipts it would give in a session; the local audit
// names it (chain_scope, root_chain_ids).

// agentGatewayRootChain is the route's note of the root scope of one call,
// filled in while the call is evaluated and read when its audit row is
// written.
type agentGatewayRootChain struct {
	evaluated bool
	chainIDs  []string
}

// toolChainRootScopeEnabled reports guardrail.chains.root_scope on a
// configuration whose trusted connectors are honoured (signed bundle). It is
// never on under the Secure Client integration (refused by validation).
func (a *APIServer) toolChainRootScopeEnabled(ctx context.Context) bool {
	if a == nil {
		return false
	}
	cfg := a.liveBaseConfig(ctx)
	return cfg != nil && !cfg.SecureClientIntegration() && cfg.Guardrail.Chains.RootScope &&
		trustedConnectorStateNow().honoured
}

// toolChainRootRepository is the root-scope chain repository of req, or nil:
// the setting is off, the call is not a trusted connector's with an honoured
// root_session_id, or the root state is unavailable (the session verdict is
// then unchanged).
func (a *APIServer) toolChainRootRepository(ctx context.Context, req agentHookRequest) *audit.ToolChainRepository {
	if a == nil || a.store == nil || req.ConnectorInstanceID == "" ||
		req.ConnectorName != connector.AgentGatewayConnectorName || !a.toolChainRootScopeEnabled(ctx) {
		return nil
	}
	note, ok := ctx.Value(agentGatewayAuditKey{}).(agentGatewayAudit)
	if !ok || note.rootSessionHonoured == "" || note.rootChain == nil {
		return nil
	}
	af, ok := actingForFromContext(ctx)
	if !ok || af.ConnectorAccountID == "" {
		return nil
	}
	digest, err := audit.ToolChainRootScopeDigest(audit.ConnectorInstanceID(req.ConnectorInstanceID),
		af.ConnectorAccountID, af.Person.UserID, note.rootSessionHonoured)
	if err != nil {
		return nil
	}
	repository, err := a.store.ToolChainRootRepository(ctx, digest)
	if err != nil {
		return nil
	}
	note.rootChain.evaluated = true
	return repository
}

// rootToolChainAdded is what the root window's result adds to the session
// window's (toolChainRootOnlyResult), or nothing. A committed root denial is
// recorded in panicState at once, as the session lane does: a later panic
// must still answer the block.
func rootToolChainAdded(
	profile connector.HookProfile,
	req agentHookRequest,
	resp agentHookResponse,
	repository *audit.ToolChainRepository,
	root, session audit.ToolChainObserveResult,
	panicState *toolChainHookPanicState,
) audit.ToolChainObserveResult {
	if repository == nil {
		return audit.ToolChainObserveResult{}
	}
	added, err := toolChainRootOnlyResult(root, session)
	if err != nil {
		return audit.ToolChainObserveResult{}
	}
	if added.DeniedMask != 0 && panicState != nil {
		panicState.committedBlock = committedAgentHookChainPanicBlock(profile, req, resp, added)
		if root.Status == audit.ToolChainObserveFresh && len(root.ReceiptIDs) != 0 {
			panicState.finalization.rootRepository = repository
			panicState.finalization.rootReceiptIDs = append([]string(nil), root.ReceiptIDs...)
		}
		panicState.denyCommitted = true
	}
	return added
}

// applyToolChainRootResult merges what the root window adds into resp after
// the session window's result: a chain the session window did not complete,
// or completed with less (not enforcement safe, not denied). The root
// receipts are finalized with the call.
func (a *APIServer) applyToolChainRootResult(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	resp agentHookResponse,
	finalization *toolChainHookFinalization,
	repository *audit.ToolChainRepository,
	root, added audit.ToolChainObserveResult,
	denyEligible bool,
	latency time.Duration,
) agentHookResponse {
	if root.Status == audit.ToolChainObserveFresh && len(root.ReceiptIDs) != 0 {
		finalization.rootRepository = repository
		finalization.rootReceiptIDs = append([]string(nil), root.ReceiptIDs...)
	}
	if len(added.DetectedChainIDs) == 0 {
		return resp
	}
	if note, ok := ctx.Value(agentGatewayAuditKey{}).(agentGatewayAudit); ok && note.rootChain != nil {
		note.rootChain.chainIDs = appendUniqueStrings(note.rootChain.chainIDs, added.DetectedChainIDs...)
	}
	chainFindings := toolChainRuleFindings(added)
	intent := toolChainHookIntent(
		guardrailActionForConnector(a.decisionConfig(ctx), req.ConnectorName, HighestSeverity(chainFindings), true),
		denyEligible,
		added,
	)
	resp = mergeAgentHookFindings(profile, req, resp, chainFindings, intent)
	if added.Status == audit.ToolChainObserveFresh {
		eval := a.emitHookRuleFindings(
			ctx,
			req.ConnectorName,
			req.HookEventName,
			&ToolInspectVerdict{
				Action:           resp.Action,
				Severity:         HighestSeverity(chainFindings),
				Findings:         FindingStrings(chainFindings),
				DetailedFindings: chainFindings,
			},
			"tool_call_chain",
			latency,
		)
		resp.RuleIDs = mergeBoundedRuleIDs(8, added.DetectedChainIDs, eval.RuleIDs, resp.RuleIDs)
		if added.DeniedMask != 0 && eval.EvaluationID != "" {
			resp.EvaluationID = eval.EvaluationID
		} else if resp.EvaluationID == "" {
			resp.EvaluationID = eval.EvaluationID
		}
		if finalization.evaluationID == "" {
			finalization.evaluationID = eval.EvaluationID
		}
	} else {
		// An exact transport replay reproduces the durable decision without
		// duplicate finding telemetry.
		resp.RuleIDs = mergeBoundedRuleIDs(8, added.DetectedChainIDs, resp.RuleIDs)
	}
	if added.DeniedMask != 0 {
		resp = committedAgentHookChainBlock(profile, req, resp)
	}
	return resp
}

// toolChainRootOnlyResult keeps the chains of root the session result does
// not already give at the same strength.
func toolChainRootOnlyResult(root, session audit.ToolChainObserveResult) (audit.ToolChainObserveResult, error) {
	keep := (root.DetectedMask &^ session.DetectedMask) |
		(root.EnforcementSafeMask &^ session.EnforcementSafeMask) |
		(root.DeniedMask &^ session.DeniedMask)
	out := root
	out.DetectedMask &= keep
	out.EnforcementSafeMask &= keep
	out.DeniedMask &= keep
	if out.DeniedMask == 0 {
		out.StableActionID = ""
	}
	var err error
	if out.DetectedChainIDs, err = guardrail.ToolChainIDs(out.DetectedMask); err != nil {
		return audit.ToolChainObserveResult{}, err
	}
	if out.EnforcementSafeChainIDs, err = guardrail.ToolChainIDs(out.EnforcementSafeMask); err != nil {
		return audit.ToolChainObserveResult{}, err
	}
	if out.DeniedChainIDs, err = guardrail.ToolChainIDs(out.DeniedMask); err != nil {
		return audit.ToolChainObserveResult{}, err
	}
	return out, nil
}
