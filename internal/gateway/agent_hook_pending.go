// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/google/uuid"
)

// A receipt-capable managed hook can act on an answer before the gateway's
// audit write, which waits for the hook's receipt. So the occurrence is
// journaled in the audit store before the answer is offered
// (audit.Store.JournalHookDelivery): one power-loss durable row with only
// the facts needed to audit the call without its receipt, no raw hook body,
// tool arguments or response output. The handler deletes the row once its
// records are settled. A row whose gateway process died first is audited by
// the next process, as the decision the call has without a receipt.
const pendingHookRecoveredReason = "managed hook receipt recovered after gateway restart"

// hookDeliveryProcessID tells this process's journal rows from those of a
// gateway process that has stopped. Rows of this process belong to its live
// handlers, also those of a server a config reload replaced, so recovery
// never takes them over.
var hookDeliveryProcessID = uuid.NewString()

func (a *APIServer) deliveryProcessID() string {
	if a.hookDeliveryProcessID != "" {
		return a.hookDeliveryProcessID
	}
	return hookDeliveryProcessID
}

type pendingHookRequest struct {
	ConnectorName          string
	HookEventName          string
	SessionID              string
	TurnID                 string
	AgentID                string
	AgentName              string
	AgentType              string
	ToolInvocationID       string
	ToolName               string
	CorrelationUnavailable bool
}

func pendingRequest(req agentHookRequest) pendingHookRequest {
	return pendingHookRequest{
		ConnectorName: req.ConnectorName, HookEventName: req.HookEventName,
		SessionID: req.SessionID, TurnID: req.TurnID,
		AgentID: req.AgentID, AgentName: req.AgentName, AgentType: req.AgentType,
		ToolInvocationID: req.ToolInvocationID, ToolName: req.ToolName,
		CorrelationUnavailable: req.CorrelationUnavailable,
	}
}

func (p pendingHookRequest) request(id string, bodyBytes int64) agentHookRequest {
	return agentHookRequest{
		ConnectorName: p.ConnectorName, HookEventName: p.HookEventName,
		SessionID: p.SessionID, TurnID: p.TurnID,
		AgentID: p.AgentID, AgentName: p.AgentName, AgentType: p.AgentType,
		ToolInvocationID: p.ToolInvocationID, ToolName: p.ToolName,
		CorrelationUnavailable: p.CorrelationUnavailable,
		pendingOccurrenceID:    id, pendingBodyBytes: bodyBytes, pendingRecovery: true,
	}
}

type pendingHookResponse struct {
	Action           string
	RawAction        string
	Severity         string
	Mode             string
	WouldBlock       bool
	EvaluationID     string
	RuleIDs          []string
	RedactionEnabled *bool
}

func pendingResponse(resp agentHookResponse) pendingHookResponse {
	return pendingHookResponse{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Mode: resp.Mode, WouldBlock: resp.WouldBlock,
		EvaluationID: resp.EvaluationID, RuleIDs: resp.RuleIDs,
		RedactionEnabled: resp.RedactionEnabled,
	}
}

func (p pendingHookResponse) response() agentHookResponse {
	reason := pendingHookRecoveredReason
	if p.Action == hookActionUnconfirmed {
		reason = hookexec.ManagedGatewayNoAnswerReason
	}
	return agentHookResponse{
		Action: p.Action, RawAction: p.RawAction, Severity: p.Severity,
		Mode: p.Mode, Reason: reason, SourceReason: reason,
		WouldBlock: p.WouldBlock, EvaluationID: p.EvaluationID,
		RuleIDs: p.RuleIDs, RedactionEnabled: p.RedactionEnabled,
	}
}

// pendingHookOccurrence is a journaled hook call. Its connector audit row
// has its ID and its hook_decision ID+"-decision".
type pendingHookOccurrence struct {
	ID      string
	Request pendingHookRequest
	// Proposed is the evaluated answer the gateway offers. NoReceipt is the
	// decision the call has if no receipt arrives: a policy block under a
	// closed hook stays a block, anything else is unconfirmed.
	Proposed     pendingHookResponse
	NoReceipt    pendingHookResponse
	Envelope     audit.CorrelationEnvelope
	Identity     AgentIdentity
	RawEventIDs  []string
	Extra        map[string]string
	BodyBytes    int64
	ElapsedNanos int64
	Panicked     bool
	// SandboxReceipt binds a buffered relay acknowledgement to the original
	// sandbox and audit identity. It contains no hook body or tool arguments.
	SandboxReceipt *sandboxPendingHookReceipt
	// Final is set before a failed acknowledgement is answered closed, when
	// the journal remains writable. Recovery uses it to audit that block.
	Final *pendingHookResponse
	// Settled keeps an acknowledged row available for a bounded retry without
	// counting the same hook a second time when that window ends.
	Settled bool
}

type sandboxPendingHookReceipt struct {
	BindingID        string
	RegistrationID   string
	OfferedAt        time.Time
	Reason           string
	SourceReason     string
	EnvelopeIdentity pendingHookEnvelopeIdentity
	CallRef          string
}

// The receipt arrives on another HTTP request. Preserve the first request's
// lifecycle and policy fields for its final audit row.
type pendingHookEnvelopeIdentity struct {
	StepIdx            int
	RulePackDir        string
	AgentPhase         string
	AgentPreviousPhase string
	AgentSequence      int64
	AgentLifecycleID   string
	AgentExecutionID   string
	AgentOperationID   string
}

func pendingEnvelopeIdentity(env HookAuditEnvelope) pendingHookEnvelopeIdentity {
	return pendingHookEnvelopeIdentity{
		StepIdx: env.StepIdx, RulePackDir: env.RulePackDir,
		AgentPhase: env.AgentPhase, AgentPreviousPhase: env.AgentPreviousPhase,
		AgentSequence: env.AgentSequence, AgentLifecycleID: env.AgentLifecycleID,
		AgentExecutionID: env.AgentExecutionID, AgentOperationID: env.AgentOperationID,
	}
}

func (p pendingHookEnvelopeIdentity) stamp(env *HookAuditEnvelope, resp agentHookResponse) {
	env.StepIdx, env.RulePackDir = p.StepIdx, p.RulePackDir
	env.Enforced = resp.Action == "block"
	env.AgentPhase, env.AgentPreviousPhase = p.AgentPhase, p.AgentPreviousPhase
	env.AgentSequence, env.AgentLifecycleID = p.AgentSequence, p.AgentLifecycleID
	env.AgentExecutionID, env.AgentOperationID = p.AgentExecutionID, p.AgentOperationID
}

func (s sandboxPendingHookReceipt) response(proposed pendingHookResponse) agentHookResponse {
	resp := proposed.response()
	resp.Reason, resp.SourceReason = s.Reason, s.SourceReason
	return resp
}

// journalHookDelivery journals a receipt-capable call before its answer is
// offered, and gives req the occurrence IDs its records carry. On an error
// the answer must not be offered. The IDs are set even then: if the row
// landed anyway, recovery completes the records the caller writes instead
// of auditing the call a second time.
func (a *APIServer) journalHookDelivery(
	ctx context.Context, req *agentHookRequest, proposed agentHookResponse,
	rawEventIDs []string, bodyBytes int64, elapsed time.Duration,
	panicked bool, extra map[string]string, sandboxReceipt ...bool,
) (*pendingHookOccurrence, error) {
	p := &pendingHookOccurrence{
		ID: uuid.NewString(), Request: pendingRequest(*req),
		Proposed:    pendingResponse(proposed),
		NoReceipt:   pendingResponse(a.deliveredHookDecision(req.ConnectorName, proposed, "")),
		Envelope:    audit.EnvelopeFromContext(ctx),
		Identity:    AgentIdentityFromContext(ctx),
		RawEventIDs: rawEventIDs, Extra: extra, BodyBytes: bodyBytes,
		ElapsedNanos: int64(elapsed), Panicked: panicked,
	}
	if len(sandboxReceipt) > 0 && sandboxReceipt[0] {
		binding, ok := sandboxauth.FromContext(ctx)
		if !ok || binding.ID == "" {
			return p, errors.New("sandbox hook receipt has no authenticated binding")
		}
		p.SandboxReceipt = &sandboxPendingHookReceipt{
			BindingID: binding.ID, RegistrationID: binding.RegistrationID,
			OfferedAt: time.Now(), Reason: proposed.Reason,
			SourceReason: hookSourceReason(proposed),
			CallRef:      manager.ContentRef(req.SessionID, req.ToolName, sandboxDecisionToolInput(*req)),
		}
		if p.Proposed.RawAction == "" {
			p.Proposed.RawAction = proposed.Action
		}
		var identity HookAuditEnvelope
		a.stampHookEnvelopeIdentity(ctx, req.ConnectorName, &identity, *req, proposed)
		p.SandboxReceipt.EnvelopeIdentity = pendingEnvelopeIdentity(identity)
	}
	req.pendingOccurrenceID, req.pendingBodyBytes = p.ID, bodyBytes
	if a.store == nil {
		return p, errors.New("hook audit store is unavailable")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	return p, a.store.JournalHookDelivery(ctx, p.ID, a.deliveryProcessID(), data)
}

// settlePendingHook deletes the journal row once both records of the call
// are settled. Otherwise the row stays for the next gateway process.
func (a *APIServer) settlePendingHook(ctx context.Context, p *pendingHookOccurrence, result hookFinalizationResult) {
	if p == nil || !result.AuditPersisted || !result.DecisionSettled {
		return
	}
	if err := a.store.ForgetHookDelivery(ctx, p.ID); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal cleanup failed id=%s: %v\n", p.ID, err)
	}
}

// pendingHookRecovery runs one recovery pass at a time in this process: a
// config reload starts a new server beside the old one.
var pendingHookRecovery sync.Mutex

// startPendingHookRecovery audits, in the background, the journal rows
// earlier gateway processes left. Listeners never wait for it, and nothing
// it meets stops the gateway: a row it cannot audit yet stays for the next
// start.
func (a *APIServer) startPendingHookRecovery(ctx context.Context) {
	a.pendingHookRecoveryOnce.Do(func() { go a.recoverPendingHooks(ctx) })
}

func (a *APIServer) recoverPendingHooks(ctx context.Context) {
	if a == nil || a.store == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return
	}
	pendingHookRecovery.Lock()
	defer pendingHookRecovery.Unlock()
	entries, err := a.store.UnauditedHookDeliveries(ctx, a.deliveryProcessID())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal unreadable; kept for the next start: %v\n", err)
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		if err := a.recoverPendingHook(ctx, entry); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s not recovered; kept for the next start: %v\n", entry.ID, err)
		}
	}
}

// recoverPendingHook audits one journal row and deletes it. A panic is an
// error, never a gateway exit.
func (a *APIServer) recoverPendingHook(ctx context.Context, entry audit.HookDeliveryJournalEntry) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recovery panic: %v", recovered)
		}
	}()
	var p pendingHookOccurrence
	if err := json.Unmarshal(entry.Occurrence, &p); err != nil {
		return err
	}
	if p.ID != entry.ID || p.Request.ConnectorName == "" || p.Request.HookEventName == "" {
		return errors.New("journal row fields are invalid")
	}
	if p.SandboxReceipt != nil {
		remaining := time.Until(p.SandboxReceipt.OfferedAt.Add(sandboxHookReceiptWindow))
		if remaining > 0 {
			wait := time.NewTimer(remaining)
			defer wait.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait.C:
			}
		}
		sandboxHookReceiptLock(p.ID).Lock()
		defer sandboxHookReceiptLock(p.ID).Unlock()
		// An acknowledgement can update the journal while startup recovery
		// waits for the receipt window. Reload after taking the same lock.
		latest, found, err := a.store.HookDelivery(ctx, p.ID)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if err := json.Unmarshal(latest.Occurrence, &p); err != nil {
			return err
		}
		if p.Settled {
			return a.store.ForgetHookDelivery(ctx, p.ID)
		}
	}
	resp, err := a.pendingHookRecoveryResponse(ctx, &p)
	if err != nil {
		return err
	}
	req := p.Request.request(p.ID, p.BodyBytes)
	if p.SandboxReceipt != nil {
		req.pendingEnvelopeIdentity = &p.SandboxReceipt.EnvelopeIdentity
		req.pendingSandboxCallRef = p.SandboxReceipt.CallRef
	}
	persistCtx := audit.ContextWithEnvelope(ctx, p.Envelope)
	persistCtx = ContextWithAgentIdentity(persistCtx, p.Identity)
	persistCtx = enrichAgentHookContext(persistCtx, req)
	persistCtx = withRedactionDecision(persistCtx, resp.RedactionEnabled)
	result := a.finalizeAgentHook(persistCtx, req.ConnectorName, req, resp,
		p.RawEventIDs, nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
	if !result.AuditPersisted || !result.DecisionSettled {
		// Stable IDs make the next pass skip whichever record landed.
		return fmt.Errorf("audit=%t hook_decision=%t", result.AuditPersisted, result.DecisionSettled)
	}
	return a.store.ForgetHookDelivery(ctx, p.ID)
}

// pendingHookRecoveryResponse is the answer recovery audits. A record of
// the occurrence that is already stored decides its missing companion, so
// the two records of one call never disagree. With neither stored, the
// call has its no-receipt decision.
func (a *APIServer) pendingHookRecoveryResponse(ctx context.Context, p *pendingHookOccurrence) (agentHookResponse, error) {
	for _, id := range []string{p.ID, p.ID + "-decision"} {
		action, found, err := a.store.StoredHookDecisionAction(ctx, id)
		if err != nil {
			return agentHookResponse{}, err
		}
		if found {
			return p.responseFor(action), nil
		}
	}
	if p.Final != nil {
		return p.Final.response(), nil
	}
	return p.NoReceipt.response(), nil
}

// responseFor is the occurrence's answer whose decision is action, the
// decision a stored record holds. A live handler records the acknowledged
// proposal, the no-receipt decision, or a block: the hook refused the
// answer, or the gateway answered 503 and the hook took its closed
// fallback.
func (p *pendingHookOccurrence) responseFor(action string) agentHookResponse {
	switch {
	case strings.EqualFold(action, p.NoReceipt.Action):
		return p.NoReceipt.response()
	case strings.EqualFold(action, p.Proposed.Action):
		if p.SandboxReceipt != nil {
			return p.SandboxReceipt.response(p.Proposed)
		}
		return p.Proposed.response()
	case strings.EqualFold(action, "block"):
		return failedClosedHookDelivery(p.Proposed.response(), hookexec.ManagedGatewayNoAnswerReason)
	}
	resp := p.NoReceipt.response()
	if action != "" {
		resp.Action = action
	}
	return resp
}
