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
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/google/uuid"
)

// A receipt-capable managed hook can act on an answer before the gateway's
// audit write, which waits for the hook's receipt. So the occurrence is
// journaled in the audit store before the answer is offered
// (audit.Store.JournalHookDelivery): one power-loss durable row with only
// the facts needed to audit the call without its receipt, no raw hook body,
// tool arguments or response output. Once the gateway knows the decision the
// call has, the row records it too, before any record of the call is written.
// The handler deletes the row once its records are settled. A row whose
// handler could not write them is audited later, by the next gateway process
// or, when the journal fills up, by this one: as the decision the row records,
// or as the decision the call has without a receipt.
const pendingHookRecoveredReason = "managed hook receipt recovered after gateway restart"

// pendingHookJournalRows bounds the journal. Rows pile up only while the
// records of the calls cannot be written; a full journal refuses the next
// call (a 503 the managed hook resolves closed) and starts a recovery pass.
var pendingHookJournalRows = 10000

// pendingHookRecoveryBatch is the number of journal rows recovery reads at a
// time. A pass stops after pendingHookRecoveryFailures rows in a row whose
// records could not be written: the store still refuses them.
const (
	pendingHookRecoveryBatch    = 100
	pendingHookRecoveryFailures = 3
)

// pendingHookDrainInterval spaces the recovery passes a full journal starts.
var pendingHookDrainInterval = 15 * time.Second

// hookDeliveryProcessID tells this process's journal rows from those of a
// gateway process that has stopped. Rows of this process whose handler is
// still running (pendingHooksInFlight), also one of a server a config reload
// replaced, are never taken over by recovery.
var hookDeliveryProcessID = uuid.NewString()

// pendingHooksInFlight holds the journal row IDs of this process's running
// handlers.
var pendingHooksInFlight sync.Map

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
	// Reason and SourceReason are kept for the decided answer only
	// (pendingHookOccurrence.Decided), so its recovered records are the
	// records the live handler wrote.
	Reason       string `json:",omitempty"`
	SourceReason string `json:",omitempty"`
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
	Proposed  pendingHookResponse
	NoReceipt pendingHookResponse
	// Decided is the decision the live handler audits, recorded before it
	// writes the records.
	Decided      *pendingHookResponse `json:",omitempty"`
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
// of auditing the call a second time. The caller ends with
// settlePendingHook.
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
	pendingHooksInFlight.Store(p.ID, struct{}{})
	err = a.store.JournalHookDelivery(ctx, p.ID, a.deliveryProcessID(), data, pendingHookJournalRows)
	if errors.Is(err, audit.ErrHookDeliveryJournalFull) {
		a.drainPendingHooks()
	}
	return p, err
}

// pendingHookDecidedContext records resp, the decision the call has, in its
// journal row before the caller writes the records of the call with the
// returned context. A record leaves for the remote destinations even when
// the local store refuses it (GAP-1536), so recovery must write the same
// decision: it replays a recorded one. Where the decision could not be
// recorded, the records leave only once the local store keeps them, so the
// remote destinations never get a decision recovery writes differently.
func (a *APIServer) pendingHookDecidedContext(ctx context.Context, p *pendingHookOccurrence, resp agentHookResponse) context.Context {
	if p == nil || a.store == nil {
		return ctx
	}
	decided := pendingResponse(resp)
	decided.Reason, decided.SourceReason = resp.Reason, resp.SourceReason
	p.Decided = &decided
	data, err := json.Marshal(p)
	if err == nil {
		// No row: the journal refused it, so no recovery follows.
		_, err = a.store.RecordHookDeliveryVerdict(ctx, p.ID, data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery decision not journaled id=%s; its records wait for the local store: %v\n", p.ID, err)
		return observability.WithRemoteExport(ctx, observability.RemoteExportAfterLocalWrite)
	}
	return ctx
}

// settlePendingHook deletes the journal row once both records of the call
// are settled. Otherwise the row stays for recovery.
func (a *APIServer) settlePendingHook(ctx context.Context, p *pendingHookOccurrence, result hookFinalizationResult) {
	if p == nil {
		return
	}
	defer pendingHooksInFlight.Delete(p.ID)
	if !result.AuditPersisted || !result.DecisionSettled {
		return
	}
	if err := a.store.ForgetHookDelivery(ctx, p.ID); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal cleanup failed id=%s: %v\n", p.ID, err)
	}
}

// pendingHookRecovery runs one recovery pass at a time in this process: a
// config reload starts a new server beside the old one.
var pendingHookRecovery sync.Mutex

// pendingHookDrainAt is when a full journal last started a recovery pass.
var pendingHookDrainAt atomic.Int64

// startPendingHookRecovery audits, in the background, the journal rows
// earlier gateway processes left. Listeners never wait for it, and nothing
// it meets stops the gateway: a row it cannot audit yet stays for the next
// pass.
func (a *APIServer) startPendingHookRecovery(ctx context.Context) {
	a.pendingHookRecoveryOnce.Do(func() { go a.recoverPendingHooks(ctx) })
}

// drainPendingHooks starts a recovery pass in the background when the
// journal is full, at most one per pendingHookDrainInterval, so the journal
// empties once the store takes records again.
func (a *APIServer) drainPendingHooks() {
	now, last := time.Now().UnixNano(), pendingHookDrainAt.Load()
	if now-last < int64(pendingHookDrainInterval) || !pendingHookDrainAt.CompareAndSwap(last, now) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a.recoverPendingHooks(ctx)
	}()
}

// errPendingHookNotWritten is a journal row whose records the store did not
// take.
var errPendingHookNotWritten = errors.New("records not written")

func (a *APIServer) recoverPendingHooks(ctx context.Context) {
	if a == nil || a.store == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return
	}
	pendingHookRecovery.Lock()
	defer pendingHookRecovery.Unlock()
	var after audit.HookDeliveryJournalEntry
	failures := 0
	for {
		entries, err := a.store.HookDeliveries(ctx, after, pendingHookRecoveryBatch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal unreadable; kept for the next pass: %v\n", err)
			return
		}
		for _, entry := range entries {
			after = entry
			if entry.ProcessID == a.deliveryProcessID() {
				if _, live := pendingHooksInFlight.Load(entry.ID); live {
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			err := a.recoverPendingHook(ctx, entry)
			if err == nil {
				failures = 0
				continue
			}
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s not recovered; kept for the next pass: %v\n", entry.ID, err)
			if errors.Is(err, errPendingHookNotWritten) {
				if failures++; failures >= pendingHookRecoveryFailures {
					return
				}
			}
		}
		if len(entries) < pendingHookRecoveryBatch {
			return
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
	resp, export, err := a.pendingHookRecoveryResponse(ctx, &p)
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
	persistCtx = observability.WithRemoteExport(persistCtx, export)
	result := a.finalizeAgentHook(persistCtx, req.ConnectorName, req, resp,
		p.RawEventIDs, nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
	if !result.AuditPersisted || !result.DecisionSettled {
		// Stable IDs make the next pass skip whichever record landed.
		return fmt.Errorf("%w: audit=%t hook_decision=%t", errPendingHookNotWritten, result.AuditPersisted, result.DecisionSettled)
	}
	return a.store.ForgetHookDelivery(ctx, p.ID)
}

// pendingHookRecoveryResponse is the answer recovery audits, and when its
// records leave for the remote destinations. A decision the live handler
// recorded is replayed: its handler already sent the records that were
// refused locally, so the replay is written locally only. Otherwise a record
// of the occurrence that is already stored decides its missing companion, so
// the two records of one call never disagree, and with neither stored the
// call has its no-receipt decision. Those records leave once the local store
// keeps them: a pass that cannot write them sends nothing, and the next pass
// writes the same decision.
func (a *APIServer) pendingHookRecoveryResponse(ctx context.Context, p *pendingHookOccurrence) (agentHookResponse, observability.RemoteExport, error) {
	if p.Decided != nil {
		resp := p.Decided.response()
		resp.Reason, resp.SourceReason = p.Decided.Reason, p.Decided.SourceReason
		return resp, observability.RemoteExportNone, nil
	}
	for _, id := range []string{p.ID, p.ID + "-decision"} {
		action, found, err := a.store.StoredHookDecisionAction(ctx, id)
		if err != nil {
			return agentHookResponse{}, 0, err
		}
		if found {
			return p.responseFor(action), observability.RemoteExportAfterLocalWrite, nil
		}
	}
	if p.Final != nil {
		if p.SandboxReceipt != nil && p.Final.Action == "block" {
			return failedClosedHookDelivery(p.SandboxReceipt.response(p.Proposed), hookexec.ManagedGatewayNoAnswerReason),
				observability.RemoteExportAfterLocalWrite, nil
		}
		return p.Final.response(), observability.RemoteExportAfterLocalWrite, nil
	}
	return p.NoReceipt.response(), observability.RemoteExportAfterLocalWrite, nil
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
