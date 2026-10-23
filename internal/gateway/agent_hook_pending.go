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
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

// A receipt-capable managed hook can act on an answer before the gateway's
// audit write, which waits for the hook's receipt. So the occurrence is
// journaled in the audit store before the answer is offered
// (audit.Store.JournalHookDelivery): one power-loss durable row with only
// the facts needed to audit the call without its receipt, no raw hook body,
// tool arguments or response output, and the policy and turn the call was
// evaluated under. Once the gateway knows the decision the call has, the row
// records it too, before any record of the call is written. The handler
// deletes the row once its records are settled. A row whose handler could
// not write them is audited later, by the next gateway process or, when the
// journal fills up, by this one: as the decision the row records, or as the
// decision the call has without a receipt.
const pendingHookRecoveredReason = "managed hook receipt recovered after gateway restart"

// pendingHookJournalLimits bounds the journal in rows and bytes, and one
// occurrence in bytes. Rows pile up only while the records of the calls
// cannot be written; a full journal, or an occurrence over its limit,
// refuses the call (a 503 the managed hook resolves closed). A full journal
// also starts a recovery pass.
var pendingHookJournalLimits = audit.HookDeliveryJournalLimits{
	Rows: 10000, OccurrenceBytes: 64 << 10, Bytes: 64 << 20,
}

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

func (p *pendingHookOccurrence) request() agentHookRequest {
	r := p.Request
	return agentHookRequest{
		ConnectorName: r.ConnectorName, HookEventName: r.HookEventName,
		SessionID: r.SessionID, TurnID: r.TurnID,
		AgentID: r.AgentID, AgentName: r.AgentName, AgentType: r.AgentType,
		ToolInvocationID: r.ToolInvocationID, ToolName: r.ToolName,
		CorrelationUnavailable: r.CorrelationUnavailable,
		pendingOccurrenceID:    p.ID, pendingBodyBytes: p.BodyBytes, pendingRecovery: true,
		pendingProvenance: &p.Provenance,
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
	Provenance   pendingHookProvenance
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
	BindingID      string
	RegistrationID string
	OfferedAt      time.Time
	Reason         string
	SourceReason   string
	CallRef        string
}

func (s sandboxPendingHookReceipt) response(proposed pendingHookResponse) agentHookResponse {
	resp := proposed.response()
	resp.Reason, resp.SourceReason = s.Reason, s.SourceReason
	return resp
}

// pendingHookProvenance is the policy and the turn a journaled call was
// evaluated under, stamped once, before its answer is offered. Both records
// of the call carry it, also when a later gateway process writes them, and
// never the state of the server that writes them: its rule pack, its turn
// counter, its agent phases or its configuration.
type pendingHookProvenance struct {
	StepIdx     int    `json:",omitempty"`
	RulePackDir string `json:",omitempty"`
	// Envelope is the agent phase of the connector audit row, Decision that
	// of the hook_decision record.
	Envelope, Decision pendingHookPhase
	// PolicyGeneration, PolicyDigest and Profile are the policy the
	// hook_decision record names.
	PolicyGeneration int64               `json:",omitempty"`
	PolicyDigest     string              `json:",omitempty"`
	Profile          *pendingHookProfile `json:",omitempty"`
	// ConfigGeneration and ConfigHash are the configuration the connector
	// audit row names (version.Current).
	ConfigGeneration uint64 `json:",omitempty"`
	ConfigHash       string `json:",omitempty"`
}

type pendingHookPhase struct {
	Phase, PreviousPhase                  string `json:",omitempty"`
	Sequence                              int64  `json:",omitempty"`
	LifecycleID, ExecutionID, OperationID string `json:",omitempty"`
}

// pendingHookProfile is a guardrailProfileTelemetry; a nil field is absent.
type pendingHookProfile struct {
	Name, Digest, Match, MatchedGroup *string `json:",omitempty"`
}

// pendingHookProvenanceFor stamps the provenance of a call about to be
// journaled. It takes the step of the turn, so it runs once per call.
func (a *APIServer) pendingHookProvenanceFor(ctx context.Context, req agentHookRequest, proposed agentHookResponse) (prov pendingHookProvenance) {
	defer func() {
		if recovered := recover(); recovered != nil {
			a.handleHookPanic(ctx, req.ConnectorName, req.HookEventName,
				fmt.Sprintf("hook delivery provenance panic: %v", recovered))
		}
	}()
	var env HookAuditEnvelope
	a.stampHookEnvelopeIdentity(ctx, req.ConnectorName, &env, req, proposed)
	prov.StepIdx, prov.RulePackDir = env.StepIdx, env.RulePackDir
	prov.Envelope = pendingHookPhase{
		Phase: env.AgentPhase, PreviousPhase: env.AgentPreviousPhase, Sequence: env.AgentSequence,
		LifecycleID: env.AgentLifecycleID, ExecutionID: env.AgentExecutionID, OperationID: env.AgentOperationID,
	}
	if meta, _, ok := a.hookDecisionMeta(ctx, req); ok {
		prov.Decision = pendingHookPhase{
			Phase: meta.Phase, PreviousPhase: meta.PreviousPhase, Sequence: meta.Sequence,
			LifecycleID: meta.LifecycleID, ExecutionID: meta.ExecutionID, OperationID: meta.OperationID,
		}
	}
	if g := policyStampGeneration(ctx); g != nil {
		prov.PolicyGeneration, prov.PolicyDigest = int64(g.N), g.Digest
	}
	if profile := guardrailProfileTelemetryFor(ctx); profile != (guardrailProfileTelemetry{}) {
		prov.Profile = &pendingHookProfile{
			Name: optionalProvenance(profile.Name), Digest: optionalProvenance(profile.Digest),
			Match: optionalProvenance(profile.Match), MatchedGroup: optionalProvenance(profile.MatchedGroup),
		}
	}
	current := version.Current()
	prov.ConfigGeneration, prov.ConfigHash = current.Generation, current.ContentHash
	return prov
}

// stamp puts the provenance on the connector audit row of the call.
func (p *pendingHookProvenance) stamp(env *HookAuditEnvelope) {
	env.StepIdx, env.RulePackDir = p.StepIdx, p.RulePackDir
	env.AgentPhase, env.AgentPreviousPhase, env.AgentSequence = p.Envelope.Phase, p.Envelope.PreviousPhase, p.Envelope.Sequence
	env.AgentLifecycleID, env.AgentExecutionID, env.AgentOperationID = p.Envelope.LifecycleID, p.Envelope.ExecutionID, p.Envelope.OperationID
	env.configGeneration, env.configHash = p.ConfigGeneration, p.ConfigHash
}

// decisionMeta puts the agent phase of the provenance on the hook_decision
// record of the call.
func (p *pendingHookProvenance) decisionMeta(meta llmEventMeta) llmEventMeta {
	meta.Phase, meta.PreviousPhase, meta.Sequence = p.Decision.Phase, p.Decision.PreviousPhase, p.Decision.Sequence
	meta.LifecycleID, meta.ExecutionID, meta.OperationID = p.Decision.LifecycleID, p.Decision.ExecutionID, p.Decision.OperationID
	return meta
}

// decisionPolicy is the policy the hook_decision record of the call names.
func (p *pendingHookProvenance) decisionPolicy() (guardrailProfileTelemetry, observability.Optional[string], observability.Optional[int64]) {
	var profile guardrailProfileTelemetry
	if p.Profile != nil {
		profile = guardrailProfileTelemetry{
			Name: presentProvenance(p.Profile.Name), Digest: presentProvenance(p.Profile.Digest),
			Match: presentProvenance(p.Profile.Match), MatchedGroup: presentProvenance(p.Profile.MatchedGroup),
		}
	}
	digest, generation := observability.Absent[string](), observability.Absent[int64]()
	if p.PolicyDigest != "" {
		digest = observability.Present(p.PolicyDigest)
	}
	if p.PolicyGeneration > 0 {
		generation = observability.Present(p.PolicyGeneration)
	}
	return profile, digest, generation
}

func optionalProvenance(value observability.Optional[string]) *string {
	if v, ok := value.Get(); ok {
		return &v
	}
	return nil
}

func presentProvenance(value *string) observability.Optional[string] {
	if value == nil {
		return observability.Absent[string]()
	}
	return observability.Present(*value)
}

// journalHookDelivery journals a receipt-capable call before its answer is
// offered, and gives req the occurrence IDs and the provenance its records
// carry. On an error the answer must not be offered. The IDs are set even
// then: if the row landed anyway, recovery completes the records the caller
// writes instead of auditing the call a second time. The caller ends with
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
		Provenance:  a.pendingHookProvenanceFor(ctx, *req, proposed),
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
	}
	req.pendingOccurrenceID, req.pendingBodyBytes, req.pendingProvenance = p.ID, bodyBytes, &p.Provenance
	if a.store == nil {
		return p, errors.New("hook audit store is unavailable")
	}
	data, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	pendingHooksInFlight.Store(p.ID, struct{}{})
	err = a.store.JournalHookDelivery(ctx, p.ID, a.deliveryProcessID(), data, pendingHookJournalLimits)
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
// recorded, the records leave only once the local store keeps them through
// a power loss, so the remote destinations never get a decision recovery
// writes differently.
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
		_, err = a.store.RecordHookDeliveryVerdict(ctx, p.ID, data, pendingHookJournalLimits)
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
// config reload starts a new server beside the old one. It guards
// pendingHookCursor.
var pendingHookRecovery sync.Mutex

// pendingHookCursor is the last journal row of store the previous pass in
// this process reached. A pass starts after it, reads to the end of the
// journal, then from its start up to the cursor, so rows that keep failing
// never keep a pass from the rows after them.
var pendingHookCursor struct {
	store *audit.Store
	after audit.HookDeliveryJournalEntry
}

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

// journalRowAfter reports whether a comes after b in the journal's order.
func journalRowAfter(a, b audit.HookDeliveryJournalEntry) bool {
	return a.CreatedAt > b.CreatedAt || (a.CreatedAt == b.CreatedAt && a.ID > b.ID)
}

func (a *APIServer) recoverPendingHooks(ctx context.Context) {
	if a == nil || a.store == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return
	}
	pendingHookRecovery.Lock()
	defer pendingHookRecovery.Unlock()
	var start audit.HookDeliveryJournalEntry
	if pendingHookCursor.store == a.store {
		start = pendingHookCursor.after
	}
	pendingHookCursor.store = a.store
	after, wrapped := start, start.ID == ""
	defer func() { pendingHookCursor.after = after }()
	failures := 0
	for {
		entries, err := a.store.HookDeliveries(ctx, after, pendingHookRecoveryBatch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal unreadable; kept for the next pass: %v\n", err)
			return
		}
		for _, entry := range entries {
			if wrapped && start.ID != "" && journalRowAfter(entry, start) {
				// Back past where the pass began: every row was tried.
				after = audit.HookDeliveryJournalEntry{}
				return
			}
			if ctx.Err() != nil {
				return
			}
			after = entry
			if entry.ProcessID == a.deliveryProcessID() {
				if _, live := pendingHooksInFlight.Load(entry.ID); live {
					continue
				}
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
			if wrapped {
				after = audit.HookDeliveryJournalEntry{}
				return
			}
			after, wrapped = audit.HookDeliveryJournalEntry{}, true
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
	req := p.request()
	if p.SandboxReceipt != nil {
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
// keeps them through a power loss: a pass that cannot write them sends
// nothing, and the next pass writes the same decision.
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
