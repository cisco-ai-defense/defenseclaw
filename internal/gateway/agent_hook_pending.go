// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
// evaluated under. Large fields are truncated, with a marker, before the row
// is stored.
//
// Every record of a journaled call is written under a verdict pinned in its
// row first: the live handler pins the decision it audits, and recovery pins
// the decision it audits before its first write. Recovery writes the pinned
// verdict, under the call's IDs, locally and to the remote destinations, so
// one ID never carries two verdicts. Where the live handler cannot pin, its
// records leave only once the local store keeps them through a power loss.
//
// The handler deletes the row once its records are settled. A row whose
// handler could not write them is audited later, by the next gateway process
// or, when the journal fills up, by this one. A row recovery cannot audit in
// pendingHookRecoveryAttempts tries is evicted (evictPendingHook): it is
// deleted, so the journal always drains, and leaves one record that adds no
// second verdict.

// pendingHookEvictedAction is the action of the audit row an evicted
// journal row leaves, under the call's ID plus "-evicted", when no record
// of the call can exist anywhere.
const pendingHookEvictedAction = "unconfirmed-evicted"

// pendingHookEvictedAlert is the summary, and the error code, of the
// audit-health alert an evicted journal row leaves when a record of the
// call may exist.
const pendingHookEvictedAlert = "hook_delivery_evicted"

// hookDecisionReasonMaxBytes bounds the reason a hook_decision record keeps;
// a longer reason is absent from it.
const hookDecisionReasonMaxBytes = 65536

// pendingHookJournalLimits bounds the journal in rows and bytes, and one
// occurrence in bytes. Rows pile up only while the records of the calls
// cannot be written; a full journal refuses the call (a 503 the managed hook
// resolves closed) and starts a recovery pass.
var pendingHookJournalLimits = audit.HookDeliveryJournalLimits{
	Rows: 10000, OccurrenceBytes: 64 << 10, Bytes: 64 << 20,
}

// Recovery reads pendingHookRecoveryBatch rows at a time, takes at most
// pendingHookRecoveryPassRows rows in one pass, and evicts a row after
// pendingHookRecoveryAttempts tries. A pass so holds at most one batch of
// bounded occurrences in memory, and the oldest rows leave the journal
// within pendingHookRecoveryAttempts passes whatever the store refuses.
const (
	pendingHookRecoveryBatch    = 100
	pendingHookRecoveryAttempts = 3
)

var pendingHookRecoveryPassRows = 1000

// pendingHookDrainInterval spaces the recovery passes a full journal starts.
var pendingHookDrainInterval = 15 * time.Second

// pendingHookFieldBounds are the bounds encodePendingHookOccurrence tries on
// an occurrence over its limit, loosest first: the longest string kept, and
// the most entries kept of a list or of Extra. The last always fits.
var pendingHookFieldBounds = []struct{ text, entries int }{
	{4096, 64}, {1024, 32}, {256, 16}, {128, 8},
}

// pendingHookTruncatedExtra marks, in Extra, an occurrence whose fields were
// truncated; a truncated string ends with its own marker.
const pendingHookTruncatedExtra = "defenseclaw.journal_truncated"

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
	// Reason and SourceReason are the answer's own reasons, an empty one
	// included, so every write of a verdict is the same as the live one.
	Reason       string `json:",omitempty"`
	SourceReason string `json:",omitempty"`
}

func pendingResponse(resp agentHookResponse) pendingHookResponse {
	return pendingHookResponse{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Mode: resp.Mode, WouldBlock: resp.WouldBlock,
		EvaluationID: resp.EvaluationID, RuleIDs: resp.RuleIDs,
		RedactionEnabled: resp.RedactionEnabled,
		Reason:           resp.Reason, SourceReason: resp.SourceReason,
	}
}

func (p pendingHookResponse) response() agentHookResponse {
	return agentHookResponse{
		Action: p.Action, RawAction: p.RawAction, Severity: p.Severity,
		Mode: p.Mode, Reason: p.Reason, SourceReason: p.SourceReason,
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
	// Decided is the verdict pinned before any record of the call is
	// written: by the live handler, or by recovery.
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
	// Attempts counts recovery tries recorded before each.
	Attempts int `json:",omitempty"`
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
// counter, its agent phases, its policy or its configuration.
type pendingHookProvenance struct {
	StepIdx     int    `json:",omitempty"`
	RulePackDir string `json:",omitempty"`
	// Envelope is the agent phase of the connector audit row, Decision that
	// of the hook_decision record.
	Envelope, Decision pendingHookPhase
	// PolicyGeneration, PolicyDigest, Profile, Sandbox and Exempt are the
	// policy the hook_decision record names: the gateway policy, the
	// guardrail profile, the managed sandbox registration and its sandbox
	// policy, and the account's enrollment.
	PolicyGeneration int64               `json:",omitempty"`
	PolicyDigest     string              `json:",omitempty"`
	Profile          *pendingHookProfile `json:",omitempty"`
	Sandbox          *pendingHookSandbox `json:",omitempty"`
	Exempt           bool                `json:",omitempty"`
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

// pendingHookSandbox is an audit.SandboxManagedV8; a nil field is absent.
type pendingHookSandbox struct {
	Driver, RegistrationID, PolicyDigest, SubjectKey *string `json:",omitempty"`
	OpenShellVersion, InstallMode                    *string `json:",omitempty"`
	PolicyGeneration                                 *int64  `json:",omitempty"`
	Provisional                                      *bool   `json:",omitempty"`
}

// hookDecisionPolicy is the policy a hook_decision record names.
type hookDecisionPolicy struct {
	profile    guardrailProfileTelemetry
	digest     observability.Optional[string]
	generation observability.Optional[int64]
	sandbox    audit.SandboxManagedV8
	enrollment observability.Optional[string]
}

// hookDecisionPolicyFor is the policy of a call decided under ctx.
func hookDecisionPolicyFor(ctx context.Context) hookDecisionPolicy {
	return hookDecisionPolicy{
		profile: guardrailProfileTelemetryFor(ctx), digest: policyDigestV8(ctx), generation: policyGenerationV8(ctx),
		sandbox: sandboxHookManagedV8(ctx), enrollment: enterpriseEnrollmentV8(ctx),
	}
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
	policy := hookDecisionPolicyFor(ctx)
	prov.PolicyGeneration, _ = policy.generation.Get()
	prov.PolicyDigest, _ = policy.digest.Get()
	if profile := policy.profile; profile != (guardrailProfileTelemetry{}) {
		prov.Profile = &pendingHookProfile{
			Name: optionalPointer(profile.Name), Digest: optionalPointer(profile.Digest),
			Match: optionalPointer(profile.Match), MatchedGroup: optionalPointer(profile.MatchedGroup),
		}
	}
	if sandbox := policy.sandbox; sandbox != (audit.SandboxManagedV8{}) {
		prov.Sandbox = &pendingHookSandbox{
			Driver: optionalPointer(sandbox.Driver), RegistrationID: optionalPointer(sandbox.RegistrationID),
			PolicyDigest: optionalPointer(sandbox.PolicyDigest), SubjectKey: optionalPointer(sandbox.SubjectKey),
			OpenShellVersion: optionalPointer(sandbox.OpenShellVersion), InstallMode: optionalPointer(sandbox.InstallMode),
			PolicyGeneration: optionalPointer(sandbox.PolicyGeneration), Provisional: optionalPointer(sandbox.Provisional),
		}
	}
	prov.Exempt = policy.enrollment.IsPresent()
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

// decisionPolicyOr is the policy the hook_decision record of a call names:
// the one journaled with it (a field it lacks is absent, never the current
// one), or, for a call that was not journaled (nil p), the policy of ctx.
func (p *pendingHookProvenance) decisionPolicyOr(ctx context.Context) hookDecisionPolicy {
	if p == nil {
		return hookDecisionPolicyFor(ctx)
	}
	var policy hookDecisionPolicy
	if p.Profile != nil {
		policy.profile = guardrailProfileTelemetry{
			Name: presentPointer(p.Profile.Name), Digest: presentPointer(p.Profile.Digest),
			Match: presentPointer(p.Profile.Match), MatchedGroup: presentPointer(p.Profile.MatchedGroup),
		}
	}
	if p.PolicyDigest != "" {
		policy.digest = observability.Present(p.PolicyDigest)
	}
	if p.PolicyGeneration > 0 {
		policy.generation = observability.Present(p.PolicyGeneration)
	}
	if s := p.Sandbox; s != nil {
		policy.sandbox = audit.SandboxManagedV8{
			Driver: presentPointer(s.Driver), RegistrationID: presentPointer(s.RegistrationID),
			PolicyDigest: presentPointer(s.PolicyDigest), SubjectKey: presentPointer(s.SubjectKey),
			OpenShellVersion: presentPointer(s.OpenShellVersion), InstallMode: presentPointer(s.InstallMode),
			PolicyGeneration: presentPointer(s.PolicyGeneration), Provisional: presentPointer(s.Provisional),
		}
	}
	if p.Exempt {
		policy.enrollment = observability.Present("exempt")
	}
	return policy
}

func optionalPointer[T any](value observability.Optional[T]) *T {
	if v, ok := value.Get(); ok {
		return &v
	}
	return nil
}

func presentPointer[T any](value *T) observability.Optional[T] {
	if value == nil {
		return observability.Absent[T]()
	}
	return observability.Present(*value)
}

// encodePendingHookOccurrence is the journal form of p. An occurrence over
// the journal's limit is stored with its large fields truncated: each long
// string ends with a marker, long lists and Extra keep their first entries,
// and Extra says the occurrence was truncated. IDs, numbers and the pinned
// verdict (Decided) are kept whole: a pin that does not fit is an error, so
// the caller holds its records as for any pin that failed. Recovery decodes
// a truncated occurrence like any other; a truncated reason of Proposed or
// NoReceipt matches no stored record (pendingHookRecoveryVerdict).
func encodePendingHookOccurrence(p *pendingHookOccurrence) ([]byte, error) {
	data, err := json.Marshal(p)
	limit := pendingHookJournalLimits.OccurrenceBytes
	if err != nil || len(data) <= limit {
		return data, err
	}
	var tree map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber() // int64 and uint64 fields round-trip exactly
	if err := decoder.Decode(&tree); err != nil {
		return nil, err
	}
	for _, bound := range pendingHookFieldBounds {
		bounded := make(map[string]any, len(tree))
		for key, value := range tree {
			switch key {
			case "Extra":
				continue
			case "Decided":
				bounded[key] = value
				continue
			}
			bounded[key] = truncatePendingHookValue(value, bound.text, bound.entries)
		}
		extra := map[string]any{pendingHookTruncatedExtra: "true"}
		if fields, ok := tree["Extra"].(map[string]any); ok {
			keys := make([]string, 0, len(fields))
			for key := range fields {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys[:min(len(keys), bound.entries)] {
				extra[truncatePendingHookText(key, bound.text)] = truncatePendingHookValue(fields[key], bound.text, bound.entries)
			}
		}
		bounded["Extra"] = extra
		if data, err = json.Marshal(bounded); err != nil {
			return nil, err
		}
		if len(data) <= limit {
			return data, nil
		}
	}
	return nil, audit.ErrHookDeliveryOccurrenceTooLarge
}

func truncatePendingHookValue(value any, text, entries int) any {
	switch v := value.(type) {
	case string:
		return truncatePendingHookText(v, text)
	case []any:
		kept := make([]any, 0, min(len(v), entries))
		for _, item := range v[:min(len(v), entries)] {
			kept = append(kept, truncatePendingHookValue(item, text, entries))
		}
		return kept
	case map[string]any:
		kept := make(map[string]any, len(v))
		for key, item := range v {
			kept[key] = truncatePendingHookValue(item, text, entries)
		}
		return kept
	}
	return value
}

// truncatePendingHookText keeps the first text bytes of s, cut on a rune
// boundary, and marks how many it dropped.
func truncatePendingHookText(s string, text int) string {
	if len(s) <= text {
		return s
	}
	cut := text
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("…[truncated %d bytes]", len(s)-cut)
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
	data, err := encodePendingHookOccurrence(p)
	if err != nil {
		return p, err
	}
	pendingHooksInFlight.Store(p.ID, struct{}{})
	// The journal write is a durable insert (fsync): store I/O, not answer
	// CPU, so the caller's run slot is free while it waits (GAP-1790).
	resume := waitWithoutHookRunSlot(ctx)
	err = a.store.JournalHookDelivery(ctx, p.ID, a.deliveryProcessID(), data, pendingHookJournalLimits)
	resume()
	if errors.Is(err, audit.ErrHookDeliveryJournalFull) {
		a.drainPendingHooks()
	}
	return p, err
}

// pendingHookDecidedContext pins resp, the decision the call has, in its
// journal row before the caller writes the records of the call with the
// returned context. A record leaves for the remote destinations even when
// the local store refuses it (GAP-1536), and recovery writes the pinned
// verdict. Where the verdict could not be pinned, the records leave only
// once the local store keeps them through a power loss, so the remote
// destinations never get a decision recovery writes differently.
func (a *APIServer) pendingHookDecidedContext(ctx context.Context, p *pendingHookOccurrence, resp agentHookResponse) context.Context {
	if p == nil || a.store == nil {
		return ctx
	}
	verdict := pendingResponse(resp)
	p.Decided = &verdict
	data, err := encodePendingHookOccurrence(p)
	if err == nil {
		// No row: the journal refused it, so no recovery follows.
		_, err = a.store.UpdateHookDelivery(ctx, p.ID, data, pendingHookJournalLimits)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery decision not journaled id=%s; its records wait for the local store: %v\n", p.ID, err)
		return observability.WithRemoteExport(ctx, observability.RemoteExportAfterLocalWrite)
	}
	return ctx
}

// settlePendingHook deletes the journal row once both records of the call
// are settled. Otherwise the row stays, and the recovery loop of the
// running server takes it once this handler is done
// (wakePendingHookRecovery).
func (a *APIServer) settlePendingHook(ctx context.Context, p *pendingHookOccurrence, result hookFinalizationResult) {
	if p == nil {
		return
	}
	settled := false
	defer func() {
		pendingHooksInFlight.Delete(p.ID)
		if !settled {
			wakePendingHookRecovery()
		}
	}()
	if !result.AuditPersisted || !result.DecisionSettled {
		return
	}
	if err := a.store.ForgetHookDelivery(ctx, p.ID); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal cleanup failed id=%s: %v\n", p.ID, err)
		return
	}
	settled = true
}

// pendingHookRecovery runs one recovery pass at a time in this process: a
// config reload starts a new server beside the old one. It guards
// pendingHookUnrecordedTries.
var pendingHookRecovery sync.Mutex

// pendingHookUnrecordedTries counts, by journal row, the tries recovery
// could not record in the row because the store refused the update. With
// the recorded Attempts they bound the tries of a row in this process.
var pendingHookUnrecordedTries = map[string]int{}

// pendingHookDrainAt is when a full journal last started a recovery pass,
// and pendingHookDraining whether that pass still runs.
var (
	pendingHookDrainAt  atomic.Int64
	pendingHookDraining atomic.Bool
)

// pendingHookRecoveryRetryInterval is how long the recovery loop waits
// before it tries again a row it could not audit (the store refused its
// records or its deletion, or the journal could not be read), and before
// it takes a row that was left for it (wakePendingHookRecovery). While
// passes keep leaving such a row, each wait doubles, up to
// pendingHookRecoveryRetryMaxFactor intervals, so the tries of a row span
// minutes of a store outage before it is evicted.
var pendingHookRecoveryRetryInterval = time.Minute

const pendingHookRecoveryRetryMaxFactor = 16

// pendingHookRecoveryLoops holds the wake channel of each recovery loop
// running in this process.
var pendingHookRecoveryLoops = struct {
	sync.Mutex
	wakes map[chan struct{}]struct{}
}{wakes: map[chan struct{}]struct{}{}}

// wakePendingHookRecovery tells every running recovery loop that a row was
// left for it: a handler could not settle its call, or a full-journal
// drain pass left rows. Each loop has its own wake, so the loop of the
// server that runs now also takes a row a handler of a server a config
// reload replaced left, and the canceled loop of that server cannot take
// the wake from it.
func wakePendingHookRecovery() {
	pendingHookRecoveryLoops.Lock()
	defer pendingHookRecoveryLoops.Unlock()
	for wake := range pendingHookRecoveryLoops.wakes {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

// pendingHookPass is what a recovery pass left in the journal.
type pendingHookPass int

const (
	// pendingHookPassDone: no row is left that a pass may take (the rows
	// of this process's running handlers aside).
	pendingHookPassDone pendingHookPass = iota
	// pendingHookPassMore: the pass stopped at pendingHookRecoveryPassRows
	// with rows still to take.
	pendingHookPassMore
	// pendingHookPassRetry: a row the pass took is still there (its
	// records or its deletion were refused), or the journal could not be
	// read.
	pendingHookPassRetry
)

// journalsHookDeliveries reports whether this server keeps the hook
// delivery journal: only a standalone enterprise gateway with an audit
// store does (Secure Client and per-user hooks never journal).
func (a *APIServer) journalsHookDeliveries() bool {
	return a != nil && a.store != nil && a.scannerCfg != nil && a.scannerCfg.StandaloneEnterprise()
}

// startPendingHookRecovery starts, in the background, the recovery loop
// of this server (runPendingHookRecovery). Listeners never wait for it,
// and nothing it meets stops the gateway.
func (a *APIServer) startPendingHookRecovery(ctx context.Context) {
	if !a.journalsHookDeliveries() {
		return
	}
	retry := pendingHookRecoveryRetryInterval
	a.pendingHookRecoveryOnce.Do(func() {
		// Its wake is registered before its first pass reads the journal,
		// so a row left after that read wakes it.
		wake := make(chan struct{}, 1)
		pendingHookRecoveryLoops.Lock()
		pendingHookRecoveryLoops.wakes[wake] = struct{}{}
		pendingHookRecoveryLoops.Unlock()
		go a.runPendingHookRecovery(ctx, retry, wake)
	})
}

// runPendingHookRecovery audits the journal for as long as ctx lives, one
// bounded pass at a time: a pass at start, for the rows earlier gateway
// processes left; the next pass at once after a pass that stopped at its
// bound; a pass retry later after a pass that left a row it could not
// audit, or could not read the journal, the wait doubling while passes
// keep leaving one; and a pass retry after a row was left for it (wake,
// wakePendingHookRecovery). A row leaves the journal within
// pendingHookRecoveryAttempts tries, so the loop goes idle once the
// journal holds only rows of running handlers.
func (a *APIServer) runPendingHookRecovery(ctx context.Context, retry time.Duration, wake chan struct{}) {
	defer func() {
		pendingHookRecoveryLoops.Lock()
		delete(pendingHookRecoveryLoops.wakes, wake)
		pendingHookRecoveryLoops.Unlock()
	}()
	next := time.NewTimer(0)
	defer next.Stop()
	armed, wait := true, retry
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			if !armed {
				next.Reset(retry)
				armed = true
			}
			continue
		case <-next.C:
		}
		switch a.recoverPendingHooks(ctx) {
		case pendingHookPassMore:
			next.Reset(0)
			wait = retry
		case pendingHookPassRetry:
			next.Reset(wait)
			wait = min(2*wait, pendingHookRecoveryRetryMaxFactor*retry)
		default:
			armed, wait = false, retry
		}
	}
}

// drainPendingHooks starts a recovery pass in the background when the
// journal is full: one at a time, at most one per pendingHookDrainInterval,
// so the journal empties once the store takes records again, or by
// eviction.
func (a *APIServer) drainPendingHooks() {
	now := time.Now().UnixNano()
	if now-pendingHookDrainAt.Load() < int64(pendingHookDrainInterval) || !pendingHookDraining.CompareAndSwap(false, true) {
		return
	}
	pendingHookDrainAt.Store(now)
	go func() {
		defer pendingHookDraining.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if a.recoverPendingHooks(ctx) != pendingHookPassDone {
			wakePendingHookRecovery()
		}
	}()
}

// errPendingHookNotWritten is a journal row whose records the store did not
// take.
var errPendingHookNotWritten = errors.New("records not written")

// recoverPendingHooks is one recovery pass: oldest row first, at most
// pendingHookRecoveryPassRows rows. Each row it takes is audited, tried
// again by a later pass, or evicted; a row of a running handler is left
// alone. It says what it left for a later pass.
func (a *APIServer) recoverPendingHooks(ctx context.Context) pendingHookPass {
	if !a.journalsHookDeliveries() {
		return pendingHookPassDone
	}
	pendingHookRecovery.Lock()
	defer pendingHookRecovery.Unlock()
	if len(pendingHookUnrecordedTries) > pendingHookJournalLimits.Rows {
		clear(pendingHookUnrecordedTries) // rows another process deleted
	}
	var after audit.HookDeliveryJournalEntry
	taken, left := 0, pendingHookPassDone
	for {
		entries, err := a.store.HookDeliveries(ctx, after, pendingHookRecoveryBatch, pendingHookJournalLimits.OccurrenceBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery journal unreadable; kept for the next pass: %v\n", err)
			return pendingHookPassRetry
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return pendingHookPassRetry
			}
			if taken >= pendingHookRecoveryPassRows {
				if left == pendingHookPassDone {
					left = pendingHookPassMore
				}
				return left
			}
			after = audit.HookDeliveryJournalEntry{ID: entry.ID, CreatedAt: entry.CreatedAt}
			if entry.ProcessID == a.deliveryProcessID() {
				if _, live := pendingHooksInFlight.Load(entry.ID); live {
					continue
				}
			}
			taken++
			if err := a.recoverPendingHook(ctx, entry); err != nil {
				fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s not recovered; tried again later: %v\n", entry.ID, err)
				left = pendingHookPassRetry
			}
		}
		if len(entries) < pendingHookRecoveryBatch {
			return left
		}
	}
}

// recoverPendingHook tries one journal row: it records the try and the
// verdict in the row, writes the records of the call under that verdict and
// deletes the row. A try the store does not let it record is counted in
// this process (pendingHookUnrecordedTries). A row it cannot read, and a row
// whose last try failed, is evicted. A panic is an error, never a gateway
// exit; the try was recorded before it.
func (a *APIServer) recoverPendingHook(ctx context.Context, entry audit.HookDeliveryJournalEntry) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("recovery panic: %v", recovered)
		}
	}()
	var p pendingHookOccurrence
	if entry.Occurrence == nil || json.Unmarshal(entry.Occurrence, &p) != nil ||
		p.ID != entry.ID || p.Request.ConnectorName == "" || p.Request.HookEventName == "" {
		return a.evictPendingHook(ctx, entry.ID, nil, false, "the journal row cannot be read")
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
			return a.forgetPendingHook(ctx, p.ID)
		}
	}
	tries := p.Attempts + pendingHookUnrecordedTries[p.ID]
	if tries >= pendingHookRecoveryAttempts {
		return a.evictPendingHook(ctx, p.ID, &p, p.Decided != nil, fmt.Sprintf("not audited in %d recovery attempts", tries))
	}
	tries++
	p.Attempts++
	newVerdict := p.Decided == nil
	var verdictErr error
	if newVerdict {
		var resp agentHookResponse
		if resp, verdictErr = a.pendingHookRecoveryVerdict(ctx, &p); verdictErr == nil {
			verdict := pendingResponse(resp)
			p.Decided = &verdict
		}
	}
	data, err := encodePendingHookOccurrence(&p)
	found := false
	if err == nil {
		found, err = a.store.UpdateHookDelivery(ctx, p.ID, data, pendingHookJournalLimits)
	}
	// held: the verdict of this try is not pinned in the row (the store
	// refused the update, or the journal is at its byte budget), so its
	// records leave only once the local store keeps them, as the live
	// handler's do.
	held := err != nil && newVerdict
	switch {
	case err != nil:
		pendingHookUnrecordedTries[p.ID]++
	case !found:
		return nil // another pass took it
	}
	if p.Decided == nil {
		err = verdictErr
	} else {
		err = a.writePendingHookRecords(ctx, &p, held)
	}
	if err != nil {
		if tries >= pendingHookRecoveryAttempts {
			return a.evictPendingHook(ctx, p.ID, &p, p.Decided != nil && !held, fmt.Sprintf("not audited in %d recovery attempts: %v", tries, err))
		}
		return err
	}
	return a.forgetPendingHook(ctx, p.ID)
}

// writePendingHookRecords writes the records of p under its pinned verdict,
// those the store does not hold yet, with the provenance it was journaled
// with. They leave for the remote destinations as any record does: a copy
// already sent carries the same verdict. A held verdict, one this try could
// not pin, leaves only once the local store keeps it. Recovery repeats none of the
// call's live side effects (health counters, metrics, spans, alerts).
func (a *APIServer) writePendingHookRecords(ctx context.Context, p *pendingHookOccurrence, held bool) error {
	resp := p.Decided.response()
	req := p.request()
	if p.SandboxReceipt != nil {
		req.pendingSandboxCallRef = p.SandboxReceipt.CallRef
	}
	persistCtx := audit.ContextWithEnvelope(ctx, p.Envelope)
	persistCtx = ContextWithAgentIdentity(persistCtx, p.Identity)
	persistCtx = enrichAgentHookContext(persistCtx, req)
	persistCtx = withRedactionDecision(persistCtx, resp.RedactionEnabled)
	if held {
		persistCtx = observability.WithRemoteExport(persistCtx, observability.RemoteExportAfterLocalWrite)
	}
	result := a.finalizeAgentHookAnswer(persistCtx, req.ConnectorName, req, resp,
		p.RawEventIDs, nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra, false)
	if !result.AuditPersisted || !result.DecisionSettled {
		// Stable IDs make the next try skip whichever record landed.
		return fmt.Errorf("%w: audit=%t hook_decision=%t", errPendingHookNotWritten, result.AuditPersisted, result.DecisionSettled)
	}
	return nil
}

// evictPendingHook deletes a journal row recovery gives up on, so the
// journal always drains, and leaves one record of it that adds no verdict
// to a call that may have one:
//   - A call no record of which can exist anywhere is audited as one
//     unconfirmed-evicted connector row under id+"-evicted", an ID no other
//     record has. That is a readable row that never pinned a verdict (its
//     records left only once stored, RemoteExportAfterLocalWrite) and whose
//     records the store does not hold.
//   - Any other call may hold its verdict already: a record of it is stored
//     (a partial write), or its pinned verdict left for the remote
//     destinations although the store refused it (GAP-1536), or the row
//     cannot be read, or the store cannot say. Its eviction is an
//     audit-health alert naming the call, the records the store holds and
//     the pinned verdict, never a connector row.
//
// The row is deleted even when the store refuses that record, which still
// leaves for the remote destinations. pinned says the row's verdict is
// pinned in the journal row. The error is that of the deletion: the row is
// then still there, and a later pass evicts it again without a second
// record.
func (a *APIServer) evictPendingHook(ctx context.Context, id string, p *pendingHookOccurrence, pinned bool, cause string) error {
	evictedID := id + "-evicted"
	stored, known := a.storedPendingHookRecords(ctx, id, id+"-decision", evictedID)
	persistCtx := ctx
	if p != nil {
		persistCtx = audit.ContextWithEnvelope(ctx, p.Envelope)
		persistCtx = ContextWithAgentIdentity(persistCtx, p.Identity)
		persistCtx = enrichAgentHookContext(persistCtx, p.request())
	}
	switch {
	case known && len(stored) == 1 && stored[0] == evictedID:
		// An earlier eviction left its row and could not delete the journal row.
	case p != nil && !pinned && known && len(stored) == 0:
		req := p.request()
		env := HookAuditEnvelope{
			Action: pendingHookEvictedAction, Reason: "managed hook delivery evicted from the journal: " + cause,
			Connector: req.ConnectorName, Event: req.HookEventName, ElapsedMs: time.Duration(p.ElapsedNanos).Milliseconds(),
			BodyBytes: p.BodyBytes, RawEventIDs: p.RawEventIDs, EvaluationID: p.Proposed.EvaluationID,
			Extra: mergeHookEnvelopeExtra(map[string]string{"hook_delivery_id": id}, p.Extra),
		}
		env.Extra["hook_delivery_attempts"] = fmt.Sprint(p.Attempts)
		p.Provenance.stamp(&env)
		env.occurrenceID = evictedID
		if err := a.logConnectorHookAuditEnvelope(persistCtx, env); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s evicted; its audit row was refused locally: %v\n", id, err)
		}
	default:
		details := map[string]any{"hook_delivery_id": id, "cause": cause, "stored_records": strings.Join(stored, ",")}
		if !known {
			details["stored_records"] = "unknown"
		}
		if p != nil {
			details["connector"], details["hook_event"] = p.Request.ConnectorName, p.Request.HookEventName
			details["hook_delivery_attempts"] = p.Attempts
			if p.Decided != nil && pinned {
				details["hook_delivery_verdict"] = p.Decided.Action
			}
		}
		if a.logger != nil {
			if err := a.logger.LogAlertCtx(persistCtx, "hook_audit", "HIGH", pendingHookEvictedAlert, details); err != nil {
				fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s evicted; its audit-health alert was refused locally: %v\n", id, err)
			}
		}
	}
	if err := a.forgetPendingHook(ctx, id); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] hook delivery id=%s evicted; its journal row was not deleted: %v\n", id, err)
		return err
	}
	return nil
}

// storedPendingHookRecords is which of ids the store holds, and whether it
// could say for every one.
func (a *APIServer) storedPendingHookRecords(ctx context.Context, ids ...string) (stored []string, known bool) {
	for _, id := range ids {
		found, err := a.store.HasAuditEventID(ctx, id)
		if err != nil {
			return stored, false
		}
		if found {
			stored = append(stored, id)
		}
	}
	return stored, true
}

func (a *APIServer) forgetPendingHook(ctx context.Context, id string) error {
	if err := a.store.ForgetHookDelivery(ctx, id); err != nil {
		return err
	}
	delete(pendingHookUnrecordedTries, id)
	return nil
}

// pendingHookRecoveryVerdict is the verdict recovery pins for a row the live
// handler did not pin: a record of the occurrence that is already stored
// decides its missing companion, its reason included, so the two records of
// one call never disagree, and with neither stored the call has its
// no-receipt decision. A stored record whose verdict the row cannot rebuild
// is an error: the row stays until it is evicted, and no companion that
// disagrees with the stored record is written.
func (a *APIServer) pendingHookRecoveryVerdict(ctx context.Context, p *pendingHookOccurrence) (agentHookResponse, error) {
	for _, record := range []struct {
		id       string
		decision bool
	}{{p.ID, false}, {p.ID + "-decision", true}} {
		stored, found, err := a.store.StoredHookVerdict(ctx, record.id)
		if err != nil {
			return agentHookResponse{}, err
		}
		if !found {
			continue
		}
		if resp, ok := p.responseFor(stored, record.decision); ok {
			return resp, nil
		}
		return agentHookResponse{}, fmt.Errorf("the stored record %s holds a %q verdict its journal row cannot rebuild", record.id, stored.Action)
	}
	if p.Final != nil {
		if p.SandboxReceipt != nil && p.Final.Action == "block" {
			return failedClosedHookDelivery(p.SandboxReceipt.response(p.Proposed), hookexec.ManagedGatewayNoAnswerReason), nil
		}
		return p.Final.response(), nil
	}
	return p.NoReceipt.response(), nil
}

// responseFor is the occurrence's answer a stored record of it holds: one a
// live handler records (the acknowledged proposal, the no-receipt
// decision, unconfirmed, or a closed block: the hook refused the answer, or
// the gateway answered 503 and the hook took its closed fallback) whose
// action and reason, as that record stores them, are the stored ones. A
// hook_decision record (decision) keeps the reason up to
// hookDecisionReasonMaxBytes, a connector row keeps it cleaned of log
// injection.
func (p *pendingHookOccurrence) responseFor(stored audit.StoredHookVerdict, decision bool) (agentHookResponse, bool) {
	proposed := p.Proposed.response()
	candidates := []agentHookResponse{
		p.NoReceipt.response(), proposed, unconfirmedHookDelivery(proposed),
		failedClosedHookDelivery(proposed, hookexec.ManagedGatewayNoAnswerReason),
		failedClosedHookDelivery(proposed, hookDeliveryRejectedReason),
	}
	if p.SandboxReceipt != nil {
		received := p.SandboxReceipt.response(p.Proposed)
		candidates = append(candidates, received,
			failedClosedHookDelivery(received, hookexec.ManagedGatewayNoAnswerReason))
	}
	if p.Final != nil {
		candidates = append(candidates, p.Final.response())
	}
	for _, resp := range candidates {
		reason := sanitizeEnvelopeFreeForm(hookSourceReason(resp))
		if decision {
			reason, _ = hookV8OptionalText(hookSourceReason(resp), hookDecisionReasonMaxBytes).Get()
		}
		if strings.EqualFold(resp.Action, stored.Action) && reason == stored.Reason {
			return resp, true
		}
	}
	return agentHookResponse{}, false
}
