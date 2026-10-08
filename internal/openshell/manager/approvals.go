// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// Approval actors, the Reason of an applied approval's feed event.
const (
	actorAutomatic = sandboxapi.ApprovedAutomatically
	actorOperator  = sandboxapi.ApprovedByOperator
	actorPolicy    = sandboxapi.ApprovedByPolicy
)

// maxPendingApprovals bounds asks per sandbox so a proposal flood cannot
// grow the table without limit; further asks are rejected.
const maxPendingApprovals = 64

// Proposal flood limits, per sandbox. Every approval that lands is an
// OpenShell policy reload, which closes all of the sandbox's connections,
// and an in-sandbox agent can draft proposals as fast as it likes.
const (
	// autoApproveBurst automatic approvals are allowed per
	// autoApproveWindow; further proposals ask the user.
	autoApproveBurst  = 20
	autoApproveWindow = 10 * time.Minute
	// maxRulesPerSession bounds the rules approvals add between two starts
	// of a sandbox; beyond it triage rejects new proposals (the operator can
	// still approve asks already queued).
	maxRulesPerSession = 100
	// rejectBurst rejections per rejectWindow are recorded and shown;
	// further ones are rejected quietly, with one notice per window.
	rejectBurst  = 20
	rejectWindow = 10 * time.Minute
	// maxTriagePerPass bounds the new proposals one draft poll decides; the
	// next poll takes the rest.
	maxTriagePerPass = 32
)

// collapseWindow is how long a rejected destination's new proposals are
// rejected quietly, without another record or feed line. OpenShell drafts a
// fresh proposal whenever the agent retries a denied connection.
const collapseWindow = 10 * time.Minute

// approvalDeciding marks an approval an operator decision is being applied
// to, so two concurrent decisions cannot both proceed.
const approvalDeciding = "deciding"

// approval is one draft proposal the manager is tracking.
type approval struct {
	id          string
	sandbox     string
	chunkID     string
	reviewToken string
	decision    triage.Decision
	proposal    triage.Proposal
	status      string
	always      bool
	actor       string
	createdAt   time.Time
	resolvedAt  time.Time
	// deferrals counts the apply-time checks of an operator approval that
	// could not be made (triage.ErrDeferred) since it was queued.
	deferrals int
	// local marks an ask DefenseClaw raised itself, with no OpenShell
	// draft chunk behind it (hostPortAsk): approving merges its rule into
	// the sandbox policy directly (applyHostPortAsk).
	local bool
}

// approvalID names the ask for one proposed rule of one sandbox: a digest
// of everything approving it would add (rule name, every endpoint and port,
// allowed IPs, binaries). Only proposals of exactly the same rule collapse
// into one ask, so a newer proposal can never slip different endpoints or
// binaries under an ask the user already read.
func approvalID(sandbox, ruleDigest string) string {
	sum := sha256.Sum256([]byte(sandbox + "\x00" + ruleDigest))
	return "ap_" + hex.EncodeToString(sum[:8])
}

// unresolved reports whether an ask still waits on the operator, on a
// decision being applied, or on OpenShell applying it. Unresolved asks have
// no resolvedAt and are never evicted or pruned.
func (a *approval) unresolved() bool {
	return a.status == sandboxapi.ApprovalPending || a.status == sandboxapi.ApprovalQueued || a.status == approvalDeciding
}

func (a *approval) wire() sandboxapi.Approval {
	p := a.proposal
	protocol := ""
	out := sandboxapi.Approval{
		ID: a.id, Sandbox: a.sandbox, ChunkID: a.chunkID, Kind: a.decision.Kind, Host: a.decision.Host, Port: a.decision.Port,
		Binary: p.Binary, Risky: a.decision.Risky, Reason: a.decision.Message,
		Rationale: p.Rationale, SecurityNotes: p.SecurityNotes, HitCount: p.HitCount,
		RuleName: p.RuleName, AllowedIPs: append([]string(nil), p.AllowedIPs...), Binaries: append([]string(nil), p.Binaries...),
		Status: a.status, CreatedAt: a.createdAt, ResolvedAt: a.resolvedAt,
	}
	for _, ep := range p.Endpoints {
		host := triage.NormalizeHost(ep.Host)
		if protocol == "" && host == a.decision.Host {
			protocol = ep.Protocol
		}
		out.Endpoints = append(out.Endpoints, sandboxapi.ApprovalEndpoint{Host: sandboxapi.DisplayText(host), Port: ep.Port,
			Protocol: sandboxapi.DisplayText(ep.Protocol)})
	}
	out.Protocol = sandboxapi.DisplayText(protocol)
	// The proposal is the agent's (and the policy advisor's) text; the CLI
	// prints it on the user's terminal.
	for _, s := range []*string{&out.Host, &out.Binary, &out.Reason, &out.Rationale, &out.SecurityNotes, &out.RuleName} {
		*s = sandboxapi.DisplayText(*s)
	}
	out.AllowedIPs, out.Binaries = sandboxapi.DisplayTexts(out.AllowedIPs), sandboxapi.DisplayTexts(out.Binaries)
	return out
}

// batchApplier routes the batcher's approvals to the current gateway.
type batchApplier struct{ m *Manager }

func (a batchApplier) GetDraft(ctx context.Context, sandbox, status string) (*openshell.DraftPolicy, error) {
	gw, err := a.m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	return gw.Client.GetDraft(ctx, sandbox, status)
}

func (a batchApplier) ApproveDraftChunks(ctx context.Context, sandbox string, approvals []openshell.DraftChunkApproval) (*openshell.ApproveAllResult, error) {
	gw, err := a.m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	return gw.Client.ApproveDraftChunks(ctx, sandbox, approvals)
}

func (a batchApplier) ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*openshell.ApproveResult, error) {
	gw, err := a.m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	return gw.Client.ApproveDraftChunk(ctx, sandbox, chunkID, reviewToken)
}

// triageDelay is how long after a denied connection the drafted proposal is
// looked for: the supervisor flushes its denial analysis every few seconds.
var triageDelay = 12 * time.Second

// scheduleTriage polls a sandbox's drafts once, triageDelay from now,
// unless a poll is already pending.
func (m *Manager) scheduleTriage(b *box) {
	ctx := m.running()
	if ctx == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.triageTimer != nil || b.deleted {
		return
	}
	b.triageTimer = time.AfterFunc(triageDelay, func() {
		m.mu.Lock()
		b.triageTimer = nil
		gone := b.deleted
		m.mu.Unlock()
		if !gone && ctx.Err() == nil {
			m.triageNow(b)
		}
	})
}

// triageNow polls a sandbox's drafts at once on a goroutine of its own.
// The stream's receive loop and the Run loop hand their polls off to it:
// a pass resolves the destinations the agent's proposals name (up to
// triagePassBudget), which must hold neither the sandbox's event stream,
// whose server drops what a lagging receiver misses, nor the Run loop's
// reconciliation and checks, nor the other sandboxes' polls. A request
// while a pass runs makes one more pass after it.
func (m *Manager) triageNow(b *box) {
	ctx := m.running()
	if ctx == nil {
		return
	}
	m.mu.Lock()
	if b.deleted {
		m.mu.Unlock()
		return
	}
	if b.triageBusy {
		b.triageAgain = true
		m.mu.Unlock()
		return
	}
	b.triageBusy = true
	m.mu.Unlock()
	go func() {
		for {
			m.triageSandbox(ctx, b)
			m.mu.Lock()
			again := b.triageAgain && !b.deleted && ctx.Err() == nil
			b.triageAgain, b.triageBusy = false, again
			m.mu.Unlock()
			if !again {
				return
			}
		}
	}()
}

// triageSweep polls the drafts of every ready sandbox (triageNow); draft
// notifications on the stream are not guaranteed.
func (m *Manager) triageSweep() {
	m.mu.Lock()
	var ready []*box
	for _, b := range m.boxes {
		if !b.creating && !b.deleted && b.phase == audit.SandboxPhaseReady {
			ready = append(ready, b)
		}
	}
	m.mu.Unlock()
	for _, b := range ready {
		m.triageNow(b)
	}
}

// triagePolicy is what triage judges a sandbox's proposals against: its
// resolved policy and the same decider, principal and unblocks its proxy
// credential carries, so a direct rule is approved only where the proxy
// would let the sandbox through.
func (m *Manager) triagePolicy(b *box, eff *packs.Effective) triage.Policy {
	cfg := m.config()
	m.mu.Lock()
	d := b.decider
	if b.eff != eff {
		d = nil
	}
	rec := b.rec
	m.mu.Unlock()
	if d == nil {
		d, _ = m.egressDecider(cfg, eff)
	}
	return triage.Policy{
		Effective: eff, Decider: d, Principal: m.principal(rec.BindingID, scopeID(rec.ID, rec.Name), rec.Name, d, eff),
		Resolver: m.opts.Resolver, AgentProposals: cfg.OpenShell.Approvals.AgentProposalsEnabled(),
		HarnessFetches: harnessFetches(rec.Harness),
	}
}

// harnessFetchHost reports host (and port, 0 when unknown) as one of the
// harness's own background requests it does without
// (harness.Spec.DirectFetches). The egress proxy's refusal of one is
// audited (at INFO, decision code audit.SandboxEgressCodeHarnessFetch, which
// keeps it off the alerts) but, like OpenShell's (harnessFetchDenial),
// neither shown on the feed nor counted as a blocked site, a destination or
// shadow AI: the proxy cannot tell the harness's request from a tool's, so
// the host decides.
func harnessFetchHost(harnessName, host string, port int) bool {
	host = triage.NormalizeHost(host)
	for _, f := range harnessFetches(harnessName) {
		if host == triage.NormalizeHost(f.Host) && (port == 0 || port == f.Port) {
			return true
		}
	}
	return false
}

// harnessFetches are the requests the sandbox's harness makes on its own
// that it does without (harness.Spec.DirectFetches).
func harnessFetches(name string) []triage.HarnessFetch {
	spec, ok := harness.Get(name)
	if !ok {
		return nil
	}
	var out []triage.HarnessFetch
	for _, f := range spec.DirectFetches() {
		out = append(out, triage.HarnessFetch{BinaryRoot: spec.InstallRoot(), Host: f.Host, Port: f.Port, What: f.What})
	}
	return out
}

// recheckApproval judges an approval again right before the batcher applies
// it (triage.BatcherOptions.Recheck), against the chunk as it is then, the
// current policy and fresh DNS answers: an automatic approval must still be
// approved automatically, an operator's must still not be rejected.
func (m *Manager) recheckApproval(ctx context.Context, it triage.Item, chunk openshell.PolicyChunk) error {
	id, _ := it.Tag.(string)
	m.mu.Lock()
	a, b := m.approvals[id], m.boxes[it.Sandbox]
	operator, always := false, false
	if a != nil {
		operator, always = a.actor == actorOperator, a.always
	}
	m.mu.Unlock()
	if b == nil {
		return errors.New("the sandbox is gone")
	}
	eff, err := m.resolveBox(b)
	if err != nil {
		// The sandbox fails closed until its policy resolves again; the
		// approval waits instead of being refused for good.
		return fmt.Errorf("%w: the sandbox policy cannot be resolved: %v", triage.ErrDeferred, err)
	}
	p := triage.FromChunk(it.Sandbox, chunk)
	d := triage.Classify(ctx, p, m.triagePolicy(b, eff))
	switch {
	case d.Verdict == triage.Reject:
		return errors.New(d.Message)
	case d.Verdict == triage.Defer:
		return fmt.Errorf("%w: %s", triage.ErrDeferred, d.Message)
	case d.Verdict == triage.Ask && !operator:
		return errors.New("it needs the user's approval now: " + d.Message)
	}
	if operator {
		return triage.CheckProposal(eff, p, always)
	}
	return nil
}

// triageSandbox fetches a sandbox's pending proposals and decides the ones
// it has not seen yet.
func (m *Manager) triageSandbox(ctx context.Context, b *box) {
	b.triageMu.Lock()
	defer b.triageMu.Unlock()
	gw, err := m.gateway(ctx)
	if err != nil {
		return
	}
	m.mu.Lock()
	name, bindingID, eff := b.rec.Name, b.rec.BindingID, b.eff
	m.mu.Unlock()
	if eff == nil {
		if eff, err = m.resolveBox(b); err != nil {
			return
		}
	}
	draft, err := gw.Client.GetDraft(ctx, name, "pending")
	if err != nil {
		if !openshell.IsNotFound(err) {
			m.logf("draft proposals of %s: %v", name, err)
		}
		return
	}
	pol := m.triagePolicy(b, eff)
	// seenChunks tracks the inbox's pending chunks only: a decided chunk
	// leaves the pending list and its entry goes with it.
	pending := make(map[string]bool, len(draft.Chunks))
	for _, chunk := range draft.Chunks {
		pending[chunk.ID] = true
	}
	var fresh []openshell.PolicyChunk
	more := false
	m.mu.Lock()
	if b.seenChunks == nil {
		b.seenChunks = map[string]struct{}{}
	}
	for id := range b.seenChunks {
		if !pending[id] {
			delete(b.seenChunks, id)
		}
	}
	for _, chunk := range draft.Chunks {
		if chunk.Status != "" && chunk.Status != "pending" {
			continue
		}
		if _, seen := b.seenChunks[chunk.ID]; seen {
			continue
		}
		if len(fresh) == maxTriagePerPass {
			more = true
			break
		}
		b.seenChunks[chunk.ID] = struct{}{}
		fresh = append(fresh, chunk)
	}
	m.mu.Unlock()
	// Classify resolves destination names; a slow resolver must not hold
	// the pass (and the Run loop that sweeps) for long. Chunks the budget
	// leaves undecided wait for the next poll instead of being rejected as
	// unresolvable.
	pass, cancel := context.WithTimeout(ctx, triagePassBudget)
	defer cancel()
	for i, chunk := range fresh {
		if ctx.Err() != nil {
			return
		}
		p := triage.FromChunk(name, chunk)
		d := triage.Classify(pass, p, pol)
		if pass.Err() != nil && ctx.Err() == nil {
			m.mu.Lock()
			for _, c := range fresh[i:] {
				delete(b.seenChunks, c.ID)
			}
			m.mu.Unlock()
			more = true
			break
		}
		if d.Verdict == triage.Defer {
			// A lookup timed out or failed temporarily: the chunk stays
			// pending in OpenShell and the next sweep decides it again.
			m.mu.Lock()
			delete(b.seenChunks, chunk.ID)
			m.mu.Unlock()
			m.logf("triage of %s proposal %s deferred: %s", name, chunk.ID, d.Message)
			continue
		}
		m.applyTriage(ctx, gw, b, bindingID, p, d)
	}
	if more {
		m.scheduleTriage(b)
	}
}

// triagePassBudget bounds one draft poll's decisions, DNS lookups included.
var triagePassBudget = 45 * time.Second

// retriage forgets that a chunk was decided, so the next poll decides it
// again, and schedules that poll.
func (m *Manager) retriage(b *box, chunkID string) {
	m.mu.Lock()
	delete(b.seenChunks, chunkID)
	m.mu.Unlock()
	m.scheduleTriage(b)
}

// recent drops the times before cutoff.
func recent(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}

func (m *Manager) applyTriage(ctx context.Context, gw *Gateway, b *box, bindingID string, p triage.Proposal, d triage.Decision) {
	now := m.now()
	a := &approval{
		id: approvalID(p.Sandbox, p.RuleDigest), sandbox: p.Sandbox, chunkID: p.ChunkID, reviewToken: p.ReviewToken,
		decision: d, proposal: p, createdAt: now.UTC(),
	}
	m.mu.Lock()
	pending, queued := 0, 0
	for _, other := range m.approvals {
		if other.sandbox != p.Sandbox {
			continue
		}
		switch other.status {
		case sandboxapi.ApprovalPending:
			pending++
		case sandboxapi.ApprovalQueued:
			queued++
		}
	}
	// Flood limits apply to what triage decides on its own.
	switch {
	case d.Verdict != triage.Reject && b.rulesAdded+queued >= maxRulesPerSession:
		d.Verdict, d.Reason = triage.Reject, triage.ReasonRuleLimit
		d.Message = fmt.Sprintf("the sandbox already added %d rules this session; restart it to approve more", b.rulesAdded+queued)
	case d.Verdict == triage.Approve:
		b.autoApproved = recent(b.autoApproved, now.Add(-autoApproveWindow))
		if len(b.autoApproved) >= autoApproveBurst {
			d.Verdict, d.Reason = triage.Ask, triage.ReasonRateLimited
			d.Message = "the sandbox proposed many new destinations in a short time; approve to open " + d.Host
		}
	}
	prev := m.approvals[a.id]
	// A proposal of a rule already asked about collapses into that ask
	// (below) and adds none, so the cap does not apply to it: applying it
	// would reject the ask the user may be reading.
	if d.Verdict == triage.Ask && pending >= maxPendingApprovals && (prev == nil || prev.status != sandboxapi.ApprovalPending) {
		d.Verdict, d.Reason = triage.Reject, triage.ReasonTooManyPending
		d.Message = "too many proposals are waiting for you; this one was rejected"
	}
	a.decision = d
	var superseded, duplicate string
	collapse := false
	switch {
	case prev != nil && prev.status == sandboxapi.ApprovalPending && d.Verdict == triage.Ask:
		// The same rule proposed again while the user has not decided: keep
		// one ask, on the newest chunk. The content is identical (the ID is
		// its digest); the decision is refreshed.
		if prev.chunkID != p.ChunkID {
			superseded = prev.chunkID
		}
		prev.chunkID, prev.reviewToken, prev.proposal, prev.decision = p.ChunkID, p.ReviewToken, p, d
		collapse = true
	case prev != nil && (prev.status == sandboxapi.ApprovalQueued || prev.status == approvalDeciding) && d.Verdict != triage.Reject:
		// The same rule is being approved already.
		duplicate = "a proposal for the same rule is already being applied"
	case prev != nil && prev.status == sandboxapi.ApprovalRejected && d.Verdict == triage.Reject &&
		now.Sub(prev.resolvedAt) < collapseWindow:
		duplicate = d.Message
	case prev != nil && prev.status == sandboxapi.ApprovalRejected && prev.actor == actorOperator &&
		now.Sub(prev.resolvedAt) < collapseWindow:
		// The user just rejected exactly this rule; the agent proposing it
		// again does not ask again.
		duplicate = "the user rejected this proposal"
	case prev != nil && prev.status == sandboxapi.ApprovalPending:
		// The rule's verdict changed (the policy did): resolve the old ask's
		// chunk and decide the new one.
		superseded = prev.chunkID
	}
	quiet := false
	if d.Verdict == triage.Reject && duplicate == "" {
		b.rejected = recent(b.rejected, now.Add(-rejectWindow))
		if len(b.rejected) >= rejectBurst {
			quiet = true
			b.quietRejects++
		} else {
			b.rejected = append(b.rejected, now)
			b.quietRejects = 0
		}
	}
	if d.Verdict == triage.Approve && duplicate == "" && !collapse {
		b.autoApproved = append(b.autoApproved, now)
	}
	firstQuiet := quiet && b.quietRejects == 1
	id := b.identity()
	m.mu.Unlock()

	if superseded != "" {
		m.rejectChunk(ctx, gw, p.Sandbox, superseded, "superseded by a newer proposal for the same rule")
	}
	if collapse {
		return
	}
	if duplicate != "" {
		m.rejectChunk(ctx, gw, p.Sandbox, p.ChunkID, duplicate)
		return
	}
	if quiet {
		a.status, a.actor, a.resolvedAt = sandboxapi.ApprovalRejected, actorPolicy, now.UTC()
		m.storeApproval(a)
		m.rejectChunk(ctx, gw, p.Sandbox, p.ChunkID, d.Message)
		if firstQuiet {
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: p.Sandbox, Source: sandboxapi.SourceOpenShell,
				Reason: "rate_limited", Message: fmt.Sprintf("%s is proposing many blocked destinations; further rejections are not shown for %s",
					p.Sandbox, rejectWindow)})
		}
		return
	}
	m.recordApproval(ctx, id, a, audit.SandboxApprovalRequested, "", "")
	switch d.Verdict {
	case triage.Approve:
		a.status, a.actor = sandboxapi.ApprovalQueued, actorAutomatic
		m.storeApproval(a)
		m.batcher.Enqueue(triage.Item{Sandbox: p.Sandbox, BindingID: bindingID, ChunkID: p.ChunkID, Digest: p.Digest, Tag: a.id})
	case triage.Reject:
		a.status, a.actor, a.resolvedAt = sandboxapi.ApprovalRejected, actorPolicy, now.UTC()
		m.storeApproval(a)
		m.rejectChunk(ctx, gw, p.Sandbox, p.ChunkID, d.Message)
		m.recordApproval(ctx, id, a, audit.SandboxApprovalResolved, audit.SandboxApprovalDenied, actorPolicy)
		if d.Port == 22 {
			// SSH out of a sandbox: OpenShell's denial is on the feed
			// already, saying what to do instead; a second line for the
			// one attempt, with another reason, would only confuse.
			return
		}
		m.feed.Publish(sandboxapi.ActivityEvent{
			Kind: sandboxapi.ActivityEgressBlocked, Sandbox: p.Sandbox, Host: d.Host, Port: d.Port, Source: sandboxapi.SourceOpenShell,
			Category: string(d.Reason), Reason: string(d.Reason), Message: blockedMessage(d),
			Unblockable: d.Violation == nil && d.Unblockable,
		})
	default:
		a.status = sandboxapi.ApprovalPending
		m.storeApproval(a)
		m.feed.Publish(sandboxapi.ActivityEvent{
			Kind: sandboxapi.ActivityApprovalRequested, Sandbox: p.Sandbox, Host: d.Host, Port: d.Port,
			ApprovalID: a.id, Reason: string(d.Reason), Message: d.Message,
		})
		// The agent's next hook says the connection waits for the user
		// (GAP-0268).
		m.refusals.noteDirect(bindingID, p.Sandbox, triage.NormalizeHost(d.Host), d.Port, NoteAsked, now)
	}
}

// rejectChunk rejects one draft chunk; a chunk already decided or gone is
// not an error.
func (m *Manager) rejectChunk(ctx context.Context, gw *Gateway, sandbox, chunkID, reason string) {
	if err := gw.Client.RejectDraftChunk(ctx, sandbox, chunkID, truncate(reason, 512)); err != nil &&
		!openshell.IsNotFound(err) && !openshell.IsConflict(err) {
		m.logf("reject proposal %s of %s: %v", chunkID, sandbox, err)
	}
}

func blockedMessage(d triage.Decision) string {
	if d.Violation != nil && d.Violation.Admin() {
		return d.Host + " " + sandboxapi.AdminMessage
	}
	return d.Message
}

// maxTrackedApprovals bounds the approval table; the oldest resolved
// entries go first.
const maxTrackedApprovals = 4096

func (m *Manager) storeApproval(a *approval) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvals[a.id] = a
	if len(m.approvals) <= maxTrackedApprovals {
		return
	}
	resolved := make([]*approval, 0, len(m.approvals))
	for _, other := range m.approvals {
		if !other.unresolved() {
			resolved = append(resolved, other)
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].resolvedAt.Before(resolved[j].resolvedAt) })
	for _, old := range resolved {
		if len(m.approvals) <= maxTrackedApprovals {
			break
		}
		delete(m.approvals, old.id)
	}
}

// recordApproval emits one approval record. Callers must not hold m.mu.
func (m *Manager) recordApproval(ctx context.Context, id audit.SandboxIdentity, a *approval, stage audit.SandboxApprovalStage, result, actor string) {
	ev := audit.SandboxApprovalEvent{
		Sandbox: id, Stage: stage, ApprovalID: a.id, Kind: audit.SandboxApprovalKind(a.decision.Kind),
		Host: a.decision.Host, Port: a.decision.Port, Risky: a.decision.Risky, Reason: truncate(a.decision.Message, 512),
		Timestamp: m.now(),
	}
	if stage == audit.SandboxApprovalResolved {
		ev.Result, ev.ActorType = result, actor
		if result == audit.SandboxApprovalApproved {
			ev.Scope = audit.SandboxApprovalScopeSandbox
			if a.always {
				ev.Scope = audit.SandboxApprovalScopeAlways
			}
		}
	}
	m.tel.RecordSandboxApproval(ctx, ev)
}

// approvalsApplied receives the batcher's results.
func (m *Manager) approvalsApplied(results []triage.Result) {
	ctx := context.Background()
	for _, r := range results {
		id, _ := r.Item.Tag.(string)
		m.mu.Lock()
		a := m.approvals[id]
		if a != nil && a.chunkID != r.Item.ChunkID {
			a = nil // the approval moved on to another chunk
		}
		b := m.boxes[r.Item.Sandbox]
		var ident audit.SandboxIdentity
		if b != nil {
			ident = b.identity()
			if r.PolicyVersion != 0 && b.sb != nil {
				b.sb.Status.CurrentPolicyVersion = r.PolicyVersion
				ident.PolicyVersion = r.PolicyVersion
			}
		}
		applied := r.Err == nil && r.Refused == nil && !r.Skipped && !r.Changed && !r.Stale && !r.Gone
		deferred := r.Refused != nil && errors.Is(r.Refused, triage.ErrDeferred)
		if b != nil && applied {
			b.rulesAdded++
		}
		saveRules := b != nil && applied && a != nil && noteApprovedRule(b, a.proposal.RuleName, a.actor)
		retryApply := false
		if a != nil {
			a.resolvedAt = m.now().UTC()
			switch {
			case applied:
				a.status = sandboxapi.ApprovalApproved
			case r.Skipped:
				a.status = sandboxapi.ApprovalPending
			case deferred && a.actor == actorOperator:
				// The user's approval could not be checked (a DNS lookup
				// timed out, the policy did not resolve): try again a few
				// times, then hand it back to the user. The chunk stays
				// pending in OpenShell either way.
				// It stays the operator's (a.actor), so triage does not
				// decide the chunk over the user's head meanwhile.
				a.deferrals++
				if a.deferrals < maxApplyDeferrals {
					retryApply = true
				} else {
					a.status, a.deferrals = sandboxapi.ApprovalPending, 0
				}
			case r.Refused != nil && a.actor == actorOperator:
				a.status = sandboxapi.ApprovalRejected
			default:
				a.status = sandboxapi.ApprovalFailed
			}
		}
		m.mu.Unlock()
		if saveRules {
			if err := m.saveRecord(b); err != nil {
				m.logf("record the approved rule %s of %s: %v", a.proposal.RuleName, a.sandbox, err)
			}
		}
		if retryApply {
			m.retryApply(a, r.Item)
			continue
		}
		// Decide the chunk again as it is now: its content or the policy
		// changed, or an automatic approval no longer passes (triage then
		// rejects it or asks the user).
		retry := r.Changed || r.Stale || (r.Refused != nil && (a == nil || a.actor != actorOperator))
		if b != nil && retry {
			m.retriage(b, r.Item.ChunkID)
		}
		if a == nil || b == nil {
			continue
		}
		if deferred && a.status == sandboxapi.ApprovalPending {
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalRequested, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: a.decision.Host, Port: a.decision.Port, Reason: string(triage.ReasonLookupFailed),
				Message: "DefenseClaw could not check " + a.decision.Host + " before applying your approval (" +
					truncate(r.Refused.Error(), 200) + "); approve it again"})
			continue
		}
		fail := func(reason, msg string) {
			m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalCancelled, a.actor)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: a.decision.Host, Port: a.decision.Port, Reason: reason, Message: msg})
		}
		switch {
		case r.Err != nil:
			m.logf("apply approval %s of %s: %v", a.id, a.sandbox, r.Err)
			fail("apply_failed", "the approval could not be applied: "+truncate(r.Err.Error(), 200))
			continue
		case r.Refused != nil && a.actor == actorOperator:
			// The user approved it, but it no longer passes the policy (a
			// name that now resolves to this machine, say): reject it.
			msg := "not approved: " + truncate(r.Refused.Error(), 300)
			if gw, err := m.gateway(ctx); err == nil {
				m.rejectChunk(ctx, gw, a.sandbox, r.Item.ChunkID, msg)
			}
			m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalDenied, actorPolicy)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: a.decision.Host, Port: a.decision.Port, Reason: "refused_at_apply", Message: a.decision.Host + " " + msg})
			continue
		case deferred:
			fail(string(triage.ReasonLookupFailed), "DefenseClaw could not check "+a.decision.Host+" before applying it; it looks at it again")
			continue
		case r.Refused != nil:
			fail("refused_at_apply", "the approval of "+a.decision.Host+" no longer passes the policy; DefenseClaw looks at it again")
			continue
		case r.Changed:
			fail("changed", "the proposal for "+a.decision.Host+" changed after it was decided; DefenseClaw looks at it again")
			continue
		case r.Stale:
			fail("stale", "OpenShell's policy kept changing while "+a.decision.Host+" was being approved; DefenseClaw looks at it again")
			continue
		case r.Gone:
			fail("gone", "the proposal for "+a.decision.Host+" is no longer pending in OpenShell")
			continue
		case r.Skipped:
			// OpenShell left a flagged chunk out; it needs an explicit
			// operator approval, which goes through the single call.
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalRequested, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: a.decision.Host, Port: a.decision.Port, Reason: string(triage.ReasonSecurityFlagged), Message: "OpenShell flagged this proposal; approve it explicitly"})
			continue
		}
		m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalApproved, a.actor)
		m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
			Sandbox: ident, Operation: audit.SandboxPolicyRuleAdd, PolicyHash: r.PolicyHash, Actor: approvalActor(a.actor),
			Origin: originFor(a.actor), Target: a.decision.Host, Reason: policyReasonApproval, ChangeCount: 1, Timestamp: m.now(),
		})
		msg := "approved " + a.decision.Host
		if r.Forced {
			msg += " (applied while hooks were busy)"
		}
		m.refusals.forgetNote(r.Item.BindingID, triage.NormalizeHost(a.decision.Host), a.decision.Port, NoteAsked)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
			Host: a.decision.Host, Port: a.decision.Port, Reason: a.actor, Message: msg})
	}
}

// noteApprovedRule records who approved a triaged rule that was applied
// (record.ApprovedRules). A rule is the user's only while the user approved
// everything in it: approving merges a chunk into the rule of its name, so
// once DefenseClaw merged an approval of its own into a rule (another port
// or binary for the destination, before or after the user's), the rule is
// recorded as automatic and held to what the policy still approves on its
// own (enforceApprovedRules), and a user approval merged into an automatic
// rule leaves it automatic. Otherwise the endpoints DefenseClaw added
// would keep the user's authority after the policy tightened. It reports
// whether the record changed. Callers hold Manager.mu and save the record
// after releasing it.
func noteApprovedRule(b *box, rule, actor string) bool {
	if rule == "" {
		return false
	}
	origin := actorAutomatic
	if actor == actorOperator {
		origin = actorOperator
	}
	if cur, ok := b.rec.ApprovedRules[rule]; ok && (cur == origin || cur == actorAutomatic) {
		return false
	}
	next := maps.Clone(b.rec.ApprovedRules)
	if next == nil {
		next = map[string]string{}
	}
	next[rule] = origin
	b.rec.ApprovedRules = next
	return true
}

// maxApplyDeferrals bounds the apply attempts of an operator approval whose
// check could not be made; applyRetryDelay spaces them.
const maxApplyDeferrals = 3

var applyRetryDelay = 15 * time.Second

// retryApply queues an operator approval for the batcher again after
// applyRetryDelay, unless it was decided or moved on meanwhile.
func (m *Manager) retryApply(a *approval, it triage.Item) {
	time.AfterFunc(applyRetryDelay, func() {
		if m.running() == nil {
			return
		}
		m.mu.Lock()
		still := m.approvals[a.id] == a && a.status == sandboxapi.ApprovalQueued && a.chunkID == it.ChunkID
		m.mu.Unlock()
		if still {
			m.batcher.Enqueue(it)
		}
	})
}

func approvalActor(actor string) string {
	if actor == actorOperator {
		return "operator"
	}
	return "triage"
}

func originFor(actor string) string {
	if actor == actorOperator {
		return "api"
	}
	return "triage"
}

// Approvals lists the pending asks, optionally for one sandbox.
func (m *Manager) Approvals(_ context.Context, sandbox string) ([]sandboxapi.Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sandboxapi.Approval
	for _, a := range m.approvals {
		if a.status != sandboxapi.ApprovalPending || (sandbox != "" && a.sandbox != sandbox) {
			continue
		}
		out = append(out, a.wire())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// DecideApproval approves or rejects one ask. Every approval is checked
// against the sandbox's effective policy, re-resolved from the current
// configuration.
func (m *Manager) DecideApproval(ctx context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error) {
	m.mu.Lock()
	a := m.approvals[id]
	var b *box
	if a != nil {
		b = m.boxes[a.sandbox]
	}
	m.mu.Unlock()
	if a == nil || b == nil {
		return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "no pending approval %s", id)
	}
	m.mu.Lock()
	status := a.status
	bindingID := b.rec.BindingID
	if status == sandboxapi.ApprovalPending {
		a.status = approvalDeciding
	}
	// While deciding, triage leaves the approval's proposal alone.
	p, chunkID, local := a.proposal, a.chunkID, a.local
	host, port := a.decision.Host, a.decision.Port
	m.mu.Unlock()
	if status != sandboxapi.ApprovalPending {
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "approval %s is already %s", id, status)
	}
	decided, replied := false, false
	defer func() {
		if !decided {
			m.mu.Lock()
			if a.status == approvalDeciding {
				a.status = sandboxapi.ApprovalPending
			}
			m.mu.Unlock()
		}
	}()
	eff, err := m.resolveBox(b)
	if err != nil {
		return nil, err
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	hosts := networkHosts(p)
	res := &sandboxapi.ApprovalResult{}
	switch strings.ToLower(strings.TrimSpace(d.Decision)) {
	case sandboxapi.DecisionApprove:
		if d.Always {
			if err := alwaysApprovable(p); err != nil {
				return nil, err
			}
		}
		// The whole proposal is judged again against the current policy:
		// approving applies every endpoint, port and allowed IP in it. An
		// ask DefenseClaw raised itself is no agent proposal; the policy's
		// checks below judge it.
		var cur triage.Decision
		if !local {
			cur = triage.Classify(ctx, p, m.triagePolicy(b, eff))
			if cur.Verdict == triage.Reject {
				if cur.Violation != nil {
					return nil, m.violationErrorFor(ctx, cur.Violation, a.sandbox, audit.SandboxPolicyRuleAdd, host)
				}
				return nil, &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: cur.Message}
			}
		}
		if d.Always && cur.Verdict == triage.Ask && cur.Reason == triage.ReasonPrivateNetwork {
			// "Always" saves the host to openshell.egress.unblocked, and
			// the proxy's guard refuses private networks before any
			// unblock: every future sandbox would ask again.
			return nil, &sandboxapi.Error{Code: sandboxapi.CodeInvalid,
				Message: cur.Host + " is on your private network, which is opened per sandbox, not for future sandboxes",
				Detail:  "approve it for this sandbox, or add " + cur.Host + " to openshell.egress.allow to open it for every sandbox"}
		}
		if err := triage.CheckProposal(eff, p, d.Always); err != nil {
			return nil, m.violationErrorFor(ctx, err, a.sandbox, audit.SandboxPolicyRuleAdd, host)
		}
		if d.Always {
			for _, h := range hosts {
				if err := m.persistAllow(ctx, h); err != nil {
					return nil, err
				}
			}
			res.Persisted = true
		}
		m.mu.Lock()
		a.status, a.actor, a.always = sandboxapi.ApprovalQueued, actorOperator, d.Always
		queued := a.wire()
		m.mu.Unlock()
		decided = true
		if local {
			// The reply reports the decision as queued, like its message:
			// applyHostPortAsk may open the port (and resolve the approval)
			// before this returns when the hooks are already quiet.
			replied, res.Approval = true, queued
			go m.applyHostPortAsk(a, bindingID)
			res.Message = "approved; DefenseClaw opens the port once the sandbox's hooks are quiet"
			break
		}
		m.batcher.Enqueue(triage.Item{Sandbox: a.sandbox, BindingID: bindingID, ChunkID: chunkID, Digest: p.Digest, Tag: a.id})
		res.Message = "approved; OpenShell applies it once the sandbox's hooks are quiet"
	case sandboxapi.DecisionReject:
		reason := strings.TrimSpace(d.Reason)
		if reason == "" {
			reason = "rejected by the operator"
		}
		if chunkID != "" {
			if err := gw.Client.RejectDraftChunk(ctx, a.sandbox, chunkID, truncate(reason, 512)); err != nil && !openshell.IsNotFound(err) {
				return nil, upstream("reject proposal", err)
			}
		}
		if d.Always && len(hosts) > 0 {
			for _, h := range hosts {
				if err := m.persistBlock(ctx, h); err != nil {
					return nil, err
				}
			}
			res.Persisted = true
		}
		m.mu.Lock()
		a.status, a.actor, a.resolvedAt = sandboxapi.ApprovalRejected, actorOperator, m.now().UTC()
		ident := b.identity()
		m.mu.Unlock()
		decided = true
		m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalDenied, actorOperator)
		// The feed names the port as the approval does, the reply says what
		// the reject leaves, and the agent's next hook says the user
		// declined, not a network error (GAP-0236, GAP-0260).
		target := host
		if local {
			target = fmt.Sprintf("port %d on your machine (%s:%d)", port, host, port)
		}
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
			Host: host, Port: port, Reason: "rejected", Message: "rejected " + target})
		res.Message = fmt.Sprintf("%s stays closed to %s; its attempts in the next %s are refused without a new ask, and the one after that asks again",
			target, a.sandbox, packs.ShortDuration(collapseWindow))
		m.refusals.forgetNote(bindingID, triage.NormalizeHost(host), port, NoteAsked)
		m.refusals.noteDirect(bindingID, a.sandbox, triage.NormalizeHost(host), port, NoteDeclined, m.now())
	default:
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "decision must be approve or reject")
	}
	if !replied {
		m.mu.Lock()
		res.Approval = a.wire()
		m.mu.Unlock()
	}
	return res, nil
}

// networkHosts are a proposal's destination names outside this machine
// (what an "always" decision saves), each once.
func networkHosts(p triage.Proposal) []string {
	var out []string
	for _, ep := range p.Endpoints {
		host := triage.NormalizeHost(ep.Host)
		if host == "" || triage.IsHostLocal(host) || slices.Contains(out, host) {
			continue
		}
		out = append(out, host)
	}
	return out
}

// alwaysApprovable refuses "always" for proposals that reach this machine
// or the user's network as named: those are opened per sandbox only.
// DecideApproval also refuses names the current policy treats as private
// (intranet names, names that resolve to private addresses).
func alwaysApprovable(p triage.Proposal) error {
	for _, ep := range p.Endpoints {
		host := triage.NormalizeHost(ep.Host)
		if triage.IsHostLocal(host) {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "host ports are opened per sandbox; use --host-port %d for future sandboxes", ep.Port)
		}
		if addr, err := netip.ParseAddr(host); err == nil && triage.IsPrivate(addr) {
			return sandboxapi.Errorf(sandboxapi.CodeInvalid, "private network addresses are opened per sandbox, not for future sandboxes")
		}
	}
	if len(p.AllowedIPs) > 0 {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "proposals with allowed_ips are approved per sandbox, not for future sandboxes")
	}
	return nil
}

func (m *Manager) persistAllow(ctx context.Context, host string) error {
	if m.opts.Persist == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "always decisions cannot be saved: the configuration is not writable by the daemon")
	}
	if err := m.opts.Persist.AllowAlways(ctx, host); err != nil {
		return persistError(err)
	}
	return nil
}

func (m *Manager) persistBlock(ctx context.Context, host string) error {
	if m.opts.Persist == nil {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "always decisions cannot be saved: the configuration is not writable by the daemon")
	}
	if err := m.opts.Persist.BlockAlways(ctx, host); err != nil {
		return persistError(err)
	}
	return nil
}

func persistError(err error) error {
	var e *sandboxapi.Error
	if errors.As(err, &e) {
		return e
	}
	return &sandboxapi.Error{Code: sandboxapi.CodeInternal, Message: "save the decision to config.yaml", Detail: err.Error()}
}

func (m *Manager) dropApprovals(sandbox string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, a := range m.approvals {
		if a.sandbox == sandbox {
			delete(m.approvals, id)
		}
	}
}

// pruneApprovals forgets resolved approvals older than an hour.
func (m *Manager) pruneApprovals() {
	cutoff := m.now().Add(-time.Hour)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, a := range m.approvals {
		if !a.unresolved() && a.resolvedAt.Before(cutoff) {
			delete(m.approvals, id)
		}
	}
}

func packActionHarness(harness string) packs.Action {
	return packs.Action{Kind: packs.ActionHarness, Harness: harness}
}
