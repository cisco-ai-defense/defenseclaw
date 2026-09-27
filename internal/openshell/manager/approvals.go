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
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// Approval actors.
const (
	actorAutomatic = "automatic"
	actorOperator  = "operator"
	actorPolicy    = "policy"
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
		out.Endpoints = append(out.Endpoints, sandboxapi.ApprovalEndpoint{Host: host, Port: ep.Port, Protocol: ep.Protocol})
	}
	out.Protocol = protocol
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
			m.triageSandbox(ctx, b)
		}
	})
}

// triageSweep polls the drafts of every ready sandbox; draft notifications
// on the stream are not guaranteed.
func (m *Manager) triageSweep(ctx context.Context) {
	m.mu.Lock()
	var ready []*box
	for _, b := range m.boxes {
		if !b.creating && !b.deleted && b.phase == audit.SandboxPhaseReady {
			ready = append(ready, b)
		}
	}
	m.mu.Unlock()
	for _, b := range ready {
		if ctx.Err() != nil {
			return
		}
		m.triageSandbox(ctx, b)
	}
}

// triagePolicy is what triage judges a sandbox's proposals against.
func (m *Manager) triagePolicy(eff *packs.Effective) triage.Policy {
	cfg := m.config()
	return triage.Policy{
		Effective: eff, Feed: m.feedMatcher(), AgentProposals: cfg.OpenShell.Approvals.AgentProposalsEnabled(),
		Unblocked: cfg.OpenShell.Egress.Unblocked,
	}
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
	pol := m.triagePolicy(eff)
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
	for _, chunk := range fresh {
		if ctx.Err() != nil {
			return
		}
		p := triage.FromChunk(name, chunk)
		d := triage.Classify(p, pol)
		m.applyTriage(ctx, gw, b, bindingID, p, d)
	}
	if more {
		m.scheduleTriage(b)
	}
}

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
	if d.Verdict == triage.Ask && pending >= maxPendingApprovals {
		d.Verdict, d.Reason = triage.Reject, triage.ReasonTooManyPending
		d.Message = "too many proposals are waiting for you; this one was rejected"
	}
	a.decision = d
	prev := m.approvals[a.id]
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
		m.feed.Publish(sandboxapi.ActivityEvent{
			Kind: sandboxapi.ActivityEgressBlocked, Sandbox: p.Sandbox, Host: d.Host, Port: d.Port, Source: sandboxapi.SourceOpenShell,
			Category: string(d.Reason), Reason: string(d.Reason), Message: blockedMessage(d),
			Unblockable: d.Violation == nil && d.Reason == triage.ReasonBlocklisted,
		})
	default:
		a.status = sandboxapi.ApprovalPending
		m.storeApproval(a)
		m.feed.Publish(sandboxapi.ActivityEvent{
			Kind: sandboxapi.ActivityApprovalRequested, Sandbox: p.Sandbox, Host: d.Host, Port: d.Port,
			ApprovalID: a.id, Reason: string(d.Reason), Message: d.Message,
		})
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
		if other.status != sandboxapi.ApprovalPending && other.status != sandboxapi.ApprovalQueued && other.status != approvalDeciding {
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
	if err := m.tel.RecordSandboxApproval(ctx, ev); err != nil {
		m.logf("approval telemetry %s: %v", a.id, err)
	}
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
		applied := r.Err == nil && !r.Skipped && !r.Changed && !r.Stale && !r.Gone
		if b != nil && applied {
			b.rulesAdded++
		}
		if a != nil {
			a.resolvedAt = m.now().UTC()
			switch {
			case applied:
				a.status = sandboxapi.ApprovalApproved
			case r.Skipped:
				a.status = sandboxapi.ApprovalPending
			default:
				a.status = sandboxapi.ApprovalFailed
			}
		}
		m.mu.Unlock()
		if b != nil && (r.Changed || r.Stale) {
			// Decide the chunk again as it is now.
			m.retriage(b, r.Item.ChunkID)
		}
		if a == nil || b == nil {
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
		_ = m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
			Sandbox: ident, Operation: audit.SandboxPolicyRuleAdd, PolicyHash: r.PolicyHash, Actor: approvalActor(a.actor),
			Origin: originFor(a.actor), Target: a.decision.Host, Reason: "SANDBOX_APPROVAL", ChangeCount: 1, Timestamp: m.now(),
		})
		msg := "approved " + a.decision.Host
		if r.Forced {
			msg += " (applied while hooks were busy)"
		}
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
			Host: a.decision.Host, Port: a.decision.Port, Reason: a.actor, Message: msg})
	}
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
	p, chunkID := a.proposal, a.chunkID
	host, port := a.decision.Host, a.decision.Port
	m.mu.Unlock()
	if status != sandboxapi.ApprovalPending {
		return nil, sandboxapi.Errorf(sandboxapi.CodeConflict, "approval %s is already %s", id, status)
	}
	decided := false
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
		// approving applies every endpoint, port and allowed IP in it.
		if cur := triage.Classify(p, m.triagePolicy(eff)); cur.Verdict == triage.Reject {
			if cur.Violation != nil {
				return nil, m.violationError(ctx, cur.Violation, a.sandbox)
			}
			return nil, &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation, Message: cur.Message}
		}
		if err := triage.CheckProposal(eff, p, d.Always, m.feedMatcher()); err != nil {
			return nil, m.violationError(ctx, err, a.sandbox)
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
		m.mu.Unlock()
		decided = true
		m.batcher.Enqueue(triage.Item{Sandbox: a.sandbox, BindingID: bindingID, ChunkID: chunkID, Digest: p.Digest, Tag: a.id})
		res.Message = "approved; OpenShell applies it once the sandbox's hooks are quiet"
	case sandboxapi.DecisionReject:
		reason := strings.TrimSpace(d.Reason)
		if reason == "" {
			reason = "rejected by the operator"
		}
		if err := gw.Client.RejectDraftChunk(ctx, a.sandbox, chunkID, truncate(reason, 512)); err != nil && !openshell.IsNotFound(err) {
			return nil, upstream("reject proposal", err)
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
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
			Host: host, Port: port, Reason: "rejected", Message: "rejected " + host})
		res.Message = "rejected"
	default:
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "decision must be approve or reject")
	}
	m.mu.Lock()
	res.Approval = a.wire()
	m.mu.Unlock()
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
// or the user's network: those are opened per sandbox only.
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
		if a.status != sandboxapi.ApprovalPending && a.status != sandboxapi.ApprovalQueued && a.resolvedAt.Before(cutoff) {
			delete(m.approvals, id)
		}
	}
}

func packActionHarness(harness string) packs.Action {
	return packs.Action{Kind: packs.ActionHarness, Harness: harness}
}
