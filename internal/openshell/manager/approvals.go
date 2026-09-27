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

// approvalID names the ask for one destination of one sandbox. Every
// proposal OpenShell drafts for the same destination collapses into it.
func approvalID(sandbox, kind, host string, port int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", sandbox, kind, host, port)))
	return "ap_" + hex.EncodeToString(sum[:8])
}

func (a *approval) wire() sandboxapi.Approval {
	protocol := ""
	for _, ep := range a.proposal.Endpoints {
		if triage.NormalizeHost(ep.Host) == a.decision.Host {
			protocol = ep.Protocol
			break
		}
	}
	return sandboxapi.Approval{
		ID: a.id, Sandbox: a.sandbox, ChunkID: a.chunkID, Kind: a.decision.Kind, Host: a.decision.Host, Port: a.decision.Port,
		Protocol: protocol, Binary: a.proposal.Binary, Risky: a.decision.Risky, Reason: a.decision.Message,
		Rationale: a.proposal.Rationale, SecurityNotes: a.proposal.SecurityNotes, HitCount: a.proposal.HitCount,
		Status: a.status, CreatedAt: a.createdAt, ResolvedAt: a.resolvedAt,
	}
}

// batchApplier routes the batcher's approvals to the current gateway.
type batchApplier struct{ m *Manager }

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

// triageSandbox fetches a sandbox's pending proposals and decides the ones
// it has not seen yet.
func (m *Manager) triageSandbox(ctx context.Context, b *box) {
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
	pol := triage.Policy{Effective: eff, Feed: m.feedMatcher(), AgentProposals: m.config().OpenShell.Approvals.AgentProposalsEnabled()}
	for _, chunk := range draft.Chunks {
		if chunk.Status != "" && chunk.Status != "pending" {
			continue
		}
		m.mu.Lock()
		_, seen := b.seenChunks[chunk.ID]
		if !seen {
			if b.seenChunks == nil {
				b.seenChunks = map[string]struct{}{}
			}
			b.seenChunks[chunk.ID] = struct{}{}
		}
		m.mu.Unlock()
		if seen {
			continue
		}
		p := triage.FromChunk(name, chunk)
		d := triage.Classify(p, pol)
		m.applyTriage(ctx, gw, b, bindingID, p, d)
	}
}

func (m *Manager) applyTriage(ctx context.Context, gw *Gateway, b *box, bindingID string, p triage.Proposal, d triage.Decision) {
	a := &approval{
		id: approvalID(p.Sandbox, d.Kind, d.Host, d.Port), sandbox: p.Sandbox, chunkID: p.ChunkID, reviewToken: p.ReviewToken,
		decision: d, proposal: p, createdAt: m.now().UTC(),
	}
	m.mu.Lock()
	id := b.identity()
	pending := 0
	for _, other := range m.approvals {
		if other.sandbox == p.Sandbox && other.status == sandboxapi.ApprovalPending {
			pending++
		}
	}
	prev := m.approvals[a.id]
	var superseded string
	collapse := false
	switch {
	case prev != nil && prev.status == sandboxapi.ApprovalPending && d.Verdict == triage.Ask:
		// A newer proposal for a destination already waiting for the user:
		// keep one ask, pointing at the newest chunk (its review token is
		// the current one).
		superseded = prev.chunkID
		prev.chunkID, prev.reviewToken, prev.proposal = p.ChunkID, p.ReviewToken, p
		collapse = true
	case prev != nil && prev.status == sandboxapi.ApprovalRejected && d.Verdict == triage.Reject &&
		m.now().Sub(prev.resolvedAt) < collapseWindow:
		collapse = true
	}
	m.mu.Unlock()
	if collapse {
		reject := superseded
		reason := "superseded by a newer proposal for the same destination"
		if reject == "" {
			reject, reason = p.ChunkID, d.Message
		}
		if err := gw.Client.RejectDraftChunk(ctx, p.Sandbox, reject, truncate(reason, 512)); err != nil && !openshell.IsNotFound(err) && !openshell.IsConflict(err) {
			m.logf("reject proposal %s of %s: %v", reject, p.Sandbox, err)
		}
		return
	}
	if d.Verdict == triage.Ask && pending >= maxPendingApprovals {
		d.Verdict, d.Reason = triage.Reject, "too_many_pending"
		d.Message = "too many proposals are waiting for you; this one was rejected"
		a.decision = d
	}
	m.recordApproval(ctx, id, a, audit.SandboxApprovalRequested, "", "")
	switch d.Verdict {
	case triage.Approve:
		a.status, a.actor = sandboxapi.ApprovalQueued, actorAutomatic
		m.storeApproval(a)
		m.batcher.Enqueue(triage.Item{Sandbox: p.Sandbox, BindingID: bindingID, ChunkID: p.ChunkID, ReviewToken: p.ReviewToken, Tag: a.id})
	case triage.Reject:
		a.status, a.actor, a.resolvedAt = sandboxapi.ApprovalRejected, actorPolicy, m.now().UTC()
		m.storeApproval(a)
		if err := gw.Client.RejectDraftChunk(ctx, p.Sandbox, p.ChunkID, d.Message); err != nil && !openshell.IsNotFound(err) {
			m.logf("reject proposal %s of %s: %v", p.ChunkID, p.Sandbox, err)
		}
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
		b := m.boxes[r.Item.Sandbox]
		var ident audit.SandboxIdentity
		if b != nil {
			ident = b.identity()
			if r.PolicyVersion != 0 && b.sb != nil {
				b.sb.Status.CurrentPolicyVersion = r.PolicyVersion
				ident.PolicyVersion = r.PolicyVersion
			}
		}
		if a != nil {
			a.resolvedAt = m.now().UTC()
			switch {
			case r.Err != nil:
				a.status = sandboxapi.ApprovalFailed
			case r.Skipped:
				a.status = sandboxapi.ApprovalPending
			default:
				a.status = sandboxapi.ApprovalApproved
			}
		}
		m.mu.Unlock()
		if a == nil || b == nil {
			continue
		}
		switch {
		case r.Err != nil:
			m.logf("apply approval %s of %s: %v", a.id, a.sandbox, r.Err)
			m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalCancelled, a.actor)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: a.decision.Host, Port: a.decision.Port, Reason: "apply_failed", Message: "the approval could not be applied: " + truncate(r.Err.Error(), 200)})
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
	host, port := a.decision.Host, a.decision.Port
	res := &sandboxapi.ApprovalResult{}
	switch strings.ToLower(strings.TrimSpace(d.Decision)) {
	case sandboxapi.DecisionApprove:
		if d.Always && a.decision.Kind == triage.KindHostPort {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "host ports are opened per sandbox; use --host-port %d for future sandboxes", port)
		}
		if err := triage.CheckApproval(eff, host, port, d.Always, m.feedMatcher()); err != nil {
			return nil, m.violationError(ctx, err, a.sandbox)
		}
		if d.Always {
			if err := m.persistAllow(ctx, host); err != nil {
				return nil, err
			}
			res.Persisted = true
		}
		m.mu.Lock()
		a.status, a.actor, a.always = sandboxapi.ApprovalQueued, actorOperator, d.Always
		m.mu.Unlock()
		decided = true
		m.batcher.Enqueue(triage.Item{
			Sandbox: a.sandbox, BindingID: bindingID, ChunkID: a.chunkID, ReviewToken: a.reviewToken,
			Single: a.proposal.SecurityNotes != "", Tag: a.id,
		})
		res.Message = "approved; OpenShell applies it once the sandbox's hooks are quiet"
	case sandboxapi.DecisionReject:
		reason := strings.TrimSpace(d.Reason)
		if reason == "" {
			reason = "rejected by the operator"
		}
		if err := gw.Client.RejectDraftChunk(ctx, a.sandbox, a.chunkID, truncate(reason, 512)); err != nil && !openshell.IsNotFound(err) {
			return nil, upstream("reject proposal", err)
		}
		if d.Always && a.decision.Kind == triage.KindNetworkRule {
			if err := m.persistBlock(ctx, host); err != nil {
				return nil, err
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
