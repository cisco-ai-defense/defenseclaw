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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
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
	// proxy marks a local ask for a destination the egress proxy refused
	// as not on the allowlist (proxyAsk): approving it unblocks the host
	// for the sandbox (or, "always", for the person), as `sandbox unblock`
	// does, since the proxy, not an OpenShell rule, is what refused it.
	proxy bool
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
	if err := a.m.networkWithdrawn(sandbox); err != nil {
		return nil, err
	}
	gw, err := a.m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	return gw.Client.ApproveDraftChunks(ctx, sandbox, approvals)
}

func (a batchApplier) ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*openshell.ApproveResult, error) {
	if err := a.m.networkWithdrawn(sandbox); err != nil {
		return nil, err
	}
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
	m.mu.Lock()
	d := b.decider
	if b.eff != eff {
		d = nil
	}
	rec := b.rec
	m.mu.Unlock()
	cfg := m.configForSandbox(rec.Name)
	if cfg == nil {
		return triage.Policy{} // Classify refuses an unresolved policy.
	}
	if d == nil {
		d, _ = m.egressDeciderFor(cfg, eff, m.registrationOf(b))
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

// toolHostOf says what refusing host breaks for the harness harnessName,
// when a tool of the harness calls it on every use (harness.ToolHost).
func toolHostOf(harnessName, host string) (string, bool) {
	spec, ok := harness.Get(harnessName)
	if !ok {
		return "", false
	}
	return spec.ToolHostOf(triage.NormalizeHost(host))
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
		scope := sandboxrelay.DecisionScopeSession
		if always {
			scope = sandboxrelay.DecisionScopeAlways
		}
		if err := sandboxreg.CheckApprovals(m.floor(eff), sandboxrelay.DecisionEgressAllow, scope); err != nil {
			return err
		}
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
	m.mu.Lock()
	eff := b.eff
	m.mu.Unlock()
	// orgRefusal is the managed refusal the feed shows under a rejection
	// by the floor's rules (accessRefusal).
	orgRefusal, orgRule := "", ""
	if d.Verdict == triage.Ask {
		// An ask the floor doesn't let the user answer (user_approvals:
		// none) is refused at once, with the request-access contact,
		// instead of waiting for an approval that can't be given.
		f := m.floor(eff)
		var refusal *sandboxreg.DecisionRefusedError
		if err := sandboxreg.CheckApprovals(f, sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession); errors.As(err, &refusal) {
			d.Verdict, d.Reason = triage.Reject, triage.ReasonAdmin
			d.Message = d.Host + ": " + refusal.Message + ". Request access: " + requestAccess(f)
			orgRefusal, orgRule = m.accessRefusal(b, f, refusal.Message, refusal.Rule, d.Host), refusal.Rule
		}
	} else if rule := firstNonEmpty(d.AdminRule, adminRule(d.Violation)); d.Verdict == triage.Reject && rule != "" {
		orgRefusal, orgRule = m.accessRefusal(b, m.floor(eff), "", rule, d.Host), rule
	}
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
			Unblockable: d.Violation == nil && d.Unblockable, Refusal: orgRefusal,
		})
		if orgRefusal != "" {
			// The agent's next hook says it can't be approved and whom the
			// user asks (GAP-0502).
			m.refusals.noteRefused(bindingID, p.Sandbox, triage.NormalizeHost(d.Host), d.Port, orgRefusal, now)
			m.managedAccessRefused(ctx, b, triage.NormalizeHost(d.Host), d.Port, orgRule, accessRefusedProposal)
		}
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

// The gateway records approvals that reach its decisions route. A plain
// rejection and a floor-bounded attempt never reach it, so relay those two
// outcomes once under the sandbox's registered identity.
func (m *Manager) recordManagedAskDecision(ctx context.Context, b *box, a *approval, reason string) {
	if m.authority() == nil {
		return
	}
	m.mu.Lock()
	identity := b.identity()
	m.mu.Unlock()
	m.tel.RecordManagedAskDecision(ctx, audit.SandboxAskDecidedEvent{
		Sandbox: identity, ApprovalID: a.id, Kind: audit.SandboxApprovalKind(a.decision.Kind),
		Host: a.decision.Host, Port: a.decision.Port, Result: audit.SandboxApprovalDenied,
		Reason: reason, Timestamp: m.now(),
	})
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
			Sandbox: ident, Operation: audit.SandboxPolicyRuleAdd, PolicyHash: r.PolicyHash, Actor: m.actorRef(a.actor),
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
	p, chunkID, local, proxyAsk := a.proposal, a.chunkID, a.local, a.proxy
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
	m.confirmPolicy(ctx, a.sandbox)
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
		scope := sandboxrelay.DecisionScopeSession
		if d.Always {
			scope = sandboxrelay.DecisionScopeAlways
		}
		f := m.floor(eff)
		if err := sandboxreg.CheckApprovals(f, sandboxrelay.DecisionEgressAllow, scope); err != nil {
			m.recordAdminRefusal(ctx, a.sandbox, audit.SandboxPolicyRuleAdd, host)
			m.recordManagedAskDecision(ctx, b, a, "floor_denied")
			return nil, m.decisionRefusal(err, b, f, host)
		}
		if d.Always {
			if err := alwaysApprovable(p); err != nil {
				return nil, err
			}
		}
		if proxyAsk {
			// The proxy's own refusal. For the session it is an approval
			// (approveProxyAsk), which allow_unblock: false leaves the user;
			// "always" keeps the host for every sandbox as an unblock does.
			// Both check it against the policy and the floor, keep it with
			// the managed gateway and open the host in the sandbox's
			// decider at once.
			var msg string
			if d.Always {
				un, err := m.unblock(ctx, sandboxapi.UnblockRequest{Host: host, Sandbox: a.sandbox, Always: true}, a.id)
				if err != nil {
					return nil, err
				}
				msg = un.Message
			} else if msg, err = m.approveProxyAsk(ctx, b, eff, host, port, a.id); err != nil {
				return nil, err
			}
			m.mu.Lock()
			a.status, a.actor, a.always, a.resolvedAt = sandboxapi.ApprovalApproved, actorOperator, d.Always, m.now().UTC()
			ident := b.identity()
			m.mu.Unlock()
			decided, res.Persisted = true, d.Always
			m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalApproved, actorOperator)
			m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
				Host: host, Port: port, Reason: "approved", Message: "approved " + host})
			m.refusals.forgetNote(bindingID, triage.NormalizeHost(host), port, NoteAsked)
			res.Message = msg
			break
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
					return nil, m.decisionViolation(ctx, cur.Violation, b, eff, audit.SandboxPolicyRuleAdd, host)
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
		// The managed gateway re-checks the host against the floor,
		// records the person and keeps an "always"; outside managed mode an
		// "always" joins openshell.egress.unblocked. A host port reaches
		// the managed gateway too, for this session. An approval names one
		// host: triage refuses a proposal of more than one destination
		// host (ReasonMultipleHosts), above for an agent's proposal, and a
		// host-port ask has one endpoint.
		decisionHosts := hosts
		if m.authority() != nil {
			decisionHosts = managedDecisionHosts(p)
		}
		for _, h := range decisionHosts {
			decisionPort := 0
			if h == openshellHostAlias {
				decisionPort = port
			}
			stored, err := m.keepDecisionAt(ctx, b, sandboxrelay.DecisionEgressAllow, h, decisionPort, scope, a.id)
			if err != nil {
				return nil, err
			}
			res.Persisted = res.Persisted || stored
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
		if d.Always {
			// A user block only tightens: it is always kept.
			for _, h := range hosts {
				stored, err := m.keepDecision(ctx, b, sandboxrelay.DecisionEgressBlock, h, sandboxrelay.DecisionScopeAlways, a.id)
				if err != nil {
					return nil, err
				}
				res.Persisted = res.Persisted || stored
			}
		}
		m.mu.Lock()
		a.status, a.actor, a.resolvedAt = sandboxapi.ApprovalRejected, actorOperator, m.now().UTC()
		ident := b.identity()
		m.mu.Unlock()
		decided = true
		m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalDenied, actorOperator)
		if !d.Always || len(hosts) == 0 {
			m.recordManagedAskDecision(ctx, b, a, "")
		}
		// The feed names the port as the approval does, the reply says what
		// the reject leaves, and the agent's next hook says the user
		// declined, not a network error (GAP-0236, GAP-0260). Only a
		// host-port ask is a port on this machine; the egress proxy's ask
		// (proxyAsk, also local) is a destination outside it (GAP-0415).
		target := host
		switch {
		case local && !proxyAsk:
			target = fmt.Sprintf("port %d on your machine (%s:%d)", port, host, port)
		case port > 0:
			target = fmt.Sprintf("%s:%d", host, port)
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

// managedDecisionHosts are the hosts of a proposal the managed gateway
// decides: its network hosts, and this machine (the OpenShell host alias)
// when it opens a host port.
func managedDecisionHosts(p triage.Proposal) []string {
	out := networkHosts(p)
	for _, ep := range p.Endpoints {
		if triage.NormalizeHost(ep.Host) == openshellHostAlias {
			return append(out, openshellHostAlias)
		}
	}
	return out
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

// ManagedAuthority is the managed gateway as a managed host's sandbox
// daemon reaches it (sandboxrelay.Client has these methods): it re-checks
// the user's asks, unblocks and blocks against the user's floor and keeps
// the ones that last (POST and GET /api/v1/sandbox/decisions), and takes
// the daemon's records of foreign sandboxes, rules and containers (POST
// /api/v1/sandbox/events), stamping both with the person's identity. A
// Persist that implements it runs the manager in managed mode: no decision
// is written to a configuration then (the managed daemon's Persist is the
// gateway's sandboxDecisionsClient).
//
// Errors are *sandboxapi.Error values: sandboxapi.CodeConflict means the
// managed gateway no longer knows the registration (revoked, expired,
// unknown, or its account changed), and sandboxapi.CodeUnavailable that it
// could not be reached or was busy.
type ManagedAuthority interface {
	Decide(ctx context.Context, req sandboxrelay.DecisionRequest) (sandboxrelay.DecisionResult, error)
	Decisions(ctx context.Context, registration string) ([]sandboxrelay.Decision, error)
	Events(ctx context.Context, batch sandboxrelay.EventBatch) error
}

// RegistrationLookup is implemented by a ManagedAuthority that knows the
// managed registration of each of the daemon's sandboxes by name (the
// managed daemon keeps them from the bind that follows the create on). The
// manager records it on the sandbox the first time it needs it
// (registrationOf), so a sandbox whose record does not carry one yet is
// not taken for a foreign one.
type RegistrationLookup interface {
	SandboxRegistration(sandbox string) (string, bool)
}

// registrationOf is the managed registration of sandbox b: its record's,
// or the one the authority holds for its name (RegistrationLookup), which
// is then kept on the record. "" when it has none. Callers must not hold
// m.mu.
func (m *Manager) registrationOf(b *box) string {
	m.mu.Lock()
	name, registration := b.rec.Name, b.rec.RegistrationID
	m.mu.Unlock()
	if registration != "" {
		return registration
	}
	lookup, ok := m.opts.Persist.(RegistrationLookup)
	if !ok {
		return ""
	}
	if registration, ok = lookup.SandboxRegistration(name); !ok || registration == "" {
		return ""
	}
	m.mu.Lock()
	if b.rec.Name == name && b.rec.RegistrationID == "" {
		b.rec.RegistrationID = registration
	}
	m.mu.Unlock()
	return registration
}

// SetRegistration records registration as the managed registration of
// sandbox name in place of the one its record keeps: a start runs a
// stopped sandbox under a new registration (GAP-0673).
func (m *Manager) SetRegistration(name, registration string) {
	m.mu.Lock()
	b, ok := m.boxes[name]
	if !ok || b.deleted || b.rec.RegistrationID == registration {
		m.mu.Unlock()
		return
	}
	b.rec.RegistrationID = registration
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.logf("record the registration of sandbox %s: %v", name, err)
	}
}

// liveBoxes are the sandboxes the manager holds that are neither deleted
// nor kept as a snapshot.
func (m *Manager) liveBoxes() []*box {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.deleted && !b.retained {
			out = append(out, b)
		}
	}
	return out
}

// registrationGone reports an authority's answer that it no longer knows
// the registration (ManagedAuthority).
func registrationGone(err error) bool {
	return sandboxapi.IsCode(err, sandboxapi.CodeConflict)
}

// authority is the managed gateway, or nil outside managed mode.
func (m *Manager) authority() ManagedAuthority {
	a, _ := m.opts.Persist.(ManagedAuthority)
	return a
}

// managedMode reports a manager whose decisions the managed gateway keeps:
// a managed daemon's (authority), or one under a managed_enterprise
// configuration, which has no authority to keep them and so keeps none.
// It decides the egress default (deny), foreign sandboxes, rules and
// containers, and where decisions go.
func (m *Manager) managedMode() bool {
	return m.authority() != nil || managed.IsManagedEnterprise(m.config().DeploymentMode)
}

// floor is the floor F a sandbox's policy was resolved under: the loosest
// the sandbox may get, and what bounds the user's decisions, credentials
// and rules there. It is read from the sandbox's own resolved policy
// (effectiveFloor), so in managed mode it is the floor of the profile the
// sandbox's registration resolved, never the daemon's configuration. A
// managed sandbox whose policy carries no floor, and a managed call with
// no sandbox (eff nil), get closedFloor: nothing is approved, unblocked
// or handed over on a floor DefenseClaw does not know. Outside managed
// mode a policy without one is bounded by openshell.admin.
func (m *Manager) floor(eff *packs.Effective) config.OpenShellAdminConfig {
	if f, ok := effectiveFloor(eff); ok {
		return f
	}
	if m.managedMode() {
		return closedFloor()
	}
	return m.config().OpenShell.Admin
}

// effectiveFloor reads F from a resolved policy through the floor accessor
// of packs.Effective (Floor, which returns the Flags.Floor the policy was
// resolved under, or openshell.admin without one); ok is false for no
// policy, or one without the accessor. A variable so tests can give a
// sandbox a floor that differs from the daemon's configuration.
var effectiveFloor = func(eff *packs.Effective) (config.OpenShellAdminConfig, bool) {
	if eff == nil {
		return config.OpenShellAdminConfig{}, false
	}
	if fp, ok := any(eff).(interface {
		Floor() config.OpenShellAdminConfig
	}); ok {
		return fp.Floor(), true
	}
	return config.OpenShellAdminConfig{}, false
}

// closedFloor is the floor of a managed sandbox whose floor is unknown: no
// approvals, no credentials, no unblocks, no host ports, and foreign
// sandboxes stop.
func closedFloor() config.OpenShellAdminConfig {
	off := false
	return config.OpenShellAdminConfig{
		UserApprovals: config.OpenShellUserApprovalsNone, AllowedCredentials: []string{config.OpenShellCredentialsNone},
		AllowUnblock: &off, AllowHostPorts: &off, ForeignSandboxes: config.OpenShellForeignSandboxesStop,
	}
}

// requestAccess is the floor's request-access contact.
func requestAccess(f config.OpenShellAdminConfig) string {
	if s := strings.TrimSpace(f.RequestAccess); s != "" {
		return s
	}
	return config.OpenShellRequestAccessFallback
}

// decisionRefusal is the API error of a decision the floor refuses
// (sandboxreg.CheckDecision or CheckApprovals) for sandbox b: the managed
// refusal (accessRefusal) with the check's own words.
func (m *Manager) decisionRefusal(err error, b *box, f config.OpenShellAdminConfig, host string) error {
	var refusal *sandboxreg.DecisionRefusedError
	if !errors.As(err, &refusal) {
		return err
	}
	if refusal.Rule == sandboxreg.RuleInvalid {
		return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: strings.TrimPrefix(refusal.Message, sandboxapi.AdminMessage+": ")}
	}
	return accessRefusedError(m.accessRefusal(b, f, refusal.Message, refusal.Rule, host), refusal.Rule, host)
}

// Reason codes of the access_refused records (managedAccessRefused): which
// check refused the connection.
const (
	accessRefusedByProxy     = "egress_proxy"
	accessRefusedProposal    = "egress_proposal"
	accessRefusedRuleRemoved = "approved_rule_removed"
)

// managedAccessRefused records, for the managed gateway, a connection of
// b's sandbox that the organization's floor refused (rule): the gateway
// stamps the person and registration and emits
// event.sandbox.access_refused. The daemon's own egress telemetry is not
// kept on a managed computer, so a refusal the person saw in the activity
// feed left no audit record (GAP-0605). Outside managed mode it does
// nothing.
func (m *Manager) managedAccessRefused(ctx context.Context, b *box, host string, port int, rule, reason string) {
	if b == nil || m.authority() == nil {
		return
	}
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	m.managedEvent(ctx, m.registrationOf(b), sandboxrelay.EventAccessRefused, map[string]any{
		"sandbox": truncate(name, 128), "host": truncate(host, 253), "port": port, "rule": truncate(rule, 128), "reason": reason,
	})
}

// accessRefusedError is the API error of a managed refusal msg
// (accessRefusal) by rule: the message is complete, so the CLI prints it
// as it is (sandboxapi.IsPolicyRefusal), and the violation names the rule
// for the readers that branch on it.
func accessRefusedError(msg, rule, host string) *sandboxapi.Error {
	return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg,
		Violation: &sandboxapi.Violation{Key: "approvals", Attempted: host, Constraint: "openshell.admin." + rule, Admin: true,
			Message: msg}}
}

// ProfileLookup is implemented by a ManagedAuthority that knows the
// guardrail profile each of the daemon's sandboxes matched (the managed
// daemon's registrations): refusals name it and quote it.
type ProfileLookup interface {
	SandboxProfile(sandbox string) (string, bool)
}

// profileOf is the guardrail profile sandbox b's registration matched, ""
// outside managed mode, for no sandbox, or while it is not known. Callers
// must not hold m.mu.
func (m *Manager) profileOf(b *box) string {
	lookup, ok := m.opts.Persist.(ProfileLookup)
	if !ok || b == nil {
		return ""
	}
	m.mu.Lock()
	name := b.rec.Name
	m.mu.Unlock()
	profile, _ := lookup.SandboxProfile(name)
	return profile
}

// accessRefusal is the managed refusal (sandboxapi.AccessRefusedWhy) of an
// ask, approval or unblock for host in sandbox b (nil: none) that rule of
// the floor f refuses; why is the refusing check's words, "" to say it by
// the rule. Every such refusal has this one shape, with the profile, the
// sandbox and f's request-access contact (GAP-0508, GAP-0468, GAP-0502).
// Callers must not hold m.mu.
func (m *Manager) accessRefusal(b *box, f config.OpenShellAdminConfig, why, rule, host string) string {
	name := ""
	if b != nil {
		m.mu.Lock()
		name = b.rec.Name
		m.mu.Unlock()
	}
	return sandboxapi.AccessRefusedWhy(why, rule, host, m.profileOf(b), name, f.RequestAccess)
}

// adminRule is the floor rule (the openshell.admin key) that refuses with
// the organization's violation v, "" for any other refusal.
func adminRule(v *packs.Violation) string {
	if v == nil || !v.Admin() {
		return ""
	}
	rule, ok := strings.CutPrefix(v.Constraint, "openshell.admin.")
	if !ok || rule == "" || strings.Contains(rule, ".") {
		return ""
	}
	return rule
}

// person is the trusted actor reference of the person who decides on this
// daemon's sandboxes: the account it runs as (cli:<account>).
func (m *Manager) person() string {
	if name := m.host.Name; name != "" && policyTarget.MatchString(name) && len(name) <= 128 {
		return configwrite.ActorPrefixCLI + name
	}
	return configwrite.ActorPrefixCLI + "uid-" + strconv.Itoa(m.host.UID)
}

// actorRef is the actor reference of an approval's policy record: the
// person for the user's own approvals, triage for DefenseClaw's.
func (m *Manager) actorRef(actor string) string {
	if actor == actorOperator {
		return m.person()
	}
	return "triage"
}

// keepDecision applies one of the user's decisions beyond the sandbox's
// own state. In managed mode the managed gateway re-checks every one
// against the user's floor and keeps what lasts (an "always", a user
// block), recording the person; stored reports it kept this one. Outside
// it, an "always" allow or unblock joins openshell.egress.unblocked and a
// user block openshell.egress.block (Persist); a session decision keeps
// nothing. A sandbox without a registration fails closed in managed mode.
func (m *Manager) keepDecision(ctx context.Context, b *box, kind, host, scope, approvalID string) (stored bool, err error) {
	return m.keepDecisionAt(ctx, b, kind, host, 0, scope, approvalID)
}

// keepDecisionAt is keepDecision for a decision about port of host: the
// managed gateway's record of it names the port (a host-port ask).
func (m *Manager) keepDecisionAt(ctx context.Context, b *box, kind, host string, port int, scope, approvalID string) (stored bool, err error) {
	if auth := m.authority(); auth != nil {
		registration := ""
		if b != nil {
			registration = m.registrationOf(b)
		}
		if registration == "" {
			return false, sandboxapi.Errorf(sandboxapi.CodeUnavailable,
				"this sandbox has no registration with your organization's DefenseClaw gateway, so its decisions can't be made; start it again")
		}
		res, err := auth.Decide(ctx, sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: registration,
			Kind: kind, Host: host, Scope: scope, ApprovalID: approvalID, Port: port})
		if err != nil {
			return false, err
		}
		if res.Stored {
			// The sandbox's decider follows it now, not at the next
			// reconcile.
			m.noteDecision(registration, res.Decision)
			m.refreshEgress()
		}
		return res.Stored, nil
	}
	if m.managedMode() {
		if scope == sandboxrelay.DecisionScopeSession {
			return false, nil
		}
		return false, &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
			Detail: "the configuration is administrator-owned; decisions cannot be kept for future sandboxes"}
	}
	switch {
	case kind == sandboxrelay.DecisionEgressBlock && scope == sandboxrelay.DecisionScopeAlways:
		return true, m.persistBlock(ctx, host)
	case scope == sandboxrelay.DecisionScopeAlways:
		return true, m.persistAllow(ctx, host)
	}
	return false, nil
}

// managedState is what a manager in managed mode keeps of the managed
// gateway between reconciles: each registration's saved decisions (capped
// by the floor), and the foreign items it reported. It hangs off the
// Manager (managedSide) and goes with it.
type managedState struct {
	mu sync.Mutex
	// decisions are the saved decisions per registration, as the last
	// refresh (or a decision since) left them.
	decisions map[string][]sandboxrelay.Decision
	// foreignRules counts each sandbox's removals of rules DefenseClaw
	// neither rendered nor approved: a repeat stops the sandbox.
	foreignRules map[string]int
	// reported are the foreign sandboxes and containers already alerted
	// on (alert mode), so a reconcile reports each once.
	reported map[string]bool
	// foreignRemoving counts, per foreign sandbox, the reconciles whose
	// delete OpenShell took while the sandbox stayed (reconcileForeign).
	foreignRemoving map[string]int
	// foreignLeft is how many foreign sandboxes the last reconcile left
	// running (ForeignSandboxesRunning).
	foreignLeft int
	// pending are the records for the managed gateway kept while the
	// gateway was out of reach, or, for a record that needs one, while
	// none of the person's sandboxes is registered (flushManagedEvents).
	pending []sandboxrelay.Event
	// containersAt is when the containers were last looked into
	// (reportForeignContainers).
	containersAt time.Time
}

var managedStates sync.Map // weak.Pointer[Manager] -> *managedState

// managedSide returns the manager's managedState, made on first use and
// dropped once the manager is collected.
func (m *Manager) managedSide() *managedState {
	key := weak.Make(m)
	if v, ok := managedStates.Load(key); ok {
		return v.(*managedState)
	}
	st := &managedState{decisions: map[string][]sandboxrelay.Decision{}, foreignRules: map[string]int{}, reported: map[string]bool{},
		foreignRemoving: map[string]int{}}
	v, loaded := managedStates.LoadOrStore(key, st)
	if !loaded {
		runtime.AddCleanup(m, func(k weak.Pointer[Manager]) { managedStates.Delete(k) }, key)
	}
	return v.(*managedState)
}

// noteDecision adds a decision the managed gateway just stored to its
// registration's saved decisions, so the sandbox's decider follows it
// before the next refresh.
func (m *Manager) noteDecision(registration string, d sandboxrelay.Decision) {
	st := m.managedSide()
	st.mu.Lock()
	defer st.mu.Unlock()
	have, loaded := st.decisions[registration]
	if !loaded {
		// Not loaded yet: the first load brings this one with the others.
		return
	}
	list := slices.DeleteFunc(slices.Clone(have), func(have sandboxrelay.Decision) bool {
		return have.ID != "" && have.ID == d.ID
	})
	st.decisions[registration] = append(list, d)
}

// savedDecisions are a registration's saved decisions the floor f still
// allows (sandboxreg.CheckDecision): saved decisions are capped by the
// floor whenever the sandbox's policy resolves.
func (m *Manager) savedDecisions(registration string, f config.OpenShellAdminConfig) []sandboxrelay.Decision {
	if registration == "" {
		return nil
	}
	st := m.managedSide()
	st.mu.Lock()
	list, loaded := st.decisions[registration]
	list = slices.Clone(list)
	st.mu.Unlock()
	if !loaded {
		list = m.loadDecisions(registration)
	}
	return slices.DeleteFunc(list, func(d sandboxrelay.Decision) bool {
		return sandboxreg.CheckDecision(f, sandboxrelay.DecisionRequest{V: sandboxrelay.WireVersion, Registration: registration,
			Kind: d.Kind, Host: d.Host, Scope: d.Scope}) != nil
	})
}

// loadDecisionsTimeout bounds the first load of a registration's saved
// decisions (loadDecisions).
const loadDecisionsTimeout = 5 * time.Second

// loadDecisions loads the saved decisions of a registration the daemon has
// not loaded yet, a sandbox just created: its first requests follow the
// person's "always" decisions at once, not only after the next reconcile
// refreshed them (GAP-0674). A load that fails keeps nothing, so the next
// policy build or the reconcile tries again.
func (m *Manager) loadDecisions(registration string) []sandboxrelay.Decision {
	auth := m.authority()
	if auth == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), loadDecisionsTimeout)
	defer cancel()
	list, err := auth.Decisions(ctx, registration)
	if err != nil {
		m.logf("load the saved sandbox decisions of registration %s: %v", registration, err)
		return nil
	}
	st := m.managedSide()
	st.mu.Lock()
	defer st.mu.Unlock()
	if have, ok := st.decisions[registration]; ok {
		// A refresh or a new decision got there first.
		return slices.Clone(have)
	}
	if list == nil {
		list = []sandboxrelay.Decision{}
	}
	st.decisions[registration] = list
	return slices.Clone(list)
}

// refreshDecisions reloads the saved decisions of every registered
// sandbox from the managed gateway (reconcile). A registration the gateway
// can't answer for keeps what it had; one no sandbox holds, or one the
// gateway no longer knows (revoked, expired), is dropped.
func (m *Manager) refreshDecisions(ctx context.Context) {
	auth := m.authority()
	if auth == nil {
		return
	}
	var registrations []string
	for _, b := range m.liveBoxes() {
		if r := m.registrationOf(b); r != "" {
			registrations = append(registrations, r)
		}
	}
	fresh := map[string][]sandboxrelay.Decision{}
	failed := map[string]bool{}
	for _, r := range registrations {
		list, err := auth.Decisions(ctx, r)
		if err != nil {
			m.logf("load the saved sandbox decisions of registration %s: %v", r, err)
			if !registrationGone(err) {
				failed[r] = true
			}
			continue
		}
		fresh[r] = list
	}
	st := m.managedSide()
	st.mu.Lock()
	defer st.mu.Unlock()
	for r := range failed {
		fresh[r] = st.decisions[r]
	}
	st.decisions = fresh
}

// ReloadDecisions loads the saved decisions of registration from the
// managed gateway again, which caps them by the person's floor now, and
// re-resolves the sandboxes' egress when they changed. The daemon calls it
// when the gateway's answer moved the registration's policy and when its
// sandbox starts, so a floor that no longer keeps a saved allow takes it
// back from a running or restarted sandbox at once, not at the next
// reconcile (GAP-0224). A reload that fails keeps only the user blocks: a
// policy that moved is not decided under allows its new floor may refuse.
// A registration the gateway no longer knows keeps none; one never loaded
// is left for its first load.
func (m *Manager) ReloadDecisions(ctx context.Context, registration string) {
	auth := m.authority()
	if auth == nil || registration == "" {
		return
	}
	list, err := auth.Decisions(ctx, registration)
	st := m.managedSide()
	st.mu.Lock()
	have, loaded := st.decisions[registration]
	switch {
	case err == nil:
		if list == nil {
			list = []sandboxrelay.Decision{}
		}
	case registrationGone(err):
		list = []sandboxrelay.Decision{}
	case !loaded:
		st.mu.Unlock()
		m.logf("reload the saved sandbox decisions of registration %s: %v", registration, err)
		return
	default:
		list = slices.DeleteFunc(slices.Clone(have), func(d sandboxrelay.Decision) bool {
			return d.Kind != sandboxrelay.DecisionEgressBlock
		})
	}
	changed := !loaded || !slices.Equal(have, list)
	st.decisions[registration] = list
	st.mu.Unlock()
	if err != nil {
		m.logf("reload the saved sandbox decisions of registration %s: %v", registration, err)
	}
	if changed {
		m.refreshEgress()
	}
}

// maxPendingEvents bounds the records kept for the managed gateway
// (managedState.pending); the oldest go first. A batch without a
// registration holds at most as many.
const maxPendingEvents = sandboxrelay.MaxUnregisteredEventRecords

// managedEvent posts one record of the daemon to the managed gateway,
// which stamps it with the person's identity and emits it (kind is one of
// the sandboxrelay Event kinds), under registration, or without one when
// none of the person's sandboxes is registered (flushManagedEvents). Outside
// managed mode nothing is posted.
func (m *Manager) managedEvent(ctx context.Context, registration, kind string, payload any) {
	if m.authority() == nil {
		return
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	m.keepEvents(sandboxrelay.Event{Kind: kind, Time: m.now().UTC(), Payload: raw})
	m.flushManagedEvents(ctx, registration)
}

// eventWithoutRegistration reports a record the events route takes without
// a registration (sandboxrelay.EventWithoutRegistration).
func eventWithoutRegistration(ev sandboxrelay.Event) bool {
	return sandboxrelay.EventWithoutRegistration(ev.Kind)
}

// keepEvents adds records to the pending ones, dropping the oldest past
// maxPendingEvents.
func (m *Manager) keepEvents(events ...sandboxrelay.Event) {
	st := m.managedSide()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.pending = append(st.pending, events...)
	if over := len(st.pending) - maxPendingEvents; over > 0 {
		st.pending = slices.Delete(st.pending, 0, over)
	}
}

// flushManagedEvents posts the pending records under registration, except the
// foreign sandbox and container records, which always go out without one
// (the gateway stamps them with the verified caller). Without a registration
// any other record is kept for the next one. A gateway out of reach keeps
// them for the next try; one that refuses the batch drops them (the log has
// each).
func (m *Manager) flushManagedEvents(ctx context.Context, registration string) {
	auth := m.authority()
	if auth == nil {
		return
	}
	st := m.managedSide()
	st.mu.Lock()
	events := st.pending
	st.pending = nil
	// A foreign sandbox or container belongs to none of the person's
	// registrations, so it is posted under none: the registration picked for
	// the batch (anyRegistration) may be one the managed gateway no longer
	// takes, and a refused batch drops its records, which cost the audit
	// record of a foreign sandbox that was announced to the user (GAP-0633).
	unregistered, registered := splitEvents(events, eventWithoutRegistration)
	if registration == "" {
		st.pending = registered
		registered = nil
	}
	st.mu.Unlock()
	m.postEvents(ctx, auth, "", unregistered)
	m.postEvents(ctx, auth, registration, registered)
}

// postEvents posts one batch of records under registration. A gateway out of
// reach keeps them for the next try; one that refuses the batch drops them.
func (m *Manager) postEvents(ctx context.Context, auth ManagedAuthority, registration string, events []sandboxrelay.Event) {
	if len(events) == 0 {
		return
	}
	err := auth.Events(ctx, sandboxrelay.EventBatch{V: sandboxrelay.WireVersion, Registration: registration, Events: events})
	if err == nil {
		return
	}
	m.logf("report %d record(s) to the managed gateway: %v", len(events), err)
	if sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		st := m.managedSide()
		st.mu.Lock()
		later := st.pending
		st.pending = nil
		st.mu.Unlock()
		m.keepEvents(append(events, later...)...)
	}
}

// splitEvents splits events into those keep reports and the others, each
// in order.
func splitEvents(events []sandboxrelay.Event, keep func(sandboxrelay.Event) bool) (kept, rest []sandboxrelay.Event) {
	for _, ev := range events {
		if keep(ev) {
			kept = append(kept, ev)
		} else {
			rest = append(rest, ev)
		}
	}
	return kept, rest
}
