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
	"fmt"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// Proxy asks. The web path out of a sandbox is DefenseClaw's egress proxy,
// which OpenShell relays to without judging the destination, so a site
// outside the profile's allowlist is refused by the proxy and OpenShell
// drafts no proposal for it. A profile whose approvals are triaged or
// manual still means the user decides such a site, so DefenseClaw raises
// the ask itself (proxyAsk), like the ask for a host port. Approving it for
// the session opens the host for the sandbox (approveProxyAsk); approving it
// for always is the unblock the refusal's hint names (GAP-0626).

// proxyAsk raises the ask for the sandbox's first request to a site the
// egress proxy refused as not on the allowlist, unless the profile decides
// such sites itself (approvals: auto), the floor or the policy doesn't let
// the user approve it for the session (user_approvals: none, the
// organization's lists), one is waiting, the user declined it moments ago or
// the sandbox has too many waiting. allow_unblock: false takes "always" and
// unblocks from the user, not the session approval (plan §6.2), so it still
// asks. Callers must not hold m.mu.
func (m *Manager) proxyAsk(ctx context.Context, b *box, eff *packs.Effective, e egress.Event) {
	host := triage.NormalizeHost(e.Host)
	if eff == nil || host == "" || eff.Approvals == packs.ApprovalsAuto || triage.IsHostLocal(host) {
		return
	}
	if sandboxreg.CheckApprovals(m.floor(eff), sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession) != nil ||
		triage.CheckApproval(eff, host, e.Port, false) != nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	name := b.rec.Name
	p := proxyProposal(name, host, e.Port)
	id := approvalID(name, p.RuleDigest)
	pending := 0
	for _, other := range m.approvals {
		if other.sandbox == name && other.status == sandboxapi.ApprovalPending {
			pending++
		}
	}
	skip := pending >= maxPendingApprovals
	if prev := m.approvals[id]; prev != nil {
		switch {
		case prev.unresolved():
			skip = true
		case prev.status == sandboxapi.ApprovalApproved && now.Sub(prev.resolvedAt) < collapseWindow:
			skip = true
		case prev.status == sandboxapi.ApprovalRejected && prev.actor == actorOperator && now.Sub(prev.resolvedAt) < collapseWindow:
			skip = true
		}
	}
	ident := b.identity()
	m.mu.Unlock()
	if skip {
		return
	}
	reason := triage.ReasonNotAllowlisted
	message := host + " is not on the allowlist"
	if eff.Approvals == packs.ApprovalsManual {
		reason, message = triage.ReasonManual, fmt.Sprintf("approvals are manual for the %s profile: %s is not on the allowlist", eff.Profile, host)
	}
	d := triage.Decision{Verdict: triage.Ask, Reason: reason, Kind: triage.KindNetworkRule, Host: host, Port: e.Port,
		Unblockable: true, Message: message}
	a := &approval{id: id, sandbox: name, decision: d, proposal: p, status: sandboxapi.ApprovalPending, createdAt: now.UTC(), local: true, proxy: true}
	// The connection that asked failed at once: the agent's next hook says
	// it waits for the user instead of the refusal's unblock hint. Noted
	// before the ask is listed, so no hook sees the ask without the note
	// (GAP-0665, GAP-0698).
	m.refusals.forgetNote(e.BindingID, host, e.Port, "")
	m.refusals.noteDirect(e.BindingID, name, host, e.Port, NoteAsked, now)
	m.storeApproval(a)
	m.recordApproval(ctx, ident, a, audit.SandboxApprovalRequested, "", "")
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalRequested, Sandbox: name, Host: host, Port: e.Port,
		ApprovalID: id, Reason: string(d.Reason), Message: d.Message})
}

// approveProxyAsk opens host for sandbox b's session: the approval of its
// proxy ask (proxyAsk). It is an approval, not an unblock: the sandbox's
// decider opens only the allowlist's default refusal of the host, after its
// lists and the blocklist feed (egress.DeciderOptions.Approved), so it
// stands under allow_unblock: false. The managed gateway re-checks it
// against the floor and records the person and the ask. Callers must not
// hold m.mu.
func (m *Manager) approveProxyAsk(ctx context.Context, b *box, eff *packs.Effective, host string, port int, approvalID string) (string, error) {
	if err := triage.CheckApproval(eff, host, port, false); err != nil {
		return "", m.decisionViolation(ctx, err, b, eff, audit.SandboxPolicyRuleAdd, host)
	}
	if _, err := m.keepDecision(ctx, b, sandboxrelay.DecisionEgressAllow, host, sandboxrelay.DecisionScopeSession, approvalID); err != nil {
		return "", err
	}
	m.mu.Lock()
	sandboxID, name := scopeID(b.rec.ID, b.rec.Name), b.rec.Name
	m.mu.Unlock()
	if err := m.approved.Add(egress.Unblock{Pattern: host, SandboxID: sandboxID, CreatedAt: m.now().UTC()}); err != nil {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
	}
	m.mu.Lock()
	if !slices.Contains(b.rec.Approved, host) {
		b.rec.Approved = append(slices.Clip(b.rec.Approved), host)
	}
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.logf("save the approval of %s for %s: %v", host, name, err)
	}
	return "approved " + host + " for sandbox " + name, nil
}

// proxyProposal is what approving a proxy ask opens: the one host, on the
// port the refused request used. It names no OpenShell rule, because the
// proxy, not the sandbox policy, refused it.
func proxyProposal(sandbox, host string, port int) triage.Proposal {
	digest := "proxy:" + host
	return triage.Proposal{Sandbox: sandbox, Endpoints: []triage.Endpoint{{Host: host, Port: port}}, Digest: digest, RuleDigest: digest}
}

// settleProxyAsks resolves the sandbox's waiting proxy ask for host that an
// unblock made outside the ask (`sandbox unblock`, the TUI) has answered, so
// the list does not keep an ask nothing waits on. Callers must not hold m.mu.
func (m *Manager) settleProxyAsks(ctx context.Context, sandbox, host string, always bool) {
	host = triage.NormalizeHost(host)
	var settled []*approval
	var ident audit.SandboxIdentity
	m.mu.Lock()
	if b := m.boxes[sandbox]; b != nil {
		ident = b.identity()
		for _, a := range m.approvals {
			if a.proxy && a.sandbox == sandbox && a.decision.Host == host && a.status == sandboxapi.ApprovalPending {
				a.status, a.actor, a.always, a.resolvedAt = sandboxapi.ApprovalApproved, actorOperator, always, m.now().UTC()
				settled = append(settled, a)
			}
		}
	}
	m.mu.Unlock()
	for _, a := range settled {
		m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalApproved, actorOperator)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: sandbox, ApprovalID: a.id,
			Host: host, Port: a.decision.Port, Reason: "approved", Message: "approved " + host})
	}
}
