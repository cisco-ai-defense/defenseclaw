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
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/policy"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// Host ports. A run's --host-port consents to one port on this machine; the
// sandbox policy keeps it closed until the user approves the sandbox's
// first connection to it. OpenShell drafts no proposal for a connection to
// host.openshell.internal (its transparent mapping, not a policy rule,
// refuses the port), so DefenseClaw raises that ask itself (hostPortAsk),
// and approving it merges an allow rule for the port into the sandbox
// policy (applyHostPortAsk), which adds the port to the mapping. A denied
// connection to a port the run did not declare gets one feed line per
// session that names the flag instead.

// hostPortRule is the network_policies key of an approved host port, in
// the allow_<host>_<port> shape triage and enforcement judge.
func hostPortRule(port int) string {
	return "allow_host_openshell_internal_" + strconv.Itoa(port)
}

// hostPortProposal is the rule approving host port port opens: the port on
// host.openshell.internal for every binary of the sandbox, which the
// --host-port consent names. binary is the executable whose connection was
// denied, for the ask's display only.
func hostPortProposal(sandbox string, port int, binary string) triage.Proposal {
	digest := "host-port:" + strconv.Itoa(port)
	return triage.Proposal{
		Sandbox: sandbox, RuleName: hostPortRule(port), Binary: binary, Binaries: []string{policy.AnyBinary},
		Endpoints: []triage.Endpoint{{Host: openshellHostAlias, Port: port}},
		Digest:    digest, RuleDigest: digest,
	}
}

// hostPortDenied handles OpenShell's denial of a sandbox connection to a
// host port other than DefenseClaw's own listeners. A connection OpenShell
// closed on a policy reload, or that the mapping denied for a port it
// covers (republished under the connection), reaches nothing new and is
// left alone. Every other denial is a blocked request: a declared port the
// policy opens becomes an ask, any other port gets its feed line.
func (m *Manager) hostPortDenied(ctx context.Context, b *box, r ocsf.Record, at time.Time) {
	if policyReloadCut(r) {
		return
	}
	port := r.Port
	m.mu.Lock()
	if b.rec.HostAlias != nil && slices.Contains(b.rec.HostAlias.Ports, port) && mappingDenial(r) {
		m.mu.Unlock()
		return
	}
	name, id, eff := b.rec.Name, b.identity(), b.eff
	declared := slices.Contains(b.rec.Flags.HostPorts, port)
	b.blocked++
	explained := b.closedPorts[port]
	m.mu.Unlock()
	replayed := at.Before(m.startedAt)
	_ = m.tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{
		Sandbox: id, Source: audit.SandboxEgressSourceOpenShell, Host: openshellHostAlias, Port: port,
		Blocked: true, DecisionCode: "SANDBOX_EGRESS_OPENSHELL_DENIED", Reason: truncate(firstNonEmpty(r.Reason, r.Message), 512),
		PolicyOutcome: truncate(r.Policy, 256), Timestamp: at,
	})
	refusal := errors.New("the sandbox policy is not resolved")
	if eff != nil {
		refusal = eff.Allow(packs.Action{Kind: packs.ActionHostPort, Port: port})
	}
	if declared && refusal == nil && !replayed {
		m.hostPortAsk(ctx, b, port, r.Binary)
		return
	}
	if explained {
		return
	}
	m.mu.Lock()
	if b.closedPorts == nil {
		b.closedPorts = map[int]bool{}
	}
	b.closedPorts[port] = true
	m.mu.Unlock()
	m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name,
		Host: openshellHostAlias, Port: port, Source: sandboxapi.SourceOpenShell, Reason: sandboxapi.ReasonHostPortClosed,
		Message: hostPortClosedMessage(port, declared, refusal), Replayed: replayed})
}

// hostPortClosedMessage is the feed line of a denied connection to host
// port port that no ask covers.
func hostPortClosedMessage(port int, declared bool, refusal error) string {
	target := openshellHostAlias + ":" + strconv.Itoa(port)
	switch {
	case refusal != nil:
		return truncate(fmt.Sprintf("✗ %s: the sandbox policy does not open port %d on this machine to the sandbox (%v)", target, port, refusal), 512)
	case declared:
		return fmt.Sprintf("✗ %s: port %d on this machine stays closed until you approve the sandbox's ask for it: defenseclaw sandbox approvals",
			target, port)
	default:
		return fmt.Sprintf("✗ %s: port %d on this machine is closed to the sandbox; run the sandbox with --host-port %d to be asked about it",
			target, port, port)
	}
}

// hostPortAsk raises the ask for the sandbox's first denied connection to
// the declared host port port, unless one is waiting or being applied, the
// port was approved moments ago (the mapping is being republished), or the
// user rejected it within collapseWindow.
func (m *Manager) hostPortAsk(ctx context.Context, b *box, port int, binary string) {
	now := m.now()
	m.mu.Lock()
	name := b.rec.Name
	p := hostPortProposal(name, port, binary)
	id := approvalID(name, p.RuleDigest)
	pending := 0
	for _, other := range m.approvals {
		if other.sandbox == name && other.status == sandboxapi.ApprovalPending {
			pending++
		}
	}
	prev := m.approvals[id]
	skip := pending >= maxPendingApprovals
	if prev != nil {
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
	d := triage.Decision{
		Verdict: triage.Ask, Reason: triage.ReasonHostLocal, Kind: triage.KindHostPort, Host: openshellHostAlias, Port: port, Risky: true,
		Message: fmt.Sprintf("the sandbox asks to reach port %d on your machine (--host-port %d)", port, port),
	}
	a := &approval{id: id, sandbox: name, decision: d, proposal: p, status: sandboxapi.ApprovalPending, createdAt: now.UTC(), local: true}
	m.storeApproval(a)
	m.recordApproval(ctx, ident, a, audit.SandboxApprovalRequested, "", "")
	m.feed.Publish(sandboxapi.ActivityEvent{
		Kind: sandboxapi.ActivityApprovalRequested, Sandbox: name, Host: openshellHostAlias, Port: port,
		ApprovalID: id, Reason: string(d.Reason), Message: d.Message,
	})
}

// hostPortApplyTimeout bounds applying an approved host port.
const hostPortApplyTimeout = 2 * time.Minute

// applyHostPortAsk opens an approved host port: once the sandbox has no
// hook request open (a policy reload closes its connections, as approved
// proposals wait for in the batcher), the port's rule is merged into the
// sandbox policy.
func (m *Manager) applyHostPortAsk(a *approval, bindingID string) {
	ctx := m.running()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, hostPortApplyTimeout)
	defer cancel()
	if q := m.opts.Quiesce; q != nil && bindingID != "" {
		wait, done := context.WithTimeout(ctx, profileQuiesceWait)
		_ = q.WaitQuiescent(wait, bindingID, profileQuiesceIdle)
		done()
	}
	res, err := m.mergeHostPortRule(ctx, a)
	m.hostPortApplied(context.WithoutCancel(ctx), a, res, err)
}

// mergeHostPortRule checks an approved host port against the policy as it
// is now and merges its rule into the sandbox policy.
func (m *Manager) mergeHostPortRule(ctx context.Context, a *approval) (*openshell.ConfigUpdateResult, error) {
	m.mu.Lock()
	b := m.boxes[a.sandbox]
	p := a.proposal
	m.mu.Unlock()
	if b == nil || len(p.Endpoints) != 1 {
		return nil, errors.New("the sandbox is gone")
	}
	eff, err := m.resolveBox(b)
	if err != nil {
		return nil, err
	}
	if err := triage.CheckProposal(eff, p, false); err != nil {
		return nil, err
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		return nil, err
	}
	port := uint32(p.Endpoints[0].Port)
	rule := v1.NetworkPolicyRule{
		Name:      p.RuleName,
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: openshellHostAlias, Port: port, Ports: []uint32{port}}},
		Binaries:  []v1.PolicyNetworkBinary{{Path: policy.AnyBinary}},
	}
	res, err := gw.Client.MergePolicy(ctx, a.sandbox, []openshell.PolicyMergeOperation{{AddRule: &v1.AddNetworkRule{RuleName: p.RuleName, Rule: rule}}},
		openshell.PolicyUpdateOptions{Annotations: map[string]string{"source": "defenseclaw", "reason": "host-port-approval"}})
	if err != nil && !openshell.IsAlreadyExists(err) {
		return nil, upstream("open host port "+strconv.Itoa(int(port)), err)
	}
	return res, nil
}

// hostPortApplied records the outcome of applying an approved host port.
func (m *Manager) hostPortApplied(ctx context.Context, a *approval, res *openshell.ConfigUpdateResult, err error) {
	m.mu.Lock()
	b := m.boxes[a.sandbox]
	var ident audit.SandboxIdentity
	saveRules := false
	if b != nil {
		ident = b.identity()
		if err == nil {
			b.rulesAdded++
			saveRules = noteApprovedRule(b, a.proposal.RuleName, actorOperator)
			if res != nil && res.Version != 0 && b.sb != nil {
				b.sb.Status.CurrentPolicyVersion = res.Version
				ident.PolicyVersion = res.Version
			}
		}
	}
	a.resolvedAt = m.now().UTC()
	a.status = sandboxapi.ApprovalApproved
	if err != nil {
		a.status = sandboxapi.ApprovalFailed
	}
	m.mu.Unlock()
	if b == nil {
		return
	}
	if saveRules {
		if serr := m.saveRecord(b); serr != nil {
			m.logf("record the approved rule %s of %s: %v", a.proposal.RuleName, a.sandbox, serr)
		}
	}
	port := a.decision.Port
	if err != nil {
		m.logf("open host port %d of %s: %v", port, a.sandbox, err)
		m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalCancelled, a.actor)
		m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
			Host: openshellHostAlias, Port: port, Reason: "apply_failed",
			Message: truncate(fmt.Sprintf("port %d on your machine could not be opened: %v", port, err), 300)})
		return
	}
	m.recordApproval(ctx, ident, a, audit.SandboxApprovalResolved, audit.SandboxApprovalApproved, a.actor)
	ev := audit.SandboxPolicyEvent{Sandbox: ident, Operation: audit.SandboxPolicyRuleAdd, Actor: approvalActor(a.actor),
		Origin: originFor(a.actor), Target: openshellHostAlias, Reason: policyReasonApproval, ChangeCount: 1, Timestamp: m.now()}
	if res != nil {
		ev.PolicyHash = res.PolicyHash
	}
	if perr := m.tel.RecordSandboxPolicy(ctx, ev); perr != nil {
		m.logf("policy telemetry for approval %s: %v", a.id, perr)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityApprovalResolved, Sandbox: a.sandbox, ApprovalID: a.id,
		Host: openshellHostAlias, Port: port, Reason: a.actor,
		Message: fmt.Sprintf("approved port %d on your machine (%s:%d)", port, openshellHostAlias, port)})
}
