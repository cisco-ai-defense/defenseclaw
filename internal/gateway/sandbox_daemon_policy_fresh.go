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

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A running managed sandbox's egress proxy decides each new connection with
// the policy the managed gateway confirmed for the sandbox's registration no
// more than sandboxEgressLease before, and confirms it again first once a
// relayed answer named another policy generation. The administrator's change
// then reaches the sandbox's first connection after the managed gateway
// applied it, tighter or looser, on every driver and platform: the daemon
// learned of it from a relayed hook or the minute's poll only, and a running
// sandbox kept the old egress lists for 20-50 s after `ensure` reported the
// new generation (a GitHub clone the new block forbids still ran; GAP-0172).
//
// Four rules keep a connection from being decided under a policy older than
// the one the daemon holds:
//
//   - A lease renews only once the answer that renews it is in force: applied
//     to the registration, adopted into the floor the manager resolves
//     against, and every sandbox's policy re-resolved (adoptApplied). Renewed
//     before, a connection that came in during the adoption took the fast
//     path, and the proxy decided it with the credential of the old policy.
//   - A registration's policy requests and the application of their answers
//     take turns (askPolicy), and an answer to a request older than one
//     already applied is dropped (daemonRegistrations.applyOrdered): a
//     minute's poll that asked before the change and answered after a
//     connection's confirmation put the old lists back.
//   - The proxy reads the credential again after every Refresh
//     (egress.Options.Refresh), so a connection that waited for another
//     one's confirmation, or found the lease that confirmation renewed, is
//     decided by the decider in force once its Refresh returned.
//   - An answer that ended the registration stays on its egress lease until
//     the poll marks it revoked and stops the sandbox. A later gateway error
//     cannot allow another connection.
const (
	// sandboxEgressLease is how long a confirmation decides the new
	// connections of a registration's sandbox, and how long the verdict of
	// one the managed gateway did not answer holds from when it ended. A
	// busy sandbox asks policy/current about once a lease, well within the
	// sandbox-policy budget (10 a second per account).
	sandboxEgressLease = time.Second
	// sandboxEgressConfirmTimeout bounds each step of one confirmation (the
	// registration's turn and policy/current, the settings, the adoption),
	// which the connections wait for.
	sandboxEgressConfirmTimeout = 2 * time.Second
	// sandboxEgressRounds bounds how many confirmations one connection waits
	// for when the policy keeps changing under them.
	sandboxEgressRounds = 3
)

// sandboxEgressPolicyChanging is the reason of a new connection refused
// while the sandbox's policy changed and the managed gateway has not
// confirmed the new one.
const sandboxEgressPolicyChanging = "your organization changed this sandbox's policy and DefenseClaw could not confirm the new one yet; try again in a moment"

// sandboxEgressNotCovered is the reason of a new connection refused because
// the managed gateway ended the sandbox's registration: the sandbox is being
// stopped.
const sandboxEgressNotCovered = "your organization's policy no longer covers this sandbox; delete it and start it again with defenseclaw sandbox run"

// egressLeases are the egress leases of the daemon's registrations by id.
// The zero value is ready.
type egressLeases struct {
	mu   sync.Mutex
	byID map[string]*egressLease
}

// egressLease is one registration's. turn (capacity 1) serializes the
// registration's policy requests with the application of their answers
// (askPolicy). The rest is under egressLeases.mu: confirmed is when the
// newest confirmation in force was asked for (renew), stale when the policy
// was last known to have changed (expire). asked and ended are when the
// connections' last confirmation was asked for and ended, failed whether it
// put no answer in force, and off its verdict, which holds for a lease after
// a failed one ended unless a change was named since it was asked for. gone
// stays set once the gateway ended the registration, until prune drops the
// lease. attempt is the connections' confirmation under way, which a burst
// of new connections shares.
type egressLease struct {
	turn             chan struct{}
	confirmed, stale time.Time
	asked, ended     time.Time
	failed           bool
	gone             bool
	off              *egress.Decision
	attempt          *egressAttempt
}

// egressAttempt is one confirmation the new connections of a sandbox share:
// done closes once changed and off, its outcome, are set.
type egressAttempt struct {
	asked   time.Time
	done    chan struct{}
	changed bool
	off     *egress.Decision
}

// leaseVerdict is a lease at one instant (egressLeases.begin): fresh
// (confirmed since the last change, within the lease), gone (the gateway
// ended the registration), changing (the policy changed after the last
// confirmation in force) and off (the last attempt's verdict, while it holds).
type leaseVerdict struct {
	fresh, gone, changing bool
	off                   *egress.Decision
}

func (l *egressLeases) lease(id string) *egressLease {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byID == nil {
		l.byID = map[string]*egressLease{}
	}
	lease := l.byID[id]
	if lease == nil {
		lease = &egressLease{turn: make(chan struct{}, 1)}
		l.byID[id] = lease
	}
	return lease
}

// markGone makes the gateway's ended answer sticky for id until its lease
// is pruned. It reports whether this answer first marked the lease gone.
func (l *egressLeases) markGone(id string) bool {
	lease := l.lease(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	if lease.gone {
		return false
	}
	lease.gone = true
	return true
}

// expire ends id's lease: the policy changed.
func (l *egressLeases) expire(id string) {
	lease := l.lease(id)
	l.mu.Lock()
	lease.stale = time.Now()
	l.mu.Unlock()
}

// renew records a confirmation of id asked for at sent whose answer is in
// force. One asked for before the policy last changed (stale) does not make
// the lease fresh.
func (l *egressLeases) renew(id string, sent time.Time) {
	lease := l.lease(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	if sent.After(lease.confirmed) {
		lease.confirmed = sent
	}
}

// begin is lease at now for a new connection: gone, fresh, the attempt under
// way to wait for, a new attempt the caller runs (owner), or, while the last
// failed attempt's verdict holds, that verdict (off).
func (l *egressLeases) begin(lease *egressLease, now time.Time) (a *egressAttempt, owner bool, v leaseVerdict) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lease.gone {
		v.gone = true
		return nil, false, v
	}
	v.changing = !lease.stale.IsZero() && !lease.confirmed.After(lease.stale)
	if !v.changing && !lease.confirmed.IsZero() && now.Sub(lease.confirmed) < sandboxEgressLease {
		v.fresh = true
		return nil, false, v
	}
	if lease.attempt != nil {
		return lease.attempt, false, v
	}
	// The retry interval of an attempt that put nothing in force runs from
	// its end: from its start, an attempt the gateway kept for the whole
	// confirmation timeout (longer than the lease) was due again at once,
	// and each connection of a burst waited for its own (GAP-0172).
	due := lease.asked.IsZero() || !lease.asked.After(lease.stale) || !lease.failed ||
		now.Sub(lease.ended) >= sandboxEgressLease
	if !due {
		v.off = lease.off
		return nil, false, v
	}
	a = &egressAttempt{asked: now, done: make(chan struct{})}
	lease.attempt, lease.asked = a, now
	return a, true, v
}

// end records the outcome of lease's attempt a and wakes the connections
// that wait for it.
func (l *egressLeases) end(lease *egressLease, a *egressAttempt, changed bool, off *egress.Decision, failed bool) {
	l.mu.Lock()
	a.changed, a.off = changed, off
	lease.attempt, lease.ended, lease.failed, lease.off = nil, time.Now(), failed, off
	l.mu.Unlock()
	close(a.done)
}

// changedSince reports whether a relayed answer named another policy after
// the attempt began, or the gateway ended the registration. Check it after
// the attempt finishes: either can arrive while policy/current or the
// adoption is in flight.
func (l *egressLeases) changedSince(lease *egressLease, asked time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return lease.gone || (!lease.stale.IsZero() && !asked.After(lease.stale))
}

// prune drops the leases of registrations the daemon no longer has.
func (l *egressLeases) prune(regs []daemonRegistration) {
	live := make(map[string]bool, len(regs))
	for _, r := range regs {
		live[r.ID] = true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, lease := range l.byID {
		if !live[id] && lease.attempt == nil {
			delete(l.byID, id)
		}
	}
}

// policyAnswer is the managed gateway's answer to one policy request of a
// registration (askPolicy): sent is when it was asked for; gone (with
// reason) that the gateway ended the registration; changed that the answer
// changed the registration (applyLive) and moved that it named another
// generation than the registration's. err is a transient failure.
type policyAnswer struct {
	id             string
	sent           time.Time
	err            error
	gone           bool
	reason         string
	changed, moved bool
}

// askPolicy asks the managed gateway for r's policy, policy/current or with
// report the state report (running), and applies the answer, in r's turn: a
// registration's requests never overlap, so an answer is never older than
// one applied before it. A registration the gateway ended is reported gone
// and its egress lease is marked gone here. Its registration record stays
// live so the poll can mark it revoked and stop its sandbox.
func (d *SandboxDaemon) askPolicy(ctx context.Context, r daemonRegistration, report, running bool) policyAnswer {
	ans := policyAnswer{id: r.ID}
	markGone := func(reason string) {
		ans.gone, ans.reason = true, reason
		if d.leases.markGone(r.ID) {
			d.logf("sandbox %s: its managed registration ended (%s)", r.Sandbox, reason)
		}
	}
	turn := d.leases.lease(r.ID).turn
	select {
	case turn <- struct{}{}:
	case <-ctx.Done():
		ans.err = ctx.Err()
		return ans
	}
	defer func() { <-turn }()
	// An answer applied while this request waited for its turn is what
	// this one's generation compares with.
	if cur, ok := d.regs.get(r.Sandbox); ok && cur.ID == r.ID {
		r = cur
	}
	seq := d.regs.nextSeq()
	ans.sent = time.Now()
	var cp sandboxrelay.CurrentPolicy
	if report {
		cp, ans.err = d.relay.Report(ctx, r.ID, running)
	} else {
		cp, ans.err = d.relay.Current(ctx, r.ID)
	}
	if reason, gone := registrationGone(ans.err); gone {
		ans.err = nil
		markGone(reason)
		return ans
	}
	if ans.err != nil {
		return ans
	}
	if cp.Revoked {
		markGone(cp.RevokedReason)
		return ans
	}
	ans.moved = cp.Generation != 0 && cp.Generation != r.Generation
	ans.changed = d.regs.applyOrdered(r, seq, cp)
	return ans
}

// adoptApplied puts every registration change applied so far in force
// before a connection is decided: the floor of the running sandboxes is
// adopted and every sandbox's policy re-resolved (adoptRunningFloor), with
// refresh also when the floor stays (the managed settings changed). A
// change the minute's poll, a start or another sandbox's confirmation
// applied is adopted by the first connection after it, not only once that
// poll asked every registration. An adoption under way is waited for. ok
// is false when the sandboxes could not be listed: the change is not in
// force, and the connection is refused.
func (d *SandboxDaemon) adoptApplied(ctx context.Context, refresh bool) (changed, ok bool) {
	if !refresh && d.adopted.Load() >= d.regs.changeCount() {
		return false, true
	}
	d.adoptMu.Lock()
	defer d.adoptMu.Unlock()
	if !refresh && d.adopted.Load() >= d.regs.changeCount() {
		return false, true
	}
	phases, listed := d.sandboxPhases(ctx)
	if !listed {
		return false, false
	}
	return d.adoptLocked(phases, true, refresh), true
}

// adoptLocked is one adoption, under adoptMu: the floor of the sandboxes
// phases lists as running (adoptRunningFloor), every sandbox's policy
// re-resolved when the floor changed or with refresh. With listed, every
// registration change applied before it is in force once it returns.
func (d *SandboxDaemon) adoptLocked(phases map[string]string, listed, refresh bool) bool {
	target := d.regs.changeCount()
	changed := d.adoptRunningFloor(phases)
	if refresh && !changed {
		d.rt.manager.RefreshPolicies()
		changed = true
	}
	if listed && target > d.adopted.Load() {
		d.adopted.Store(target)
	}
	return changed
}

// egressRefresh is the egress proxy's Refresh (egress.Options.Refresh):
// confirmEgressPolicy's verdict for a new connection of pr's sandbox.
func (d *SandboxDaemon) egressRefresh(ctx context.Context, pr egress.Principal) *egress.Decision {
	changed, off := d.confirmEgressPolicy(ctx, pr)
	if changed && off == nil {
		d.logf("sandbox %s: its changed policy is in force before a new connection", pr.SandboxName)
	}
	return off
}

// confirmEgressPolicy brings the policy of pr's sandbox up to date before a
// new connection of it is decided; changed reports that it put a changed
// policy in force. Within the lease nothing is asked. Otherwise the
// registration's policy/current is, and once its answer and every change
// applied before it are in force (adoptApplied) the lease renews. The new
// connections that come in meanwhile wait for that confirmation and take its
// outcome. A managed gateway that does not answer keeps the policy in force,
// as the poll does, unless the policy is known to have changed: then the
// connection is refused (off) until the new one is confirmed, so a
// tightening never waits for the gateway; the outcome holds for a lease
// after that confirmation ended, without asking again. A registration the
// gateway ended stays refused across later gateway errors until the poll
// marks it revoked and stops its sandbox; one already marked revoked is
// refused too, even if its sandbox's stop failed.
func (d *SandboxDaemon) confirmEgressPolicy(ctx context.Context, pr egress.Principal) (bool, *egress.Decision) {
	r, ok := d.regs.get(pr.SandboxName)
	switch {
	case !ok || r.ID == "":
		// A create keeps its registration once OpenShell made the sandbox;
		// until then the floor the create took from the managed gateway
		// decides.
		return false, nil
	case r.Revoked:
		return false, sandboxEgressRevoked()
	}
	changed, off := d.confirmLease(ctx, r)
	if off != nil {
		return changed, off
	}
	adopted, ok := d.adoptApplied(ctx, false)
	if !ok {
		return changed, sandboxEgressRefusal()
	}
	return changed || adopted, nil
}

// confirmLease is confirmEgressPolicy's lease: fresh, the outcome of the
// confirmation under way or of the last failed one, or a new confirmation
// (confirmOnce). A connection whose request ends while it waits is refused.
func (d *SandboxDaemon) confirmLease(ctx context.Context, r daemonRegistration) (bool, *egress.Decision) {
	lease := d.leases.lease(r.ID)
	for range sandboxEgressRounds {
		a, owner, v := d.leases.begin(lease, time.Now())
		switch {
		case v.gone:
			return false, sandboxEgressRevoked()
		case v.fresh:
			return false, nil
		case a == nil:
			return false, v.off
		case owner:
			changed, off, failed := d.confirmOnce(ctx, r, v.changing)
			d.leases.end(lease, a, changed, off, failed)
			if d.leases.changedSince(lease, a.asked) {
				continue
			}
			return changed, off
		}
		select {
		case <-a.done:
		case <-ctx.Done():
			return false, sandboxEgressRefusal()
		}
		if d.leases.changedSince(lease, a.asked) {
			continue
		}
		return a.changed, a.off
	}
	// The policy kept changing under the confirmations this connection
	// waited for.
	return false, sandboxEgressRefusal()
}

// confirmOnce is one confirmation of r's policy for the new connections of
// its sandbox; failed reports that it put no answer in force. It runs to
// its end for the connections waiting on it even when the connection that
// asked went away; each step is bounded.
func (d *SandboxDaemon) confirmOnce(ctx context.Context, r daemonRegistration, changing bool) (changed bool, off *egress.Decision, failed bool) {
	ctx = context.WithoutCancel(ctx)
	cctx, cancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
	ans := d.askPolicy(cctx, r, false, false)
	cancel()
	switch {
	case ans.gone:
		d.askPoll()
		return false, sandboxEgressRevoked(), true
	case ans.err != nil:
		if changing {
			d.logf("confirm the changed policy of sandbox %s: %v", r.Sandbox, ans.err)
			return false, sandboxEgressRefusal(), true
		}
		return false, nil, true
	}
	if ans.moved {
		// The poll reads the managed settings again for a generation it
		// sees move; this confirmation recorded the new one first, so it
		// reads them, before the policies are re-resolved.
		sctx, scancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
		d.refreshSettings(sctx)
		scancel()
	}
	actx, acancel := context.WithTimeout(ctx, sandboxEgressConfirmTimeout)
	adopted, ok := d.adoptApplied(actx, ans.moved)
	acancel()
	if !ok {
		return ans.changed, sandboxEgressRefusal(), true
	}
	d.leases.renew(r.ID, ans.sent)
	if ans.moved {
		// The other registrations follow at once.
		d.askPoll()
	}
	return ans.changed || adopted, nil, false
}

// sandboxEgressRefusal is the refusal of a connection whose sandbox policy
// changed and is not confirmed: the organization's, egress off for now.
func sandboxEgressRefusal() *egress.Decision {
	return &egress.Decision{Category: egress.CategoryEgressOff, Source: egress.SourceAdmin, Reason: sandboxEgressPolicyChanging}
}

// sandboxEgressRevoked is the refusal of a connection whose sandbox's
// registration the managed gateway ended.
func sandboxEgressRevoked() *egress.Decision {
	return &egress.Decision{Category: egress.CategoryEgressOff, Source: egress.SourceAdmin, Reason: sandboxEgressNotCovered}
}
