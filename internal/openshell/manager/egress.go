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
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// unblockIndex serves a sandbox decider's unblock lookups: the unblocks
// scoped to the principal's sandbox (live) and the "always" ones, which
// exist only as the saved openshell.egress.unblocked, so taking one out of
// the configuration takes it back. The decider consults them only after its
// guard, the administrator's lists and the block list, and not at all while
// the administrator forbids unblocking, so an unblock never lifts more than
// the sandbox's own policy allows.
type unblockIndex struct {
	live  *egress.MemoryUnblocks
	saved *egress.MemoryUnblocks
}

func (u unblockIndex) Unblocked(p egress.Principal, host string) (egress.Unblock, bool) {
	if ub, ok := u.live.Unblocked(p, host); ok {
		return ub, true
	}
	return u.saved.Unblocked(p, host)
}

// unblockIndex returns the index with cfg's saved "always" decisions.
// Configuration validation keeps them parseable; one that is not is
// skipped.
func (m *Manager) unblockIndex(cfg *config.Config) unblockIndex {
	saved, _ := egress.NewMemoryUnblocks()
	for _, host := range cfg.OpenShell.Egress.Unblocked {
		_ = saved.Add(egress.Unblock{Pattern: host})
	}
	return unblockIndex{live: m.unblocks, saved: saved}
}

// egressDecider builds a sandbox's own egress proxy decider from its
// resolved policy (packs.Effective.EgressDecider) and the unblock index.
// Each sandbox's proxy credential carries its own, so one sandbox's pack,
// admin clamps, ports and unblocks never decide another's egress.
func (m *Manager) egressDecider(cfg *config.Config, eff *packs.Effective) (*egress.Decider, error) {
	d, err := eff.EgressDecider(m.unblockIndex(cfg))
	if err != nil {
		m.logf("%s: %v", gatewaylog.ErrCodeOpenShellPackInvalid, err)
		return nil, &sandboxapi.Error{Code: sandboxapi.CodePackInvalid, Message: "the sandbox egress policy is invalid", Detail: err.Error()}
	}
	return d, nil
}

// Decider builds the egress proxy's default decider: the configured posture
// without run flags, with the persistent unblocks. The manager registers
// every sandbox's proxy credential with the sandbox's own decider
// (egressDecider), so the default decides only for a principal registered
// without one.
func (m *Manager) Decider() (*egress.Decider, error) {
	cfg := m.config()
	base, err := m.baseEffective(cfg)
	if err != nil {
		return nil, err
	}
	return m.egressDecider(cfg, base)
}

// refreshEgress re-resolves every sandbox's policy, re-registers its proxy
// credential with its rebuilt decider, and swaps in a new default decider,
// which also retires the proxy's pooled upstream connections. It runs after
// creates, deletes and configuration changes.
func (m *Manager) refreshEgress() {
	cfg := m.opts.Config()
	m.mu.Lock()
	m.cfgSeen = cfg
	boxes := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.creating && !b.deleted && !b.retained {
			boxes = append(boxes, b)
		}
	}
	proxy := m.proxy
	m.mu.Unlock()
	for _, b := range boxes {
		eff, err := m.resolveBox(b)
		if err != nil {
			// resolveBox suspended the credential (policyUnresolved).
			continue
		}
		m.syncCredential(b, eff)
		m.announcePosture(b, eff)
	}
	if proxy == nil {
		return
	}
	if d, err := m.Decider(); err != nil {
		m.logf("egress decider: %v", err)
	} else if err := proxy.SetDecider(d); err != nil {
		m.logf("egress decider: %v", err)
	}
}

// syncCredential registers a sandbox's egress proxy credential with its
// current principal and decider, or suspends it while the sandbox's network
// mode is deny (the strict profile, for example after an administrator
// required the strict pack or raised min_profile): the proxy then refuses
// the sandbox altogether instead of serving it under another policy, with a
// 403 that says why rather than the 407 of an unknown credential, and the
// feed says so once. Without a decider the credential is revoked.
func (m *Manager) syncCredential(b *box, eff *packs.Effective) {
	m.mu.Lock()
	cred, rec, d := b.cred, b.rec, b.decider
	m.mu.Unlock()
	if cred.Username == "" || rec.BindingID == "" || eff == nil {
		return
	}
	pr := m.principal(rec.BindingID, scopeID(rec.ID, rec.Name), rec.Name, d, eff)
	switch {
	case eff.NetworkMode == packs.NetworkDeny:
		why := egressOffReason(eff)
		if err := m.creds.Suspend(cred, pr, egressOffDecision(eff, why)); err != nil {
			m.creds.Revoke(rec.BindingID)
		}
		m.noteEgressOff(b, why)
	case d == nil:
		m.creds.Revoke(rec.BindingID)
	default:
		_ = m.creds.Register(cred, pr)
		m.noteEgressOff(b, "")
	}
	m.recheckEgress(rec.BindingID)
}

// egressOffDecision is the refusal a sandbox's suspended egress proxy
// credential is answered with.
func egressOffDecision(eff *packs.Effective, why string) egress.Decision {
	dec := egress.Decision{Category: egress.CategoryEgressOff, Reason: why, Source: egress.SourceDefault}
	if eff != nil {
		if s, ok := effSetting(eff, "network.mode"); ok && s.Source == packs.SourceAdmin {
			dec.Source = egress.SourceAdmin
		}
		if s, ok := effSetting(eff, "pack"); ok && s.Source == packs.SourceAdmin {
			dec.Source = egress.SourceAdmin
		}
	}
	return dec
}

// egressOffReason says why a sandbox's policy turns its web egress off: an
// organization's required pack or constraint, else the sandbox's own pack
// or profile.
func egressOffReason(eff *packs.Effective) string {
	pack := ""
	if eff.Pack != nil {
		pack = eff.Pack.Name
	}
	if s, ok := effSetting(eff, "pack"); ok && s.Source == packs.SourceAdmin && pack != "" {
		return "your organization's required sandbox pack (" + pack + ") turns web egress off for this sandbox (" + s.Origin + ")"
	}
	for _, key := range []string{"network.mode", "profile"} {
		if s, ok := effSetting(eff, key); ok && s.Source == packs.SourceAdmin {
			return "your organization's DefenseClaw policy turns web egress off for this sandbox (" + s.Origin + ")"
		}
	}
	origin := "pack " + firstNonEmpty(pack, "-")
	if s, ok := effSetting(eff, "network.mode"); ok && s.Origin != "" {
		origin = s.Origin
	}
	return "the sandbox policy turns web egress off for this sandbox (network mode deny, from " + origin + ")"
}

// unblocksOff reports the organization's refusal of every unblock
// (openshell.admin.allow_unblock: false).
func unblocksOff(err error) bool {
	var v *packs.Violation
	return errors.As(err, &v) && v.Constraint == "openshell.admin.allow_unblock"
}

// effSetting is one resolved setting of eff with its provenance.
func effSetting(eff *packs.Effective, key string) (packs.Setting, bool) {
	for _, s := range eff.Explain() {
		if s.Key == key {
			return s, true
		}
	}
	return packs.Setting{}, false
}

// noteEgressOff records why a sandbox's web egress is off ("" while it is
// on) and tells the feed when a policy change turns it off: a sandbox that
// starts out that way (the strict pack) has no proxy to be refused by.
func (m *Manager) noteEgressOff(b *box, why string) {
	m.mu.Lock()
	first := !b.egressSynced
	b.egressSynced = true
	changed := b.egressOff != why
	b.egressOff = why
	name, skip := b.rec.Name, b.creating || b.deleted
	m.mu.Unlock()
	if first || !changed || skip || why == "" {
		return
	}
	// A change of the sandbox's state rather than one refused request
	// (those follow as egress.blocked events with category egress_off).
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityLifecycle, Sandbox: name, Source: sandboxapi.SourceProxy,
		Reason: sandboxapi.ReasonEgressOff, Message: truncate("✗ all web egress: "+why+"; the proxy refuses every request with that reason", 512)})
}

// recheckEgress applies a binding's revoked or re-registered egress proxy
// credential to its open tunnels (egress.Proxy.Recheck): they close once
// the credential is gone, and the rebuilt decider decides them again, so
// failing closed, the deny network mode and an administrator's tightening
// reach the tunnels already open too.
func (m *Manager) recheckEgress(bindingID string) {
	m.mu.Lock()
	proxy := m.proxy
	m.mu.Unlock()
	if proxy == nil || bindingID == "" {
		return
	}
	if n := proxy.Recheck(bindingID); n > 0 {
		m.logf("closed %d egress tunnel(s) the sandbox policy no longer allows", n)
	}
}

// enforceAll re-checks the approved rules of every ready sandbox against
// the current policy (enforceApprovedRules). A sandbox whose own policy
// cannot be resolved has its rules judged by the organization's policy
// alone (orgPolicy), so an administrator's tightening still reaches them;
// when even that cannot be resolved, every triaged rule is removed. It
// reports whether it reached the gateway and checked every ready sandbox.
func (m *Manager) enforceAll(ctx context.Context) bool {
	gw, err := m.gateway(ctx)
	if err != nil {
		return false
	}
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
			return false
		}
		eff, err := m.resolveBox(b)
		if err != nil {
			if eff, err = m.orgPolicy(b); err != nil {
				m.mu.Lock()
				name := b.rec.Name
				m.mu.Unlock()
				m.logf("%s: sandbox %s: the organization's sandbox policy cannot be resolved either: %v",
					gatewaylog.ErrCodeOpenShellPackInvalid, name, err)
				eff = nil
			}
		}
		m.enforceApprovedRules(ctx, gw, b, eff)
		m.enforceProviderEndpoints(ctx, gw, b, eff)
	}
	return true
}

// Unblock lifts an egress block for one sandbox or, with Always, for every
// sandbox (the host joins openshell.egress.unblocked). The policy's check
// (packs ActionUnblock) asks the same decider the proxy uses, so only what
// an unblock can lift there is accepted: the blocklist feed and the mode
// defaults, never the guard (this machine, private networks), the
// administrator's lists or the block list.
func (m *Manager) Unblock(ctx context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error) {
	host := triage.NormalizeHost(req.Host)
	if host == "" || strings.ContainsAny(host, "/ \t") {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "a destination host is required")
	}
	if req.Sandbox == "" && !req.Always {
		return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "name a sandbox or ask for always")
	}
	var (
		b   *box
		eff *packs.Effective
		err error
	)
	if req.Sandbox != "" {
		if b, err = m.box(req.Sandbox); err != nil {
			return nil, err
		}
		if err := m.refuseRetained(b); err != nil {
			return nil, err
		}
		if eff, err = m.resolveBox(b); err != nil {
			return nil, err
		}
	} else if eff, err = m.baseEffective(m.config()); err != nil {
		return nil, err
	}
	if err := triage.CheckUnblock(eff, host); err != nil {
		if unblocksOff(err) && !eff.Egress.BlockLargeUploads && eff.DecideEgress(host, 0).Allowed {
			// Nothing to lift: the organization's refusal of unblocks
			// would only send the user to the administrator for nothing.
			// The large-upload block refuses hosts the policy allows, which
			// only an unblock would lift, so under it the refusal stands.
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid,
				"%s is not blocked: the sandbox policy lets the sandbox reach it, so there is nothing to unblock", host)
		}
		return nil, m.violationErrorFor(ctx, err, req.Sandbox, audit.SandboxEgressUnblock, host)
	}
	if req.Always {
		if err := triage.CheckApproval(eff, host, 0, true); err != nil && !triage.IsHostLocal(host) {
			return nil, m.violationErrorFor(ctx, err, req.Sandbox, audit.SandboxEgressUnblock, host)
		}
	}
	resp := &sandboxapi.UnblockResponse{Host: host, Sandbox: req.Sandbox}
	var ident audit.SandboxIdentity
	if req.Always {
		probe, _ := egress.NewMemoryUnblocks()
		if err := probe.Add(egress.Unblock{Pattern: host}); err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
		}
		// The saved list is the only record of an "always" unblock: the
		// persister reloads the configuration, and the deciders are
		// rebuilt from it (configLoop would within two seconds too).
		if err := m.persistAllow(ctx, host); err != nil {
			return nil, err
		}
		m.refreshEgress()
		resp.Scope, resp.Persisted = string(audit.SandboxApprovalScopeAlways), true
		resp.Message = "unblocked " + host + " for every sandbox (saved to openshell.egress.unblocked)"
	} else {
		m.mu.Lock()
		sandboxID := scopeID(b.rec.ID, b.rec.Name)
		m.mu.Unlock()
		if err := m.unblocks.Add(egress.Unblock{Pattern: host, SandboxID: sandboxID, CreatedAt: m.now().UTC()}); err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
		}
		m.mu.Lock()
		if !slices.Contains(b.rec.Unblocks, host) {
			b.rec.Unblocks = append(slices.Clip(b.rec.Unblocks), host)
		}
		name := b.rec.Name
		m.mu.Unlock()
		if err := m.saveRecord(b); err != nil {
			m.logf("save unblock of %s: %v", name, err)
		} else {
			resp.Persisted = true
		}
		resp.Scope = string(audit.SandboxApprovalScopeSandbox)
		resp.Message = "unblocked " + host + " for sandbox " + req.Sandbox
	}
	if b != nil {
		m.mu.Lock()
		ident = b.identity()
		m.mu.Unlock()
	}
	if ident.Name == "" {
		ident = audit.SandboxIdentity{Name: "all", Runtime: audit.SandboxRuntimeOpenShell}
	}
	if err := m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
		Sandbox: ident, Operation: audit.SandboxEgressUnblock, Actor: "operator", Origin: "api", Target: host,
		Reason: policyReasonUnblock, ChangeCount: 1, Timestamp: m.now(),
	}); err != nil {
		m.logf("policy telemetry for the unblock of %s: %v", host, err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressUnblocked, Sandbox: req.Sandbox, Host: host,
		Reason: resp.Scope, Message: resp.Message})
	return resp, nil
}

// EgressUnblock reports whether a sandbox's egress proxy reaches host
// because of an unblock decision, and that decision's scope: "sandbox" (an
// unblock for this sandbox) or "always" (one saved to
// openshell.egress.unblocked). It asks the decider and principal the
// sandbox's proxy credential carries, so it says what the proxy does now: a
// host the proxy refuses (the organization's lists, the block list, an
// unblock ignored under allow_unblock: false, a suspended credential) or
// allows for another reason (the open web, an allow entry) is not
// unblocked. The gateway lifts DefenseClaw's destination rules for the
// hosts it reports (#954). bindingID and name must be the sandbox's.
func (m *Manager) EgressUnblock(bindingID, name, host string) (string, bool) {
	p, ok := m.creds.Lookup(bindingID)
	if !ok || p.Decider == nil || p.SandboxName != name {
		return "", false
	}
	dec := p.Decider.DecideHost(p, host)
	if !dec.Allowed || dec.Source != egress.SourceUnblock {
		return "", false
	}
	if u, ok := m.unblocks.Unblocked(p, dec.Host); ok && u.SandboxID != "" {
		return string(audit.SandboxApprovalScopeSandbox), true
	}
	return string(audit.SandboxApprovalScopeAlways), true
}

// recoverCredential restores a sandbox's egress proxy credential from its
// environment (HTTPS_PROXY userinfo) after a daemon restart.
func recoverCredential(sb *openshell.Sandbox, username string) (egress.Credential, bool) {
	if sb == nil {
		return egress.Credential{}, false
	}
	for _, key := range []string{openshell.EnvEgressURL, "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		raw := sb.Spec.Environment[key]
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.User == nil {
			continue
		}
		pass, ok := u.User.Password()
		if !ok || (username != "" && u.User.Username() != username) {
			continue
		}
		return egress.Credential{Username: u.User.Username(), Password: pass}, true
	}
	return egress.Credential{}, false
}

// egressSink turns proxy events into telemetry and feed events off the
// proxy's goroutines: the proxy must never block on either. Every sandbox
// shares its queue, so one sandbox's refusals are folded and paced before
// they reach it (admitBlocked), and a large-upload finding the full queue
// cannot take waits in overflow instead of being dropped.
type egressSink struct {
	m       *Manager
	ch      chan sinkItem
	dropped atomic.Uint64
	// wake tells run that overflow holds findings.
	wake chan struct{}
	// blocked paces each sandbox's distinct refusals into the queue.
	blocked *rateGate

	mu       sync.Mutex
	recent   map[refusalKey]*refusal
	overflow []egress.Event
	// heldAt is when flush last reported what the pacing held back.
	heldAt time.Time
}

// sinkItem is one queued proxy event; repeats counts the refusals like it
// that were folded into it (admitBlocked).
type sinkItem struct {
	ev      egress.Event
	repeats int
}

// refusalKey is what makes refusals repeats of one another.
type refusalKey struct {
	sandbox, host string
	port          int
	category      egress.Category
	rule          string
}

// refusal is the fold of one refusalKey's repeats since its first record.
type refusal struct {
	since   time.Time
	repeats int
	last    egress.Event
}

const egressSinkBuffer = 4096

func newEgressSink(m *Manager) *egressSink {
	return &egressSink{m: m, ch: make(chan sinkItem, egressSinkBuffer), wake: make(chan struct{}, 1),
		blocked: newRateGate(blockedBurst, blockedRate), recent: map[refusalKey]*refusal{}}
}

// EgressEvent implements egress.EventSink.
func (s *egressSink) EgressEvent(e egress.Event) {
	it := sinkItem{ev: e}
	if e.Kind == egress.EventLargeUpload && e.Terminated {
		// An upload the large-upload block cut: the agent sees only the
		// broken connection too (EgressRefusals).
		s.m.refusals.note(e, s.m.now())
	}
	if e.Kind == egress.EventBlocked {
		// Every refusal, before the telemetry's folding and pacing: the
		// agent is told of what its own calls hit (EgressRefusals).
		s.m.refusals.note(e, s.m.now())
		ok, repeats := s.admitBlocked(e)
		if !ok {
			return
		}
		it.repeats = repeats
	}
	s.enqueue(it)
}

// admitBlocked folds a refusal into an earlier one of the same request
// within blockCoalesceWindow (flush records the count) and paces the
// sandbox's distinct refusals (blockedBurst, blockedRate): a workload
// refused thousands of times a second must not crowd the other sandboxes'
// events, or its own findings, out of the shared queue. An admitted
// refusal carries the repeats of an ended window flush has not recorded.
func (s *egressSink) admitBlocked(e egress.Event) (bool, int) {
	now := s.m.now()
	k := refusalKey{sandbox: e.SandboxName, host: e.Host, port: e.Port, category: e.Category, rule: e.Rule}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.recent[k]
	if r != nil && now.Sub(r.since) < blockCoalesceWindow {
		r.repeats++
		r.last = e
		return false, 0
	}
	if !s.blocked.take(e.SandboxName, now) {
		return false, 0
	}
	carried := 0
	if r != nil {
		carried = r.repeats
	}
	s.recent[k] = &refusal{since: now}
	return true, carried
}

// enqueue queues an item without ever blocking the proxy. A full queue
// drops it and counts the drop, except a large-upload finding, which waits
// in overflow.
func (s *egressSink) enqueue(it sinkItem) {
	select {
	case s.ch <- it:
		return
	default:
	}
	if it.ev.Kind == egress.EventLargeUpload {
		s.mu.Lock()
		kept := len(s.overflow) < maxSinkOverflow
		if kept {
			s.overflow = append(s.overflow, it.ev)
		}
		s.mu.Unlock()
		if kept {
			select {
			case s.wake <- struct{}{}:
			default:
			}
			return
		}
	}
	if n := s.dropped.Add(1); n == 1 || n%1000 == 0 {
		s.m.logf("egress telemetry backlog: %d events dropped", n)
	}
}

func (s *egressSink) run(ctx context.Context) {
	flush := time.NewTicker(sinkFlushInterval)
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case it := <-s.ch:
			s.m.egressEvent(ctx, it.ev, it.repeats)
		case <-s.wake:
			s.drainOverflow(ctx)
		case <-flush.C:
			s.drainOverflow(ctx)
			s.flush(ctx)
		}
	}
}

// drainOverflow processes the findings the full queue could not take.
func (s *egressSink) drainOverflow(ctx context.Context) {
	s.mu.Lock()
	list := s.overflow
	s.overflow = nil
	s.mu.Unlock()
	for _, e := range list {
		s.m.egressEvent(ctx, e, 0)
	}
}

// flush records the refusals folded into an earlier one whose window
// ended (one record naming the count), forgets the ended windows, and
// reports the refusals and feed events each sandbox's pacing held back.
func (s *egressSink) flush(ctx context.Context) {
	now := s.m.now()
	var folded []sinkItem
	s.mu.Lock()
	for k, r := range s.recent {
		if now.Sub(r.since) < blockCoalesceWindow {
			continue
		}
		if r.repeats > 0 {
			folded = append(folded, sinkItem{ev: r.last, repeats: r.repeats})
		}
		delete(s.recent, k)
	}
	s.mu.Unlock()
	sort.Slice(folded, func(i, j int) bool { return folded[i].ev.Time.Before(folded[j].ev.Time) })
	for _, it := range folded {
		// The last of the repeats stands for them all.
		s.m.egressEvent(ctx, it.ev, it.repeats-1)
	}
	// The counts of what the pacing held back go out less often: a
	// sandbox that floods for hours must not fill the feed with them.
	s.mu.Lock()
	report := now.Sub(s.heldAt) >= heldBackInterval
	if report {
		s.heldAt = now
	}
	s.mu.Unlock()
	if !report {
		return
	}
	for _, h := range s.blocked.drain(now) {
		s.m.logf("sandbox %s: %d refused egress requests to further destinations were not recorded one by one (more than %d a second)",
			h.key, h.n, blockedRate)
		s.m.publishHeldBack(h.key, h.n, "refused requests to further destinations were not recorded one by one")
	}
	for _, h := range s.m.egressFeed.drain(now) {
		s.m.publishHeldBack(h.key, h.n, "egress events were not shown one by one")
	}
}

// publishHeldBack tells the feed how many of a sandbox's egress events its
// pacing held back.
func (m *Manager) publishHeldBack(sandbox string, n int, what string) {
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: sandbox, Source: sandboxapi.SourceProxy,
		Reason: "flood", Message: fmt.Sprintf("… %d more %s (this sandbox makes more than the feed shows)", n, what)})
}

// publishEgress publishes one of a sandbox's egress events to the activity
// feed that every sandbox shares, paced per sandbox (feedBurst, feedRate);
// flush reports what the pacing held back.
func (m *Manager) publishEgress(ev sandboxapi.ActivityEvent) {
	if !m.egressFeed.take(ev.Sandbox, m.now()) {
		return
	}
	m.feed.Publish(ev)
}

func (m *Manager) egressEvent(ctx context.Context, e egress.Event, repeats int) {
	m.mu.Lock()
	b := m.boxes[e.SandboxName]
	var ident audit.SandboxIdentity
	if b != nil {
		// The proxy's requests are no sign of the harness at work (hook
		// silence): the proxy cannot tell the harness's from a tool's or a
		// `sandbox exec` command's. OpenShell's record of the connection
		// to the proxy names the binary, and marks the harness's own
		// (hostAliasEvent).
		ident = b.identity()
	}
	m.mu.Unlock()
	if b == nil {
		return
	}
	switch e.Kind {
	case egress.EventAllowed, egress.EventBlocked:
		blocked := e.Kind == egress.EventBlocked
		reason, more := e.Reason, ""
		if repeats > 0 {
			// Refusals folded into this one (egressSink.admitBlocked).
			more = fmt.Sprintf(" (and %d more like it)", repeats)
			reason += more
		}
		ev := audit.SandboxEgressEvent{
			Sandbox: ident, Source: audit.SandboxEgressSourceProxy, Host: e.Host, Port: e.Port,
			Scheme: egressScheme(e), ResolvedIP: remoteIP(e.RemoteAddr), Blocked: blocked,
			DecisionCode: decisionCode(e), Reason: truncate(reason, 512),
			PolicyOutcome: policyOutcome(e), Timestamp: e.Time,
		}
		if err := m.tel.RecordSandboxEgress(ctx, ev); err != nil {
			m.logf("egress telemetry: %v", err)
		}
		if blocked || e.FirstSeen {
			kind := sandboxapi.ActivityEgressAllowed
			msg := "✓ " + e.Host
			if blocked {
				kind = sandboxapi.ActivityEgressBlocked
				msg = "✗ " + e.Host + " (" + categoryText(e) + ")" + more
			}
			m.publishEgress(sandboxapi.ActivityEvent{
				Time: e.Time, Kind: kind, Sandbox: e.SandboxName, Host: e.Host, Port: e.Port, Method: e.Method,
				Source: sandboxapi.SourceProxy, Category: string(e.Category), Rule: e.Rule, Unblockable: blocked && e.Unblockable,
				Reason: truncate(e.Reason, 300), Message: msg,
			})
		}
	case egress.EventLargeUpload:
		if e.Terminated {
			m.largeUploadBlocked(ctx, ident, e)
			return
		}
		remediation := "Review what the agent uploaded; block the destination if it is not expected " +
			"(openshell.egress.block_large_uploads: true cuts such uploads)."
		if p, ok := m.creds.Lookup(e.BindingID); ok && p.BlockLargeUploads {
			// Under the block only an exempt destination is reported.
			remediation = "Review what the agent uploaded. The large-upload block is on, but " + e.Host +
				" is exempt from it (an unblock, an allow entry or your organization's allowed list names it), so the upload was only reported; " +
				"remove that entry if the destination is not expected."
		}
		// The proxy reports the upload as it crosses the threshold, before
		// it ends: it sent more than the threshold, and BytesUp is only
		// what had gone up then.
		size := fmt.Sprintf("%d bytes", e.BytesUp)
		if e.Threshold > 0 {
			size = "more than " + egress.FormatThreshold(e.Threshold)
		}
		_ = m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
			Sandbox: ident, Kind: audit.SandboxFindingLargeUpload, Severity: "MEDIUM",
			Title: "Large upload to a first-seen destination",
			Description: fmt.Sprintf("%s sent %s to %s, which it had not contacted before (%d bytes as it crossed the threshold).",
				e.SandboxName, size, e.Host, e.BytesUp),
			Evidence: truncate(e.Reason, 512), TargetRef: e.Host, Remediation: remediation,
			Timestamp: e.Time,
		})
		m.feed.Publish(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityEgressLargeUpload, Sandbox: e.SandboxName,
			Host: e.Host, Port: e.Port, Source: sandboxapi.SourceProxy, BytesUp: e.BytesUp, Threshold: e.Threshold, Severity: "MEDIUM",
			Reason:  truncate(e.Reason, 300),
			Message: fmt.Sprintf("⚠ large upload to first-seen %s (%s)", e.Host, size)})
	}
}

// largeUploadBlocked records and shows an upload the large-upload block cut
// (egress.block_large_uploads): a HIGH finding, a blocked egress record,
// and a ✗ in the feed that names the threshold and, when an unblock lifts
// the block, offers it. The proxy refuses the sandbox's later tunnels to
// the destination with the same category, each an ordinary blocked event.
func (m *Manager) largeUploadBlocked(ctx context.Context, ident audit.SandboxIdentity, e egress.Event) {
	threshold := egress.FormatThreshold(e.Threshold)
	remediation := "Review what the agent tried to upload. If the destination is expected, unblock it for the sandbox: " +
		"defenseclaw sandbox unblock " + e.Host + " --sandbox " + e.SandboxName + "."
	if !e.Unblockable {
		remediation = "Review what the agent tried to upload. Your organization does not allow unblocks; " +
			"ask your administrator if the destination is expected."
	}
	_ = m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
		Sandbox: ident, Kind: audit.SandboxFindingLargeUpload, Severity: "HIGH",
		Title: "Large upload to a first-seen destination blocked",
		Description: fmt.Sprintf("%s tried to send more than %s to %s, which it had not contacted before; "+
			"the large-upload block cut the upload (%d bytes had been sent) and refuses further requests there.",
			e.SandboxName, threshold, e.Host, e.BytesUp),
		Evidence: truncate(e.Reason, 512), TargetRef: e.Host, Remediation: remediation, Timestamp: e.Time,
	})
	if err := m.tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{
		Sandbox: ident, Source: audit.SandboxEgressSourceProxy, Host: e.Host, Port: e.Port,
		Scheme: egressScheme(e), ResolvedIP: remoteIP(e.RemoteAddr), Blocked: true,
		DecisionCode: decisionCode(e), Reason: truncate(e.Reason, 512),
		PolicyOutcome: policyOutcome(e), Severity: "HIGH", Timestamp: e.Time,
	}); err != nil {
		m.logf("egress telemetry: %v", err)
	}
	m.feed.Publish(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: e.SandboxName,
		Host: e.Host, Port: e.Port, Method: e.Method, Source: sandboxapi.SourceProxy, Category: sandboxapi.CategoryLargeUpload,
		Unblockable: e.Unblockable, BytesUp: e.BytesUp, Severity: "HIGH", Reason: truncate(e.Reason, 300),
		Message: "✗ " + e.Host + " (" + sandboxapi.LargeUploadBlockedText(e.Reason) + ")"})
}

func egressScheme(e egress.Event) string {
	switch {
	case e.Method == "CONNECT" && e.Port == 443:
		return "https"
	case e.Method != "CONNECT" && e.Method != "":
		return "http"
	default:
		return ""
	}
}

func remoteIP(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func decisionCode(e egress.Event) string {
	if e.Kind == egress.EventAllowed {
		return "SANDBOX_EGRESS_ALLOWED"
	}
	cat := strings.ToUpper(strings.ReplaceAll(string(e.Category), "-", "_"))
	if cat == "" {
		cat = "BLOCKED"
	}
	return "SANDBOX_EGRESS_" + cat
}

func policyOutcome(e egress.Event) string {
	out := string(e.Source)
	if e.Rule != "" {
		out += ":" + e.Rule
	}
	if e.Feed != "" {
		out += " feed " + e.Feed + "@" + e.FeedVersion
	}
	return truncate(out, 256)
}

func categoryText(e egress.Event) string {
	switch {
	case e.Category == egress.CategoryLargeUpload:
		return sandboxapi.LargeUploadBlockedText(e.Reason)
	case e.Entry != "":
		return strings.ReplaceAll(string(e.Category), "_", " ") + ": " + e.Entry
	case e.Category != "":
		return strings.ReplaceAll(string(e.Category), "_", " ")
	default:
		return "blocked"
	}
}

// LargeUploadBytes is the configured first-seen-host upload alert threshold
// for the proxy's counter (openshell.egress.large_upload_mb, 0 disables).
// It applies only to a principal without its own: every sandbox's proxy
// credential carries the threshold of its resolved pack (largeUploadBytes),
// re-registered whenever its policy is.
func (m *Manager) LargeUploadBytes() int64 {
	eff, err := m.baseEffective(m.config())
	if err != nil {
		return egress.DefaultLargeUploadBytes
	}
	return largeUploadBytes(eff)
}

// largeUploadBytes is eff's large-upload threshold as a principal carries
// it: negative when its pack turns the signal off, zero (the counter's)
// without a policy.
func largeUploadBytes(eff *packs.Effective) int64 {
	switch {
	case eff == nil:
		return 0
	case eff.Egress.LargeUploadMB <= 0:
		return -1
	default:
		return int64(eff.Egress.LargeUploadMB) << 20
	}
}
