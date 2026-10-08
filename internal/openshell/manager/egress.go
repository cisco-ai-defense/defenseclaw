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
	"net/http"
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
	// `sandbox policy block HOST` writes config.yaml, and the snapshot
	// follows the file only after the reload watcher: an unblock in that
	// second must not be decided, and reported done, against the block
	// list from before the write (GAP-0173).
	m.syncConfig(ctx)
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
	m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
		Sandbox: ident, Operation: audit.SandboxEgressUnblock, Actor: "operator", Origin: "api", Target: host,
		Reason: policyReasonUnblock, ChangeCount: 1, Timestamp: m.now(),
	})
	m.feed.Publish(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressUnblocked, Sandbox: req.Sandbox, Host: host,
		Reason: resp.Scope, Message: resp.Message})
	return resp, nil
}

// syncConfig loads config.yaml into the configuration snapshot
// (Options.SyncConfig). A file the reload refuses keeps the snapshot as it
// is; the reload reports why in the daemon's health.
func (m *Manager) syncConfig(ctx context.Context) {
	if m.opts.SyncConfig == nil {
		return
	}
	if err := m.opts.SyncConfig(ctx); err != nil {
		m.logf("load config.yaml before the decision: %v", err)
	}
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
	// openshell folds OpenShell's own refusals like recent folds the
	// proxy's (foldOpenShell).
	openshell map[openshellRefusalKey]*openshellRefusal
}

// openshellRefusalKey is what makes OpenShell's refusals repeats of one
// another: the sandbox, the destination and the program.
type openshellRefusalKey struct {
	sandbox, host, binary string
	port                  int
}

// openshellRefusal is the fold of one openshellRefusalKey's repeats since
// its first record and feed line: the last repeat stands for them all.
type openshellRefusal struct {
	since   time.Time
	repeats int
	last    audit.SandboxEgressEvent
	feed    *sandboxapi.ActivityEvent
}

// maxOpenShellRefusals bounds the refusals foldOpenShell keeps windows for.
const maxOpenShellRefusals = 4096

// foldOpenShell reports whether an OpenShell refusal of sandbox (its record
// ev, its feed line feed when the feed shows it) repeats one recorded within
// blockCoalesceWindow: then it only counts, and flush records the count in
// one record and one feed line. A retry loop refused seven times in seven
// seconds made seven MEDIUM alerts and seven feed lines (GAP-0199).
func (s *egressSink) foldOpenShell(sandbox string, ev audit.SandboxEgressEvent, feed *sandboxapi.ActivityEvent) bool {
	now := s.m.now()
	k := openshellRefusalKey{sandbox: sandbox, host: ev.Host, binary: ev.Executable, port: ev.Port}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.openshell[k]; r != nil && now.Sub(r.since) < blockCoalesceWindow {
		r.repeats++
		r.last, r.feed = ev, feed
		return true
	}
	if s.openshell == nil {
		s.openshell = map[openshellRefusalKey]*openshellRefusal{}
	}
	if len(s.openshell) < maxOpenShellRefusals {
		s.openshell[k] = &openshellRefusal{since: now}
	}
	return false
}

// flushOpenShell records, for each OpenShell refusal whose window ended,
// the repeats folded into it, and forgets the ended windows.
func (s *egressSink) flushOpenShell(ctx context.Context, now time.Time) {
	var folded []*openshellRefusal
	s.mu.Lock()
	for k, r := range s.openshell {
		if now.Sub(r.since) < blockCoalesceWindow {
			continue
		}
		if r.repeats > 0 {
			folded = append(folded, r)
		}
		delete(s.openshell, k)
	}
	s.mu.Unlock()
	sort.Slice(folded, func(i, j int) bool { return folded[i].last.Timestamp.Before(folded[j].last.Timestamp) })
	for _, r := range folded {
		ev, more := r.last, ""
		if r.repeats > 1 {
			more = fmt.Sprintf(" (and %d more like it)", r.repeats-1)
		}
		ev.Reason = truncate(ev.Reason+more, 512)
		s.m.tel.RecordSandboxEgress(ctx, ev)
		if r.feed != nil {
			line := *r.feed
			line.Message += more
			s.m.publishEgress(line)
		}
	}
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
	s.m.reportAuthFailures(ctx, now)
	s.flushOpenShell(ctx, now)
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
	for _, h := range s.m.procGate.drain(now) {
		name, what := h.key, "process"
		if n, ok := strings.CutSuffix(h.key, "\x00ssh"); ok {
			name, what = n, "SSH"
		}
		s.m.logf("sandbox %s: %d %s records were not recorded one by one (more than %d a second)", name, h.n, what, activityRate)
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

// firstToolHostRefusal reports whether host's refusal is the first the
// box's sandbox got since the daemon started, and marks it.
func (m *Manager) firstToolHostRefusal(b *box, host string) bool {
	host = triage.NormalizeHost(host)
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.toolHostsSaid == nil {
		b.toolHostsSaid = map[string]bool{}
	}
	if b.toolHostsSaid[host] {
		return false
	}
	b.toolHostsSaid[host] = true
	return true
}

func (m *Manager) egressEvent(ctx context.Context, e egress.Event, repeats int) {
	if e.Kind == egress.EventAuthFailed {
		// No principal: the credential is what failed.
		m.authFailed(ctx, e)
		return
	}
	m.mu.Lock()
	b := m.boxes[e.SandboxName]
	var ident audit.SandboxIdentity
	var harnessName string
	var eff *packs.Effective
	if b != nil {
		harnessName, eff = b.rec.Harness, b.eff
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
		category, text := string(e.Category), categoryText(e)
		if blocked && e.Category == egress.CategoryOperatorBlock && eff != nil {
			// The block list merges the pack's, the repository policy's
			// and the user's own: the line, the destination and the audit
			// record (an alert) say whose entry it was, where it is removed
			// (GAP-0136).
			if c, t := blockOriginText(eff.BlockOrigin(e.Host)); c != "" {
				category, text = c, t
				ev.DecisionCode, ev.Reason = "SANDBOX_EGRESS_"+strings.ToUpper(c), truncate(t+more, 512)
			}
		}
		fetch := blocked && harnessFetchHost(harnessName, e.Host, e.Port)
		if fetch {
			// The harness's own background request, which it does without:
			// audited, but no alert.
			ev.DecisionCode, ev.Severity = audit.SandboxEgressCodeHarnessFetch, "INFO"
		}
		m.tel.RecordSandboxEgress(ctx, ev)
		if fetch {
			return
		}
		m.observeDestination(ctx, b, destinationSighting{host: e.Host, port: e.Port, at: e.Time, proxy: true, denied: blocked,
			category: category})
		if blocked || e.FirstSeen {
			kind := sandboxapi.ActivityEgressAllowed
			// The port tells an HTTPS request from a plain-HTTP one to
			// the same host, which are refused one by one.
			where := sandboxapi.HostPort(e.Host, e.Port)
			msg := "✓ " + where
			if blocked {
				kind = sandboxapi.ActivityEgressBlocked
				msg = "✗ " + where + " (" + text + ")" + more
			}
			m.publishEgress(sandboxapi.ActivityEvent{
				Time: e.Time, Kind: kind, Sandbox: e.SandboxName, Host: e.Host, Port: e.Port, Method: e.Method,
				Source: sandboxapi.SourceProxy, Category: category, Rule: e.Rule, Unblockable: blocked && e.Unblockable,
				Reason: truncate(e.Reason, 300), Message: msg,
			})
		}
		if what, ok := toolHostOf(harnessName, e.Host); ok && blocked && m.firstToolHostRefusal(b, e.Host) {
			// The refusal of a host a harness tool calls for every site
			// read as the site's own (GAP-0234, GAP-0263).
			line := "⚠ " + e.Host + " is refused: " + what
			if e.Unblockable {
				line += "; `defenseclaw sandbox unblock " + e.Host + " --sandbox " + e.SandboxName + "` opens it for this sandbox"
			}
			m.publishEgress(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityFinding, Sandbox: e.SandboxName, Host: e.Host,
				Port: e.Port, Source: sandboxapi.SourceProxy, Severity: "INFO", Reason: sandboxapi.ReasonToolHostRefused, Message: line})
		}
	case egress.EventClosed, egress.EventFailed:
		m.egressEnded(ctx, ident, e)
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
		m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
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
			Message: fmt.Sprintf("⚠ large upload to first-seen %s (%s)", sandboxapi.HostPort(e.Host, e.Port), size)})
	}
}

// egressEnded records the end of an allowed tunnel or forwarded request:
// what it sent and received and how long it took (completed, or cancelled
// when the proxy cut it short), or the upstream failure the sandbox got a
// 502 or 504 for (failed; timed out on a 504). The decision was recorded
// when it opened.
func (m *Manager) egressEnded(ctx context.Context, ident audit.SandboxIdentity, e egress.Event) {
	ev := audit.SandboxEgressEvent{
		Sandbox: ident, Source: audit.SandboxEgressSourceProxy, Host: e.Host, Port: e.Port, Scheme: egressScheme(e),
		ResolvedIP: remoteIP(e.RemoteAddr), DecisionCode: "SANDBOX_EGRESS_ALLOWED", PolicyOutcome: policyOutcome(e),
		Duration: e.Duration, Timestamp: e.Time,
	}
	switch {
	case e.Kind == egress.EventClosed && e.Terminated:
		// The large-upload block (its finding says so), the idle timeout, a
		// refused TLS server name or content, or a recheck, whose reason
		// says why (its credential was revoked).
		ev.End, ev.Terminated, ev.BytesUp, ev.BytesDown = audit.SandboxEgressFailed, true, e.BytesUp, e.BytesDown
		ev.DecisionCode = "SANDBOX_EGRESS_TERMINATED"
		ev.Reason = truncate(firstNonEmpty(e.Reason, "the egress proxy cut it short"), 512)
	case e.Kind == egress.EventClosed:
		ev.End, ev.BytesUp, ev.BytesDown = audit.SandboxEgressCompleted, e.BytesUp, e.BytesDown
	default:
		ev.End, ev.TimedOut = audit.SandboxEgressFailed, e.Status == http.StatusGatewayTimeout
		ev.DecisionCode = "SANDBOX_EGRESS_UPSTREAM_FAILED"
		ev.Reason = truncate(firstNonEmpty(e.Error, e.Reason), 512)
	}
	m.tel.RecordSandboxEgress(ctx, ev)
	if ev.DecisionCode != "SANDBOX_EGRESS_UPSTREAM_FAILED" {
		// The counter counted it: the destinations view keeps its totals.
		m.touchDestinations(e.SandboxName)
		return
	}
	if m.destinationFailed(e.SandboxName, e.Host) {
		where := sandboxapi.HostPort(e.Host, e.Port)
		m.publishEgress(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityFinding, Sandbox: e.SandboxName,
			Host: e.Host, Port: e.Port, Source: sandboxapi.SourceProxy, Severity: "INFO", Reason: sandboxapi.ReasonUpstreamFailed,
			Message: "⚠ " + where + ": the connection failed upstream, not blocked by DefenseClaw (" + upstreamFailure(e) +
				"); `defenseclaw sandbox destinations " + e.SandboxName + "` counts the failures"})
	}
}

// authFailures counts the egress proxy's refusals of invalid credentials
// (authFailed): count since the last report, the last at lastAt, and
// whether a streak is reported as degraded health.
type authFailures struct {
	mu                        sync.Mutex
	count                     int
	since, reportedAt, lastAt time.Time
	last                      string
	degraded                  bool
}

// authFailedEvery paces the reports of refused credentials.
const authFailedEvery = time.Minute

// authFailed counts a request the egress proxy refused for an invalid proxy
// credential (malformed, unknown, revoked or wrong; a request without one
// is the normal first leg of the handshake and no event). It names no
// sandbox, so it is health of the integration (reportAuthFailures): a
// sandbox that keeps a stale or revoked credential (an environment from
// before a restart) or another program on this machine trying the proxy
// must not flood the records.
func (m *Manager) authFailed(ctx context.Context, e egress.Event) {
	now := m.now()
	a := &m.authFails
	a.mu.Lock()
	if a.count == 0 {
		a.since = now
	}
	a.count++
	a.lastAt = now
	a.last = truncate(sandboxapi.DisplayText(sandboxapi.HostPort(e.Host, e.Port)), 256)
	a.mu.Unlock()
	m.reportAuthFailures(ctx, now)
}

// reportAuthFailures reports the refused credentials: the first of a streak
// at once, as one degraded health record; then their count in the log at
// most every authFailedEvery; and the streak's end, once authFailedEvery
// passes without a refusal, as one restored record. The sink's flush calls
// it too, so a burst's count and its end are reported.
func (m *Manager) reportAuthFailures(ctx context.Context, now time.Time) {
	a := &m.authFails
	a.mu.Lock()
	var state audit.SandboxHealthState
	switch {
	case a.count > 0 && !a.degraded:
		state, a.degraded = audit.SandboxHealthDegraded, true
	case a.count > 0 && now.Sub(a.reportedAt) >= authFailedEvery:
		// Logged only: the streak is reported degraded already.
	case a.count == 0 && a.degraded && now.Sub(a.lastAt) >= authFailedEvery:
		state, a.degraded = audit.SandboxHealthRestored, false
	default:
		a.mu.Unlock()
		return
	}
	n, since, last := a.count, a.since, a.last
	if n > 0 {
		a.count, a.reportedAt = 0, now
	}
	a.mu.Unlock()
	code := gatewaylog.ErrCodeOpenShellEgressAuthFailed
	msg := fmt.Sprintf("the sandbox egress proxy refused %d request(s) with an invalid proxy credential since %s (the last to %s): "+
		"a sandbox may use a stale or revoked credential, or another program on this machine tries the proxy",
		n, since.UTC().Format(time.RFC3339), firstNonEmpty(last, "-"))
	if state == audit.SandboxHealthRestored {
		msg = fmt.Sprintf("the sandbox egress proxy refused no proxy credential for %s", authFailedEvery)
	}
	m.logf("%s: %s", code, msg)
	if state != "" {
		m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{State: state, ErrorCode: errorToken(code),
			ErrorSummary: truncate(msg, 512), Timestamp: now})
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
	m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
		Sandbox: ident, Kind: audit.SandboxFindingLargeUpload, Severity: "HIGH",
		Title: "Large upload to a first-seen destination blocked",
		Description: fmt.Sprintf("%s tried to send more than %s to %s, which it had not contacted before; "+
			"the large-upload block cut the upload (%d bytes had been sent) and refuses further requests there.",
			e.SandboxName, threshold, e.Host, e.BytesUp),
		Evidence: truncate(e.Reason, 512), TargetRef: e.Host, Remediation: remediation, Timestamp: e.Time,
	})
	m.tel.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{
		Sandbox: ident, Source: audit.SandboxEgressSourceProxy, Host: e.Host, Port: e.Port,
		Scheme: egressScheme(e), ResolvedIP: remoteIP(e.RemoteAddr), Blocked: true,
		DecisionCode: decisionCode(e), Reason: truncate(e.Reason, 512),
		PolicyOutcome: policyOutcome(e), Severity: "HIGH", Timestamp: e.Time,
	})
	m.feed.Publish(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: e.SandboxName,
		Host: e.Host, Port: e.Port, Method: e.Method, Source: sandboxapi.SourceProxy, Category: sandboxapi.CategoryLargeUpload,
		Unblockable: e.Unblockable, BytesUp: e.BytesUp, Severity: "HIGH", Reason: truncate(e.Reason, 300),
		Message: "✗ " + sandboxapi.HostPort(e.Host, e.Port) + " (" + sandboxapi.LargeUploadBlockedText(e.Reason) + ")"})
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

// blockOriginText is the feed category and text of a block-list refusal
// whose entry came from origin (packs.Effective.BlockOrigin); "" for the
// user's own list, which operator_block already names.
func blockOriginText(origin string) (category, text string) {
	switch origin {
	case packs.BlockFromPack:
		return sandboxapi.CategoryPackBlock, "on the pack's block list"
	case packs.BlockFromRepoPolicy:
		return sandboxapi.CategoryRepoPolicyBlock, "on the repository policy's block list, " + packs.RepoPolicyPath
	case packs.BlockFromFirewall:
		return sandboxapi.CategoryFirewallBlock, "a deny rule of the host egress firewall"
	}
	return "", ""
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
