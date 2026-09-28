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
	"net"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

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
			// resolveBox revoked the credential (policyUnresolved).
			continue
		}
		m.syncCredential(b, eff)
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
// current principal and decider, or revokes it while the sandbox's network
// mode is deny (the strict profile, for example after an administrator
// raised min_profile) or it has no decider: the proxy then refuses the
// sandbox altogether instead of serving it under another policy.
func (m *Manager) syncCredential(b *box, eff *packs.Effective) {
	m.mu.Lock()
	cred, rec, d := b.cred, b.rec, b.decider
	m.mu.Unlock()
	if cred.Username == "" || rec.BindingID == "" || eff == nil {
		return
	}
	if eff.NetworkMode == packs.NetworkDeny || d == nil {
		m.creds.Revoke(rec.BindingID)
	} else {
		_ = m.creds.Register(cred, m.principal(rec.BindingID, scopeID(rec.ID, rec.Name), rec.Name, d, eff))
	}
	m.recheckEgress(rec.BindingID)
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
// proxy's goroutines: the proxy must never block on either.
type egressSink struct {
	m       *Manager
	ch      chan egress.Event
	dropped atomic.Uint64
}

const egressSinkBuffer = 4096

func newEgressSink(m *Manager) *egressSink {
	return &egressSink{m: m, ch: make(chan egress.Event, egressSinkBuffer)}
}

// EgressEvent implements egress.EventSink.
func (s *egressSink) EgressEvent(e egress.Event) {
	select {
	case s.ch <- e:
	default:
		if n := s.dropped.Add(1); n == 1 || n%1000 == 0 {
			s.m.logf("egress telemetry backlog: %d events dropped", n)
		}
	}
}

func (s *egressSink) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.ch:
			s.m.egressEvent(ctx, e)
		}
	}
}

func (m *Manager) egressEvent(ctx context.Context, e egress.Event) {
	m.mu.Lock()
	b := m.boxes[e.SandboxName]
	var ident audit.SandboxIdentity
	if b != nil {
		ident = b.identity()
		if e.Kind == egress.EventAllowed || e.Kind == egress.EventClosed {
			b.activeAt = m.now()
			m.noteWorkLocked(b)
		}
	}
	m.mu.Unlock()
	if b == nil {
		return
	}
	switch e.Kind {
	case egress.EventAllowed, egress.EventBlocked:
		blocked := e.Kind == egress.EventBlocked
		ev := audit.SandboxEgressEvent{
			Sandbox: ident, Source: audit.SandboxEgressSourceProxy, Host: e.Host, Port: e.Port,
			Scheme: egressScheme(e), ResolvedIP: remoteIP(e.RemoteAddr), Blocked: blocked,
			DecisionCode: decisionCode(e), Reason: truncate(e.Reason, 512),
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
				msg = "✗ " + e.Host + " (" + categoryText(e) + ")"
			}
			m.feed.Publish(sandboxapi.ActivityEvent{
				Time: e.Time, Kind: kind, Sandbox: e.SandboxName, Host: e.Host, Port: e.Port, Method: e.Method,
				Source: sandboxapi.SourceProxy, Category: string(e.Category), Rule: e.Rule, Unblockable: blocked && e.Unblockable,
				Reason: truncate(e.Reason, 300), Message: msg,
			})
		}
	case egress.EventLargeUpload:
		severity := "MEDIUM"
		if e.Terminated {
			severity = "HIGH"
		}
		_ = m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
			Sandbox: ident, Kind: audit.SandboxFindingLargeUpload, Severity: severity,
			Title:       "Large upload to a first-seen destination",
			Description: fmt.Sprintf("%s sent %d bytes to %s, which it had not contacted before.", e.SandboxName, e.BytesUp, e.Host),
			Evidence:    truncate(e.Reason, 512), TargetRef: e.Host,
			Remediation: "Review what the agent uploaded; block the destination if it is not expected.",
			Timestamp:   e.Time,
		})
		m.feed.Publish(sandboxapi.ActivityEvent{Time: e.Time, Kind: sandboxapi.ActivityEgressLargeUpload, Sandbox: e.SandboxName,
			Host: e.Host, Port: e.Port, Source: sandboxapi.SourceProxy, BytesUp: e.BytesUp, Severity: severity,
			Message: fmt.Sprintf("⚠ large upload to first-seen %s (%d bytes)", e.Host, e.BytesUp)})
	}
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
