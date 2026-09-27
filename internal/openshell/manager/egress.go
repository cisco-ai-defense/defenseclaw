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
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// feedMatcher adapts the egress proxy's builtin blocklist to the packs
// FeedMatcher, so approvals and unblocks are checked against exactly what
// the proxy blocks.
func (m *Manager) feedMatcher() packs.FeedMatcher {
	feed, err := egress.BuiltinBlocklist()
	return func(feeds []string, host string) (string, bool) {
		if err != nil || !slices.Contains(feeds, packs.FeedBuiltin) {
			return "", false
		}
		match, ok := feed.Match(host)
		if !ok {
			return "", false
		}
		return match.Entry.Name, true
	}
}

// Decider builds the egress decider from the configured posture and the
// live sandboxes: the administrator's and every sandbox pack's block lists
// apply to all sandboxes (a union can only block more), the configured
// allow list applies to all, and each sandbox's own allow list and
// unblocks reach only that sandbox through the unblock index.
func (m *Manager) Decider() (*egress.Decider, error) {
	cfg := m.config()
	base, err := m.baseEffective(cfg)
	if err != nil {
		return nil, err
	}
	opts := egress.DeciderOptions{
		Mode:  egress.ModeOpen,
		Ports: base.Egress.Ports,
		// "Always" decisions are unblocks, never operator allows: an allow
		// entry opens the private addresses its name resolves to, an
		// unblock only lifts blocklist and allowlist refusals.
		Unblocks: unblockIndex{m: m, always: proxyPatterns(cfg.OpenShell.Egress.Unblocked)},
	}
	if base.NetworkMode == packs.NetworkAllowlist {
		opts.Mode = egress.ModeAllowlist
	}
	if !slices.Contains(base.Egress.Feeds, packs.FeedBuiltin) {
		opts.Blocklists = []*egress.Feed{}
	}
	block := append(append([]string{}, base.Egress.AdminBlock...), base.Egress.Block...)
	allow := append([]string{}, base.Egress.Allow...)
	ports := append([]int{}, base.Egress.Ports...)
	m.mu.Lock()
	for _, b := range m.boxes {
		if b.eff == nil || b.deleted {
			continue
		}
		block = append(block, b.eff.Egress.Block...)
		for _, p := range b.eff.Egress.Ports {
			if !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	m.mu.Unlock()
	if len(base.Egress.AllowOnly) > 0 {
		// Nothing outside the administrator's list is reachable.
		opts.Mode = egress.ModeAllowlist
		opts.Allowlists = []*egress.Feed{}
		allow = append([]string{}, base.Egress.AllowOnly...)
	}
	opts.Block = proxyPatterns(block)
	opts.Allow = proxyPatterns(allow)
	opts.Ports = ports
	return egress.NewDecider(opts)
}

// proxyPatterns converts pack host globs to proxy patterns: "*" (every
// host) has no proxy form and is dropped, which only matters for allow
// lists (packs never let it through).
func proxyPatterns(globs []string) []string {
	var out []string
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" || g == "*" {
			continue
		}
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// refreshEgress re-resolves every sandbox's policy and swaps in a new
// decider. It runs after creates, deletes and configuration changes.
func (m *Manager) refreshEgress() {
	cfg := m.opts.Config()
	m.mu.Lock()
	m.cfgSeen = cfg
	boxes := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		if !b.creating && !b.deleted {
			boxes = append(boxes, b)
		}
	}
	proxy := m.proxy
	m.mu.Unlock()
	for _, b := range boxes {
		eff, err := m.resolveBox(b)
		if err != nil {
			continue
		}
		m.mu.Lock()
		cred, rec := b.cred, b.rec
		m.mu.Unlock()
		if cred.Username != "" && rec.BindingID != "" {
			_ = m.creds.Register(cred, m.principal(rec.BindingID, scopeID(rec.ID, rec.Name), rec.Name, eff))
		}
	}
	if proxy == nil {
		return
	}
	d, err := m.Decider()
	if err != nil {
		m.logf("egress decider: %v", err)
		return
	}
	if err := proxy.SetDecider(d); err != nil {
		m.logf("egress decider: %v", err)
	}
}

// unblockIndex serves the Decider's unblock lookups: sandbox-scoped and
// persistent unblocks (always, openshell.egress.unblocked), and each
// sandbox's own pack allow list. Nothing is unblocked when the
// administrator forbids unblocking, and nothing outside an administrator
// allow-only list.
type unblockIndex struct {
	m      *Manager
	always []string
}

func (u unblockIndex) Unblocked(p egress.Principal, host string) (egress.Unblock, bool) {
	m := u.m
	m.mu.Lock()
	var b *box
	if p.SandboxName != "" {
		b = m.boxes[p.SandboxName]
	}
	var eff *packs.Effective
	if b != nil {
		eff = b.eff
	}
	m.mu.Unlock()
	if eff == nil {
		return egress.Unblock{}, false
	}
	if triage.CheckUnblock(eff, host) != nil {
		return egress.Unblock{}, false
	}
	if len(eff.Egress.AllowOnly) > 0 && !packs.MatchAnyHost(eff.Egress.AllowOnly, host) {
		return egress.Unblock{}, false
	}
	if ub, ok := m.unblocks.Unblocked(p, host); ok {
		return ub, true
	}
	for _, glob := range u.always {
		if packs.MatchHost(glob, host) {
			return egress.Unblock{Pattern: glob}, true
		}
	}
	for _, glob := range eff.Egress.Allow {
		if packs.MatchHost(glob, host) {
			return egress.Unblock{Pattern: glob, SandboxID: p.SandboxID}, true
		}
	}
	return egress.Unblock{}, false
}

// Unblock lifts an egress block for one sandbox or, with Always, for every
// sandbox (the host joins openshell.egress.unblocked).
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
		if eff, err = m.resolveBox(b); err != nil {
			return nil, err
		}
	} else if eff, err = m.baseEffective(m.config()); err != nil {
		return nil, err
	}
	if err := triage.CheckUnblock(eff, host); err != nil {
		return nil, m.violationError(ctx, err, req.Sandbox)
	}
	if req.Always {
		if err := triage.CheckApproval(eff, host, 0, true, m.feedMatcher()); err != nil && !triage.IsHostLocal(host) {
			return nil, m.violationError(ctx, err, req.Sandbox)
		}
	}
	// Guard and operator blocks (private networks, this machine, the
	// administrator's blocklist) are never lifted by an unblock.
	probe := egress.Principal{BindingID: "unblock-probe", SandboxName: req.Sandbox}
	if b != nil {
		m.mu.Lock()
		probe = m.principal(b.rec.BindingID, scopeID(b.rec.ID, b.rec.Name), b.rec.Name, eff)
		m.mu.Unlock()
	}
	if d, derr := m.Decider(); derr == nil {
		dec := d.Decide(probe, host, 443)
		if !dec.Allowed && !dec.Unblockable && (dec.Source == egress.SourceGuard || dec.Source == egress.SourceOperator) {
			return nil, &sandboxapi.Error{Code: sandboxapi.CodePolicyViolation,
				Message: host + " cannot be unblocked", Detail: dec.Reason}
		}
	}
	resp := &sandboxapi.UnblockResponse{Host: host, Sandbox: req.Sandbox}
	var ident audit.SandboxIdentity
	if req.Always {
		if err := m.persistAllow(ctx, host); err != nil {
			return nil, err
		}
		if err := m.unblocks.Add(egress.Unblock{Pattern: host, CreatedAt: m.now().UTC()}); err != nil {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "%v", err)
		}
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
			b.rec.Unblocks = append(b.rec.Unblocks, host)
		}
		rec := b.rec
		m.mu.Unlock()
		if err := m.records.save(&rec); err != nil {
			m.logf("save unblock of %s: %v", rec.Name, err)
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
	_ = m.tel.RecordSandboxPolicy(ctx, audit.SandboxPolicyEvent{
		Sandbox: ident, Operation: audit.SandboxEgressUnblock, Actor: "operator", Origin: "api", Target: host,
		Reason: "SANDBOX_EGRESS_UNBLOCK", ChangeCount: 1, Timestamp: m.now(),
	})
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
				Source: sandboxapi.SourceProxy, Category: string(e.Category), Rule: e.Rule, Unblockable: blocked && unblockable(e),
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

// unblockable reports proxy refusals an unblock can lift: feed entries and
// the mode defaults (allowlist misses, open-mode IP literals).
func unblockable(e egress.Event) bool {
	return e.Source == egress.SourceFeed || e.Source == egress.SourceDefault
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
func (m *Manager) LargeUploadBytes() int64 {
	eff, err := m.baseEffective(m.config())
	if err != nil {
		return egress.DefaultLargeUploadBytes
	}
	if eff.Egress.LargeUploadMB <= 0 {
		return -1
	}
	return int64(eff.Egress.LargeUploadMB) << 20
}
