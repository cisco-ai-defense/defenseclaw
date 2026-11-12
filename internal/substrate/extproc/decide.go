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

package extproc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// Categories the callout adds to the egress Decider's (egress.Category).
// The set is closed: it labels telemetry.
const (
	CategoryUnattributed    = "unattributed"
	CategoryActorNotLive    = "actor_not_live"
	CategoryActorUnverified = "actor_unverified"
	CategoryURLRule         = "url_rule"
	CategoryChainEgress     = "chain_egress"
	CategoryAskDenied       = "ask_denied"
	CategoryAskPending      = "ask_pending"
	CategoryMCPToolBlocked  = "mcp_tool_blocked"
	CategoryCalloutError    = "callout_error"
)

// Decision sources the callout adds to egress.Source.
const (
	sourceIdentity = "identity"
	sourceProfile  = "profile"
	sourceDLP      = "dlp"
	sourceChain    = "chain"
	sourceAsk      = "ask"
	sourceTool     = "tool_rules"
	sourceCallout  = "callout"
	sourceOwnHost  = "defenseclaw"
)

// Header is one request header, its name in lower case.
type Header struct {
	Name  string
	Value string
}

// Request is the part of a request the Engine decides on.
type Request struct {
	Actor       ActorRef
	IdentityErr error
	Method      string
	Scheme      string
	Authority   string
	// Path is :path, query included.
	Path string
	// Host is the normalized :authority host; empty when invalid.
	Host    string
	Headers []Header
	// ContentLength is -1 when the request did not say.
	ContentLength int64
	ContentType   string
	Accept        string
	// EndOfStream marks a request with no body.
	EndOfStream bool
	Start       time.Time
}

func (r *Request) header(name string) string {
	for _, h := range r.Headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

// Verdict is the Engine's decision for a request.
type Verdict struct {
	Allow bool
	// Alert marks an allowed request with findings worth an alert.
	Alert bool
	// OwnHost marks a DefenseClaw host: no mutation, no chain step.
	OwnHost     bool
	Category    string
	Source      string
	Rule        string
	Reason      string
	Feed        string
	FeedVersion string
	// AdminRule is the organization's list that refused (egress_block,
	// egress_allow_only), for the managed refusal text.
	AdminRule string
	Profile   string
	AskID     string
	Findings  []string
	// Retryable refusals (the callout could not decide) answer 503.
	Retryable bool
	// WantBody asks the server to switch the request to buffered body mode.
	WantBody      bool
	BodyInspected bool
	BodyOverCap   bool
}

// Options configure an Engine. Nil interfaces get the interim behaviour:
// no UID resolution, no asks (an ask-required host is refused, D12), no
// chain state, no tool judge (MCP bodies get the DLP scans only).
type Options struct {
	Config       *Config
	Policies     PolicySource
	UIDs         UIDResolver
	Asks         AskSink
	ChainSink    ChainSink
	ChainChecker ChainChecker
	Judge        ToolJudge
	Events       EventSink
	Now          func() time.Time
}

// Engine decides requests. It is safe for concurrent use.
type Engine struct {
	cfg       *Config
	policies  PolicySource
	uids      *UIDCache
	asks      AskSink
	chain     *chainQueue
	checker   ChainChecker
	judge     ToolJudge
	events    EventSink
	red       *Redactor
	secrets   *secretValues
	dcHosts   *hostMatcher
	mcpHosts  *hostMatcher
	bodyHosts *hostMatcher
	mcpNames  map[string]string
	bindings  []binding
	body      *bodyMode
	now       func() time.Time
}

// NewEngine builds an Engine and starts its chain worker; Close stops it.
func NewEngine(o Options) (*Engine, error) {
	cfg := o.Config
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	e := &Engine{cfg: cfg, policies: o.Policies, asks: o.Asks, checker: o.ChainChecker, judge: o.Judge,
		events: o.Events, now: o.Now, mcpNames: map[string]string{}}
	if e.now == nil {
		e.now = time.Now
	}
	if e.policies == nil {
		sp, err := NewStaticPolicies(cfg)
		if err != nil {
			return nil, err
		}
		e.policies = sp
	}
	e.uids = NewUIDCache(o.UIDs, cfg.UID.CacheTTL, cfg.UID.StaleMax)
	e.uids.now = e.now
	e.secrets = newSecretValues(cfg.ActorSecretsDir)
	e.secrets.now = e.now
	e.red = newRedactor(cfg, e.secrets)
	e.dcHosts = mustHostMatcher(cfg.DefenseClawHosts)
	e.mcpHosts = mustHostMatcher(mcpHostNames(cfg.MCPHosts))
	e.bodyHosts = mustHostMatcher(cfg.BodyHosts)
	for _, entry := range cfg.MCPHosts {
		h, name, _ := strings.Cut(entry, "=")
		if nh, _, err := normalizeHost(h); err == nil && strings.TrimSpace(name) != "" {
			e.mcpNames[nh] = strings.TrimSpace(name)
		}
	}
	e.bindings = compileBindings(cfg.Secrets)
	e.body = newBodyMode(cfg.BodyInspection, e.now)
	e.chain = newChainQueue(o.ChainSink, cfg.Chain.QueueSize)
	return e, nil
}

// Close stops the chain worker after it drains.
func (e *Engine) Close() { e.chain.close() }

// Redactor returns the engine's redactor.
func (e *Engine) Redactor() *Redactor { return e.red }

// BodyModeStatus is the body-mode detection state (for readiness and
// doctor): off, unknown, supported or unsupported.
func (e *Engine) BodyModeStatus() string { return e.body.status() }

// InvalidateActor is the lifecycle hook: a deleted, recreated or forked
// actor's cached UID is dropped.
func (e *Engine) InvalidateActor(atespace, name string) { e.uids.Invalidate(atespace, name) }

// ChainDropped is how many observed_egress steps the full queue dropped.
func (e *Engine) ChainDropped() uint64 { return e.chain.droppedCount() }

func deny(v Verdict, category, source, rule, reason string) Verdict {
	v.Allow, v.Alert = false, false
	v.Category, v.Source, v.Rule, v.Reason = category, source, rule, reason
	v.WantBody = false
	return v
}

// failure applies the failure mode to a request the callout could not
// decide: refused (retryable) when closed, allowed with an alert when open.
func (e *Engine) failure(v Verdict, category, reason string) Verdict {
	if e.cfg.FailureMode == FailureOpen {
		v.Allow, v.Alert = true, true
		v.Findings = append(v.Findings, category)
		return v
	}
	v = deny(v, category, sourceCallout, "", reason)
	v.Retryable = true
	return v
}

// DecideHeaders decides a request on its headers.
func (e *Engine) DecideHeaders(ctx context.Context, req *Request) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			v = e.failure(Verdict{}, CategoryCalloutError, "The DefenseClaw egress callout hit an internal error.")
		}
	}()
	if req.IdentityErr != nil {
		return deny(v, CategoryUnattributed, sourceIdentity, "",
			"The request carries no actor identity from the Substrate egress gateway, so DefenseClaw can't tell whose it is.")
	}
	if req.Host == "" {
		return deny(v, string(egress.CategoryInvalidDestination), string(egress.SourceGuard), "", egress.CategoryInvalidDestination.Reason())
	}
	if _, ok := e.dcHosts.match(req.Host); ok {
		// The actor listener: the gateway verifies the JWT and inspects the
		// hook or model call itself. Never buffered (model streams).
		return Verdict{Allow: true, OwnHost: true, Source: sourceOwnHost}
	}
	uid, err := e.uids.Resolve(ctx, req.Actor)
	switch {
	case errors.Is(err, ErrActorNotLive):
		return deny(v, CategoryActorNotLive, sourceIdentity, "",
			"The Substrate Control API reports no running actor with this name.")
	case err != nil:
		return e.failure(v, CategoryActorUnverified,
			"The Substrate Control API could not confirm that this actor is running.")
	}
	req.Actor.UID = uid
	pol, err := e.policies.PolicyFor(ctx, req.Actor)
	if err != nil || pol == nil {
		return e.failure(v, CategoryCalloutError, "DefenseClaw could not load this actor's policy.")
	}
	v.Profile = pol.Name

	d := pol.decider.DecideHost(egress.Principal{SandboxName: req.Actor.Name}, req.Host)
	if !d.Allowed {
		v = deny(v, string(d.Category), string(d.Source), d.Rule, d.Reason)
		v.Feed, v.FeedVersion, v.AdminRule = d.Feed, d.FeedVersion, egress.AdminRule(d.Category)
		return v
	}

	askRule := ""
	reqPath := req.Path
	if i := strings.IndexAny(reqPath, "?#"); i >= 0 {
		reqPath = reqPath[:i]
	}
	for _, r := range pol.urlRules {
		if !r.matches(req.Host, req.Method, reqPath) {
			continue
		}
		switch r.action {
		case "deny":
			return deny(v, CategoryURLRule, sourceProfile, r.name,
				"This actor's profile does not allow "+req.Method+" requests to this path on "+req.Host+".")
		case "ask":
			askRule = "url_rules:" + r.name
		}
		break
	}

	for _, f := range append(e.scanURL(req, pol), e.scanHeaders(req, pol)...) {
		if f.deny {
			return deny(v, f.kind, sourceDLP, f.where, dlpReason(f))
		}
		v.Alert = true
		v.Findings = append(v.Findings, f.String())
	}

	if cv, hit := e.checkChain(ctx, ChainStep{Kind: StepObservedEgress, Actor: req.Actor, Host: req.Host,
		Method: req.Method, Allowed: true, Time: e.now()}); hit {
		reason := cv.Reason
		if reason == "" {
			reason = "Earlier in this session the actor read a secret; DefenseClaw blocks sending data off the cluster after that."
		}
		return deny(v, CategoryChainEgress, sourceChain, cv.Rule, clip(reason, 320))
	}

	if askRule == "" {
		if pat, ok := pol.askHosts.match(req.Host); ok {
			askRule = "ask_hosts:" + pat
		}
	}
	if askRule != "" {
		v = e.ask(ctx, v, req, pol, askRule)
		if !v.Allow {
			return v
		}
	}

	v.Allow = true
	if v.Source == "" {
		v.Source = string(d.Source)
	}
	v.WantBody, v.BodyOverCap = e.wantBody(req)
	if v.BodyOverCap {
		v.Findings = append(v.Findings, "body_over_cap")
	}
	return v
}

func (e *Engine) ask(ctx context.Context, v Verdict, req *Request, pol *Policy, rule string) Verdict {
	if e.asks == nil {
		// No approvals service yet: an unanswerable ask is a denial (D12).
		return deny(v, CategoryAskDenied, sourceAsk, rule, "This host needs an approval, and no approvals service is configured.")
	}
	actx, cancel := context.WithTimeout(ctx, e.cfg.Ask.Hold)
	defer cancel()
	res, err := e.asks.Ask(actx, AskRequest{Actor: req.Actor, Profile: pol.Name, Host: req.Host, Method: req.Method,
		Rule: rule, UnattendedAsks: pol.UnattendedAsks})
	v.AskID = res.ID
	switch {
	case err != nil && !errors.Is(err, context.DeadlineExceeded):
		return e.failure(v, CategoryCalloutError, "DefenseClaw could not raise the approval this host needs.")
	case res.Outcome == AskApproved:
		v.Allow, v.Source = true, sourceAsk
		return v
	case res.Outcome == AskDenied:
		reason := "The approval this host needs was denied."
		if res.Reason != "" {
			reason = clip(res.Reason, 320)
		}
		return deny(v, CategoryAskDenied, sourceAsk, rule, reason)
	}
	return deny(v, CategoryAskPending, sourceAsk, rule, "This host needs an approval that has not been given yet.")
}

// wantBody reports whether the request qualifies for body mode (D9) and
// whether it is over the cap. MCP and admin-listed hosts only; a request
// with a body of known length up to the cap; never an SSE or gRPC stream.
func (e *Engine) wantBody(req *Request) (want, overCap bool) {
	_, mcp := e.mcpHosts.match(req.Host)
	_, listed := e.bodyHosts.match(req.Host)
	if !mcp && !listed {
		return false, false
	}
	if req.EndOfStream || req.ContentLength == 0 {
		return false, false
	}
	ct := strings.ToLower(req.ContentType)
	if strings.Contains(ct, "text/event-stream") || strings.HasPrefix(ct, "application/grpc") ||
		strings.HasPrefix(ct, "multipart/") {
		return false, false
	}
	if mcp && !strings.Contains(ct, "json") {
		return false, false
	}
	switch m := req.Method; m {
	case "POST", "PUT", "PATCH":
	default:
		return false, false
	}
	if req.ContentLength < 0 {
		// Unknown length: Envoy would buffer without a bound we can check.
		return false, true
	}
	if req.ContentLength > e.cfg.BodyMaxBytes {
		return false, true
	}
	return e.body.want(), false
}

// DecideBody decides a request again on its buffered body; v is its headers
// verdict.
func (e *Engine) DecideBody(ctx context.Context, req *Request, v Verdict, body []byte) (out Verdict) {
	defer func() {
		if r := recover(); r != nil {
			out = e.failure(v, CategoryCalloutError, "The DefenseClaw egress callout hit an internal error.")
		}
	}()
	v.WantBody = false
	if int64(len(body)) > e.cfg.BodyMaxBytes {
		v.BodyOverCap = true
		v.Findings = append(v.Findings, "body_over_cap")
		return v
	}
	v.BodyInspected = true
	pol, err := e.policies.PolicyFor(ctx, req.Actor)
	if err != nil || pol == nil {
		return e.failure(v, CategoryCalloutError, "DefenseClaw could not load this actor's policy.")
	}
	for _, f := range e.scanBody(req, pol, body) {
		if f.deny {
			return deny(v, f.kind, sourceDLP, f.where, dlpReason(f))
		}
		v.Alert = true
		v.Findings = append(v.Findings, f.String())
	}
	if _, mcp := e.mcpHosts.match(req.Host); !mcp {
		return v
	}
	calls, err := parseToolCalls(body)
	if err != nil {
		return deny(v, CategoryMCPToolBlocked, sourceTool, "jsonrpc", clip(err.Error(), 320))
	}
	if len(calls) == 0 {
		return v
	}
	if e.judge == nil {
		v.Findings = append(v.Findings, "tool_rules_not_configured")
		return v
	}
	server := e.mcpNames[req.Host]
	if server == "" {
		server = req.Host
	}
	for _, c := range calls {
		jctx, cancel := context.WithTimeout(ctx, e.cfg.Judge.Timeout)
		tv, err := e.judge.JudgeToolCall(jctx, ToolCall{Actor: req.Actor, Server: server, Host: req.Host, Tool: c.name, Args: c.args})
		cancel()
		if err != nil {
			return e.failure(v, CategoryCalloutError, "DefenseClaw could not check this MCP tool call against its tool rules.")
		}
		if tv.Block {
			reason := "DefenseClaw's tool rules refused the MCP tool call " + strconv.Quote(clip(c.name, 64)) + "."
			if tv.Reason != "" {
				reason += " " + clip(tv.Reason, 240)
			}
			return deny(v, CategoryMCPToolBlocked, sourceTool, "tools/call:"+clip(c.name, 64), reason)
		}
		if tv.Alert {
			// The hooks' alert action: allowed, recorded.
			v.Alert = true
			v.Findings = append(v.Findings, "tool_rules_alert:"+clip(c.name, 64))
		}
	}
	return v
}

func dlpReason(f finding) string {
	switch f.kind {
	case findSecretInURL:
		return fmt.Sprintf("The URL carries a secret-shaped value (%s).", f.label)
	case findSecretInHeader, findSecretInCredential:
		return fmt.Sprintf("A request header carries a secret-shaped value (%s).", f.label)
	case findSecretInBody:
		return fmt.Sprintf("The request body carries a secret-shaped value (%s).", f.label)
	case findActorSecret:
		return fmt.Sprintf("The request carries the value of the actor secret %s, which must not leave the cluster.", f.label)
	}
	return "The request carries data DefenseClaw does not let leave the cluster."
}

// clip bounds s for a reason: printable characters only, at most n bytes.
func clip(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			r = ' '
		}
		if b.Len()+len(string(r)) > n {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
