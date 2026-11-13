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
	CategoryURLRule         = "url_rule"
	CategoryPathAmbiguous   = "path_ambiguous"
	CategoryChainEgress     = "chain_egress"
	CategoryChainUnchecked  = "chain_unchecked"
	CategoryAskDenied       = "ask_denied"
	CategoryAskPending      = "ask_pending"
	CategoryMCPToolBlocked  = "mcp_tool_blocked"
	CategoryBodyUninspected = "body_uninspectable"
	CategoryCalloutError    = "callout_error"
	CategoryInternalHost    = "defenseclaw_internal"
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
	// ID names the request in its event and in the tool verdict call.
	ID          string
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
	cfg        *Config
	policies   PolicySource
	uids       *UIDCache
	asks       AskSink
	chain      *chainQueue
	checker    ChainChecker
	judge      ToolJudge
	events     EventSink
	red        *Redactor
	secrets    *secretValues
	dcHosts    *hostMatcher
	internal   *hostMatcher
	mcpHosts   *hostMatcher
	bodyHosts  *hostMatcher
	mcpNames   map[string]string
	bindings   []binding
	body       *bodyMode
	chainLimit chainLimiter
	now        func() time.Time
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
	e.internal = mustHostMatcher(cfg.InternalHosts)
	e.mcpHosts = mustHostMatcher(mcpHostNames(cfg.MCPHosts))
	e.bodyHosts = mustHostMatcher(cfg.BodyHosts)
	for _, entry := range cfg.MCPHosts {
		h, name, _ := strings.Cut(entry, "=")
		if nh, _, err := normalizeHost(h); err == nil && strings.TrimSpace(name) != "" {
			e.mcpNames[nh] = strings.TrimSpace(name)
		}
	}
	e.bindings = compileBindings(cfg.Secrets)
	e.body = newBodyMode(cfg.BodyInspection)
	e.chain = newChainQueue(o.ChainSink, cfg.Chain.QueueSize)
	return e, nil
}

// Close stops the chain worker after it drains.
func (e *Engine) Close() { e.chain.close() }

// Redactor returns the engine's redactor.
func (e *Engine) Redactor() *Redactor { return e.red }

// BodyModeStatus is the body-mode detection state (for readiness and
// doctor): off, unknown or supported.
func (e *Engine) BodyModeStatus() string { return e.body.status() }

// Degraded names what the callout can't do now, for readiness and doctor:
// "mcp_refused_until_body_support" while closed-mode auto refuses MCP
// requests to listed hosts (GAP-0146), "" otherwise.
func (e *Engine) Degraded() string {
	if e.closedAuto() && len(e.cfg.MCPHosts) > 0 && !e.body.confirmed() {
		return "mcp_refused_until_body_support"
	}
	return ""
}

// closedAuto is a managed enterprise callout that fails closed with
// body_inspection auto: it may not forward an MCP body it was never shown
// it can read (GAP-0146). OSS installs ask for the body and alert when it
// does not come (balanced defaults).
func (e *Engine) closedAuto() bool {
	return e.cfg.Managed && e.cfg.FailureMode == FailureClosed && e.cfg.BodyInspection == BodyAuto
}

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

// DecideHeaders decides a request on its headers, within MessageBudget.
func (e *Engine) DecideHeaders(ctx context.Context, req *Request) (v Verdict) {
	ctx, cancel := context.WithTimeout(ctx, MessageBudget)
	defer cancel()
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
	if _, ok := e.internal.match(req.Host); ok {
		// D15: the admin listener is never reachable from an actor, even
		// if a policy or a looser NetworkPolicy would let it through.
		return deny(v, CategoryInternalHost, sourceOwnHost, "",
			"Actors can't reach this DefenseClaw service; it is for people and DefenseClaw itself.")
	}
	if _, ok := e.dcHosts.match(req.Host); ok {
		// The actor listener: the gateway verifies the JWT and inspects the
		// hook or model call itself. Never buffered (model streams).
		return Verdict{Allow: true, OwnHost: true, Source: sourceOwnHost}
	}
	// The registration names the actor's UID (its chain window), profile and
	// attendance (GAP-0090). A lookup outage (the leader, past the stale
	// window) does not stop the actor's traffic: the actor is matched by
	// atespace, and only its chain check is missing, which
	// chain.failure_mode decides (refused on a managed install).
	rec, err := e.uids.Resolve(ctx, req.Actor)
	lookupDown := false
	switch {
	case errors.Is(err, ErrActorNotLive):
		return deny(v, CategoryActorNotLive, sourceIdentity, "",
			"DefenseClaw's registrations say this actor was deleted.")
	case err != nil:
		lookupDown = true
		v.Alert = true
		v.Findings = append(v.Findings, "registration_unavailable")
	}
	req.Actor.UID, req.Actor.Profile, req.Actor.Unattended = rec.UID, rec.Profile, rec.Unattended
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
	// URL rules match the canonical path (GAP-0046): an equivalent
	// spelling (/./admin, /%61dmin, //admin) matches like the plain one, and
	// a path an origin could read another way is refused where a path rule
	// applies.
	reqPath, pathErr := canonicalPath(pathOnly(req.Path))
	methods := requestMethods(req)
	for _, r := range pol.urlRules {
		if !r.appliesTo(req.Host, methods) {
			continue
		}
		if r.pathPrefix != "" {
			if pathErr != nil {
				return deny(v, CategoryPathAmbiguous, sourceProfile, r.name,
					"The request path uses an ambiguous encoding (an encoded slash, backslash, semicolon, percent sign or control character, or a dot segment with parameters), so DefenseClaw can't check it against this profile's path rules for "+req.Host+".")
			}
			if !r.matchesPath(reqPath) {
				continue
			}
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

	cv, outcome, chainWhy := e.checkChain(ctx, ChainStep{Kind: StepObservedEgress, Actor: req.Actor, Host: req.Host,
		Method: req.Method, Allowed: true, Time: e.now()})
	if lookupDown && e.checker != nil {
		outcome, chainWhy = chainUnchecked, uncheckedLookup
	}
	switch outcome {
	case chainHit:
		reason := cv.Reason
		if reason == "" {
			reason = "Earlier in this session the actor read a secret; DefenseClaw blocks sending data off the cluster after that."
		}
		return deny(v, CategoryChainEgress, sourceChain, cv.Rule, clip(reason, 320))
	case chainUnchecked:
		// The step still reaches the window through the observed_egress
		// queue (Finish); only this request's check is missing.
		if e.chainFailClosed(pol) {
			v = deny(v, CategoryChainUnchecked, sourceChain, chainWhy,
				"DefenseClaw could not check this request against the actor's earlier tool calls in time, and this actor's policy refuses unchecked egress.")
			v.Retryable = true
			return v
		}
		v.Alert = true
		v.Findings = append(v.Findings, "chain_unchecked:"+chainWhy)
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
	var why string
	v.WantBody, why = e.wantBody(req)
	return e.uninspected(v, why)
}

// Why an inspected host's body is not inspected. The first two are framing
// the actor chose; the others are the deployment's.
const (
	whyOverCap    = "over_cap"
	whyStreaming  = "streaming_content_type"
	whyInspectOff = "body_inspection_off"
	// whyUnavailable: a managed closed callout, body_inspection auto and no
	// body has reached the callout yet (GAP-0146).
	whyUnavailable = "body_inspection_unavailable"
)

// uninspected applies GAP-0044 to a request on an MCP or admin-listed host
// whose body won't be inspected: inspect or refuse, never allow silently.
// Framing the actor controls (a body over the cap, a streaming content
// type) is refused when the failure mode is closed and an alert when open.
// body_inspection off is recorded; a filter that ignores the override is
// an alert when the stream ends without the body (Server.end).
func (e *Engine) uninspected(v Verdict, why string) Verdict {
	switch why {
	case "":
		return v
	case whyUnavailable:
		return deny(v, CategoryBodyUninspected, sourceCallout, why,
			"DefenseClaw checks the requests sent to this MCP server, and this cluster's egress has not shown that it sends request bodies to the check, so the request can't be inspected. An administrator sets substrate.extproc.body_inspection to on (Agent Substrate with the body opt-in) or off (headers only).")
	case whyOverCap, whyStreaming:
		v.BodyOverCap = why == whyOverCap
		if e.cfg.FailureMode == FailureClosed {
			reason := "DefenseClaw inspects the requests sent to this host, and this one's body is over the inspection limit, so it can't be checked."
			if why == whyStreaming {
				reason = "DefenseClaw inspects the requests sent to this host, and this one's body is a stream (event stream, gRPC or multipart), so it can't be checked."
			}
			return deny(v, CategoryBodyUninspected, sourceCallout, why, reason)
		}
		v.Alert = true
	}
	if why == whyOverCap {
		v.Findings = append(v.Findings, "body_over_cap")
	}
	v.Findings = append(v.Findings, "body_not_inspected:"+why)
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

// wantBody reports whether to buffer the request's body (D9), or why a body
// on an inspected host can't be. MCP and admin-listed hosts only. Every
// request with a body counts, whatever its method or content type and
// whether or not it states a length (GAP-0044: framing is the actor's
// choice): a request without Content-Length is buffered too, bounded by
// the egress filter's buffer and then by the cap in DecideBody. A stated
// length over the cap, and event-stream, gRPC and multipart bodies (never
// buffered, D9), can't be inspected.
func (e *Engine) wantBody(req *Request) (bool, string) {
	_, mcp := e.mcpHosts.match(req.Host)
	_, listed := e.bodyHosts.match(req.Host)
	if (!mcp && !listed) || req.EndOfStream {
		// No body: Envoy marks end of stream on the headers. A stated
		// Content-Length of 0 is not trusted on its own.
		return false, ""
	}
	ct := strings.ToLower(req.ContentType)
	if strings.Contains(ct, "text/event-stream") || strings.HasPrefix(ct, "application/grpc") ||
		strings.HasPrefix(ct, "multipart/") {
		return false, whyStreaming
	}
	if req.ContentLength > e.cfg.BodyMaxBytes {
		return false, whyOverCap
	}
	if !e.body.want() {
		return false, whyInspectOff
	}
	if mcp && e.closedAuto() && !e.body.confirmed() {
		// A stock egress filter would send this request on with its body
		// unread; nothing has shown that this one sends bodies (GAP-0146).
		return false, whyUnavailable
	}
	return true, ""
}

// DecideBody decides a request again on its buffered body; v is its headers
// verdict. Every tools/call of a batch is judged within one MessageBudget:
// a batch that does not fit follows the failure mode.
func (e *Engine) DecideBody(ctx context.Context, req *Request, v Verdict, body []byte) (out Verdict) {
	ctx, cancel := context.WithTimeout(ctx, MessageBudget)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			out = e.failure(v, CategoryCalloutError, "The DefenseClaw egress callout hit an internal error.")
		}
	}()
	v.WantBody = false
	if int64(len(body)) > e.cfg.BodyMaxBytes {
		// A body sent without a length, larger than the cap.
		return e.uninspected(v, whyOverCap)
	}
	// Inspect what the origin reads (GAP-0044): a gzip body or a UTF-8 BOM
	// is decoded, and a body that can't be is refused or alerted, never
	// passed as "no tool call".
	body, why := decodeBody(body, req.header("content-encoding"), req.ContentType, e.cfg.BodyMaxBytes)
	switch why {
	case "":
	case whyOverCap:
		return e.uninspected(v, whyOverCap)
	default:
		return e.unreadable(v, why)
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
	// The DLP scans ran on the decoded text; a tool call needs JSON the
	// callout can parse as the server will.
	if why := jsonRPCReadable(body); why != "" {
		return e.unreadable(v, why)
	}
	calls, err := parseToolCalls(body)
	if err != nil {
		return deny(v, CategoryMCPToolBlocked, sourceTool, "jsonrpc", clip(refusalReason(err), 320))
	}
	if len(calls) == 0 {
		return v
	}
	if e.judge == nil {
		// No rule path (callout.judge.tokenSecret turned off): the tool
		// rules can't run, so the call is never a silent allow
		// (GAP-0015). A managed install refuses it.
		if e.cfg.Managed {
			return deny(v, CategoryMCPToolBlocked, sourceTool, "tool_rules_not_configured",
				"DefenseClaw can't check this MCP tool call: the tool rules are not configured for the egress callout.")
		}
		v.Alert = true
		v.Findings = append(v.Findings, "tool_rules_not_configured")
		return v
	}
	server := e.mcpNames[req.Host]
	if server == "" {
		server = req.Host
	}
	// The verdict route matches MCP asset rules on the URL (scheme, host and
	// path, never the query) and ties its findings to the session and to
	// this request's event (GAP-0015).
	scheme := strings.ToLower(req.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	callURL := scheme + "://" + req.Host + pathOnly(req.Path)
	session := clip(req.header("mcp-session-id"), 128)
	for _, c := range calls {
		jctx, cancel := context.WithTimeout(ctx, e.cfg.Judge.Timeout)
		tv, err := e.judge.JudgeToolCall(jctx, ToolCall{Actor: req.Actor, Server: server, Host: req.Host, URL: callURL,
			Tool: c.name, Args: c.args, SessionID: session, RequestID: req.ID})
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
