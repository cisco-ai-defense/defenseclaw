// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// engineRouter is the production ModelRouter: the routing engine of the
// config generation a request pinned, built once per generation, so routing
// policy changes apply without a restart (DESIGN 8.2). Only the vLLM
// Semantic Router container (classifier vllm_sr) stays restart-bound; its
// client comes from the sidecar.
type engineRouter struct {
	boot       *config.Config
	classifier engine.Classifier // vllm_sr client, nil unless started
	dotenv     string
	sticky     *engine.StickyCache
	marks      *engine.StickyCache // routing.sensitive conversation marks
	// admin, when set (tests), is used for every generation instead of
	// the routing.admin evaluator compiled per generation (adminFor).
	admin engine.AdminEvaluator
	// judge returns the shared guardrail judge (the sensitivity check of
	// routing.sensitive.check: judge); logger writes the audit rows of
	// routing refusals and of a check that fired or could not answer. Both are set once at start.
	judge  func() *LLMJudge
	logger *audit.Logger

	mu sync.Mutex
	// cache keeps the engines of the last two generations, so requests
	// pinned to the previous generation during a swap do not rebuild.
	cache [2]*engineCacheEntry
}

type engineCacheEntry struct {
	gen uint64
	cfg *config.Config
	eng *engine.Engine
}

func newEngineRouter(boot *config.Config, classifier engine.Classifier, dotenv string) *engineRouter {
	return &engineRouter{boot: boot, classifier: classifier, dotenv: dotenv, sticky: engine.NewStickyCache(), marks: engine.NewSensitiveMarkCache()}
}

// SetAdminEvaluator installs the routing.admin rules and budgets evaluator
// (S11); nil narrows nothing. Engines built after the call use it.
func (r *engineRouter) SetAdminEvaluator(a engine.AdminEvaluator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.admin = a
	r.cache = [2]*engineCacheEntry{}
}

// SetJudgeSource installs the source of the guardrail judge model used by
// routing.sensitive.check judge. Engines built after the call use it.
func (r *engineRouter) SetJudgeSource(f func() *LLMJudge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.judge = f
	r.cache = [2]*engineCacheEntry{}
}

// SetAuditLogger installs the audit logger of sensitivity-check rows.
func (r *engineRouter) SetAuditLogger(l *audit.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logger = l
}

// engineFor returns the engine and config of the generation ctx pinned
// (the boot config when none is published). nil engine = routing off.
func (r *engineRouter) engineFor(ctx context.Context) (*engine.Engine, *config.Config) {
	if r == nil {
		return nil, nil
	}
	cfg, gen := r.boot, uint64(0)
	if g := pinnedGeneration(ctx); g.published() && g.Config != nil {
		cfg, gen = g.Config, g.N
	} else if g := currentGeneration(); g.published() && g.Config != nil {
		cfg, gen = g.Config, g.N
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.cache {
		if c != nil && c.gen == gen && c.cfg == cfg {
			return c.eng, c.cfg
		}
	}
	var eng *engine.Engine
	classifier := r.classifierFor(cfg)
	if cfg != nil && cfg.Routing.Enabled && cfg.Routing.EffectiveClassifier() == config.RoutingClassifierVLLMSR && classifier == nil &&
		!cfg.StandaloneEnterprise() {
		// The vLLM Semantic Router did not start: routing stays off, as in
		// 1.0.9 (health already reports the failure). A managed device keeps
		// the engine with no classifier, so every request takes the
		// classifier-failure path (the original request) while the admin
		// floor and Gate still judge it (S11 REVIEW-slice3 F12).
	} else {
		var err error
		eng, err = engine.New(cfg, engine.Options{
			Classifier:       classifier,
			Admin:            r.adminFor(cfg),
			Managed:          cfg != nil && cfg.StandaloneEnterprise(),
			Sticky:           r.sticky,
			SensitiveMarks:   r.marks,
			SensitiveChecker: r.sensitiveCheckerFor(cfg),
			CredentialOK:     func(b engine.Backend, req engine.Request) bool { return r.backendCredentialOK(cfg, b, req) },
			EndpointOK:       routeOnlyEndpointKnown,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "[routing] policy build failed, routing off for this generation: %v\n", err)
			eng = nil
		}
	}
	r.cache[1], r.cache[0] = r.cache[0], &engineCacheEntry{gen: gen, cfg: cfg, eng: eng}
	return eng, cfg
}

// Gate checks a forwarded exit against the admin verdict of the outcome
// (S11 rules and budgets); nil when nothing refuses it.
func (r *engineRouter) Gate(ctx context.Context, o SemanticRouteOutcome, target engine.GateTarget) *engine.DenyReason {
	if o.Route == nil {
		return nil
	}
	eng, _ := r.engineFor(ctx)
	return eng.Gate(*o.Route, target)
}

// classifierFor returns the classifier of cfg: the sidecar vLLM client for
// vllm_sr, a System One client built for this generation for systemone
// (its breaker restarts with the generation), nil for rules (in-process).
func (r *engineRouter) classifierFor(cfg *config.Config) engine.Classifier {
	if cfg == nil {
		return nil
	}
	switch cfg.Routing.EffectiveClassifier() {
	case config.RoutingClassifierVLLMSR:
		if r.classifier != nil {
			return r.classifier
		}
	case config.RoutingClassifierSystemOne:
		if c := newSystemOneClassifier(cfg, r.dotenv); c != nil {
			return c
		}
	}
	return nil
}

// RouterActive reports whether the generation of ctx routes at all; the
// proxy defers and rewrites only then.
func (r *engineRouter) RouterActive(ctx context.Context) bool {
	eng, _ := r.engineFor(ctx)
	return eng != nil
}

// backendKey resolves the gateway-held key of a backend: a protected
// credential on a standalone managed host, else api_key_env (key store,
// process env, data-dir .env). "" with no key reference means keyless.
func (r *engineRouter) backendKey(cfg *config.Config, b engine.Backend) string {
	if cfg != nil && cfg.StandaloneEnterprise() {
		if strings.TrimSpace(b.Credential) != "" || b.APIKeyEnv == "" {
			// A named credential is the only source, even when it is missing.
			return cfg.RoutingCredential(b.Credential)
		}
		// A 1.0.9 or 1.0.8 managed config names the key by api_key_env only;
		// keep its meaning (the service environment or the data-dir .env),
		// with a doctor warning to move it to a protected credential.
	}
	if b.APIKeyEnv == "" {
		return ""
	}
	return ResolveAPIKey(b.APIKeyEnv, r.dotenv)
}

// backendCredentialOK reports whether a call of req can authenticate to b:
// it has no key reference or its key resolves, and on the route-only
// listener the inbound credential class can reach it (routeOnlyCredentialFits).
func (r *engineRouter) backendCredentialOK(cfg *config.Config, b engine.Backend, req engine.Request) bool {
	key := r.backendKey(cfg, b)
	if key == "" && (b.APIKeyEnv != "" || b.Credential != "") {
		return false
	}
	return routeOnlyCredentialFits(req, b, key)
}

// backendKeyless reports whether b is a model called with no credential at
// all: no key reference, its own base_url, not Bedrock (Bedrock is signed
// or keyed), and either a loopback base_url (Ollama, vLLM on this host) or
// a request routing.sensitive narrowed (its local models are tried with no
// credential rather than falling back to the cloud, GAP-0576).
func backendKeyless(b engine.Backend, narrowed bool) bool {
	if b.APIKeyEnv != "" || strings.TrimSpace(b.Credential) != "" || strings.TrimSpace(b.BaseURL) == "" ||
		strings.EqualFold(strings.TrimSpace(b.Provider), "bedrock") || b.Bedrock != nil {
		return false
	}
	return narrowed || isLoopbackBaseURL(b.BaseURL)
}

func isLoopbackBaseURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// routeOnlyCredentialFits is the route-only credential rule (DESIGN 7.3)
// as an eligibility filter, so the engine skips a backend the route
// attempt could not authenticate to and `routing explain` shows the model
// actually used: a login token or Bedrock bearer key never crosses
// providers, and a gateway-held credential signs only Bedrock. A backend
// with its own key, or a keyless one, always fits.
func routeOnlyCredentialFits(req engine.Request, b engine.Backend, key string) bool {
	if req.Listener != engine.ListenerRouteOnly || key != "" || backendKeyless(b, req.Narrowed) {
		return true
	}
	same := strings.EqualFold(strings.TrimSpace(b.Provider), req.RequestedProvider)
	switch req.CredentialClass {
	case engine.CredentialOAuth, engine.CredentialBearer:
		return same
	case engine.CredentialGateway:
		return same || strings.EqualFold(strings.TrimSpace(b.Provider), "bedrock")
	}
	return true
}

// routeOnlyEndpointKnown is the route-only endpoint rule as an eligibility
// filter: the listener forwards the agent request unchanged in shape, so it
// sends a routed call to the model base_url, else to the upstream of the
// agent own provider, else to the public endpoint of the model provider.
// A model with none of these (a bedrock alias without base_url for a
// Responses or Messages call: Bedrock has no default endpoint for them) is
// skipped with filtered_by endpoint, so routing test, routing explain and the
// real call agree; before, the engine chose it and the call fell back to the
// original model with only a route_only_fallback:origin warning
// (rel-1-0-10:GAP-1167). Other listeners keep every backend.
func routeOnlyEndpointKnown(b engine.Backend, req engine.Request) bool {
	if req.Listener != engine.ListenerRouteOnly || originOf(b.BaseURL) != "" {
		return true
	}
	provider := strings.ToLower(strings.TrimSpace(b.Provider))
	return provider == strings.ToLower(req.RequestedProvider) || providerDefaultOrigins[provider] != ""
}

// Route implements ModelRouter.
func (r *engineRouter) Route(ctx context.Context, in *ModelRouterInput) *ModelRouterDecision {
	return r.RouteDetailed(ctx, in).Decision
}

// RouteDetailed implements detailedModelRouter.
func (r *engineRouter) RouteDetailed(ctx context.Context, in *ModelRouterInput) SemanticRouteOutcome {
	started := time.Now()
	out := SemanticRouteOutcome{Result: SemanticRouteFallback, FailureCode: SemanticRouteFailureConfig}
	if in != nil {
		out.RequestModel = strings.TrimSpace(in.RequestModel)
		if out.RequestModel == "" {
			out.RequestModel = strings.TrimSpace(in.Model)
		}
	}
	eng, cfg := r.engineFor(ctx)
	if eng == nil || in == nil {
		out.Latency = time.Since(started)
		return normalizeSemanticRouteOutcome(out)
	}
	req := engineRequest(in)
	sensitiveRequestFields(&req, in, cfg)
	routeContext(eng, in, &req)
	d := eng.Decide(ctx, req)
	r.noteSensitiveDecision(ctx, in, &d)
	out.recordCaller = recordRoutingDecision(ctx, in, &d, cfg != nil && cfg.StandaloneEnterprise())
	out.Route = &d
	out.Latency = time.Since(started)
	switch d.Outcome {
	case engine.OutcomeDenied:
		out.Result, out.FailureCode, out.Deny = SemanticRouteDenied, d.FailureCode, d.Deny
	case engine.OutcomeApplied:
		b := *d.Backend
		decision := &ModelRouterDecision{
			Provider: b.Provider, Model: b.Model,
			TargetURL: b.BaseURL, TargetURLOverride: true, APIKeyOverride: true,
			Reason: fmt.Sprintf("source=%s rule=%s model=%s", d.Source, boundedRouterLabel(d.RuleID, 64), b.Alias),
		}
		decision.APIKey = r.backendKey(cfg, b)
		return mergeEngineFacts(outcomeFromDecision(in, decision, out.Latency), &d, out.recordCaller)
	default:
		out.FailureCode = d.FailureCode
	}
	return normalizeSemanticRouteOutcome(out)
}

func mergeEngineFacts(o SemanticRouteOutcome, d *engine.Decision, recordCaller string) SemanticRouteOutcome {
	o.Route, o.recordCaller = d, recordCaller
	return o
}

// engineRequest turns the proxy input into the engine request. The
// classifier text is the newest user turn the user typed (never tool
// output, system reminders or agent-injected text), bounded. With
// routing.context on, routeContext replaces it from the same extractor.
func engineRequest(in *ModelRouterInput) engine.Request {
	req := engine.Request{
		APIFamily: in.APIFamily, Connector: in.Connector, Listener: in.Listener, Severity: in.Severity,
		RequestedModel: strings.TrimSpace(in.RequestModel), RequestedProvider: in.RequestedProvider,
		CredentialClass: in.CredentialClass, HasTools: len(in.Tools) > 0, HasImages: in.HasImages,
		ConversationID: in.ConversationID, Profiles: in.Profiles, Caller: in.Caller, ToolTurn: in.ToolTurn,
	}
	if req.APIFamily == "" {
		req.APIFamily = config.RoutingAPIChat
	}
	if req.RequestedModel == "" {
		req.RequestedModel = strings.TrimSpace(in.Model)
	}
	if req.Listener == "" {
		req.Listener = engine.ListenerGuardrail
	}
	text := ""
	if in.Text != "" {
		text = routerUserText(in.Text)
	}
	size := len(in.Text)
	for _, m := range in.Messages {
		size += len(m.Content)
		if !req.HasImages && bytes.Contains(m.RawContent, []byte("image")) {
			req.HasImages = true
		}
	}
	// About four bytes per token: more than 100k estimated input tokens.
	req.LongContext = size > 400_000
	if n := len(in.Messages); n > 0 {
		req.ToolTurn = in.ToolTurn || in.Messages[n-1].Role == "tool"
		if in.Text == "" {
			for i := n - 1; i >= 0 && text == ""; i-- {
				if in.Messages[i].Role == "user" {
					text = routerMessageText(&in.Messages[i])
				}
			}
		}
	}
	req.Text = truncateUTF8(text, engine.ClassifierTextLimit)
	return req
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

var (
	_ ModelRouter         = (*engineRouter)(nil)
	_ detailedModelRouter = (*engineRouter)(nil)
)

// routerActivity is implemented by routers whose activity depends on the
// request generation (engineRouter); any other non-nil router is active.
type routerActivity interface {
	RouterActive(ctx context.Context) bool
}

// routerGate is implemented by routers with an admin gate (engineRouter).
type routerGate interface {
	Gate(ctx context.Context, o SemanticRouteOutcome, target engine.GateTarget) *engine.DenyReason
}

// routeGate checks one forwarded exit (DESIGN 15.1, S11 Gate): the routed
// backend or the original request.
func (p *GuardrailProxy) routeGate(ctx context.Context, o SemanticRouteOutcome, target engine.GateTarget) *engine.DenyReason {
	if g, ok := p.modelRouter.(routerGate); ok {
		return g.Gate(ctx, o, target)
	}
	return nil
}

// applyRouteGate runs the admin gate on the exit the outcome forwards to
// (the routed backend, else the original request) and turns a refusal into
// a denied outcome.
func (p *GuardrailProxy) applyRouteGate(ctx context.Context, o *SemanticRouteOutcome, provider, model string) {
	if o == nil || o.Result == SemanticRouteDenied {
		return
	}
	target := engine.GateTarget{Provider: provider, Model: model}
	if o.Result == SemanticRouteApplied && o.Route != nil && o.Route.Backend != nil {
		b := o.Route.Backend
		target = engine.GateTarget{Alias: b.Alias, Provider: b.Provider, Model: b.Model}
	}
	if deny := p.routeGate(ctx, *o, target); deny != nil {
		o.Result, o.Deny, o.Decision = SemanticRouteDenied, deny, nil
		o.FailureCode = SemanticRouteFailureFiltered
		amendRoutingDecision(ctx, *o)
	}
}

// sensitiveFloorOf is the sensitive source of a request the router cannot
// re-route (its floor, or an earlier sensitive turn of the conversation):
// it would go to its own (cloud) model unchecked. "" when routing or
// routing.sensitive is off, or the request is not sensitive.
func (r *engineRouter) sensitiveFloorOf(ctx context.Context, req engine.Request) string {
	if r == nil {
		return ""
	}
	eng, _ := r.engineFor(ctx)
	return eng.SensitiveFloor(req)
}

// recordRouteDeny writes the audit row of a routing refusal.
func (p *GuardrailProxy) recordRouteDeny(ctx context.Context, path string, d *engine.DenyReason) {
	if p == nil {
		return
	}
	auditRouteDeny(ctx, p.logger, path, d)
}

// auditRouteDeny writes the audit row of a routing refusal: a managed
// admin rule (action routing.admin_denied, target routing.admin) or a
// sensitive request no local model could serve (routing.sensitive_refused,
// target routing.sensitive). Code and path only, no text. These are routing
// decisions, not guardrail verdicts: their own actions keep them out of the
// guardrail block counts (inspect-request-block, which they shared before,
// GAP-1126). The request is refused either way.
func auditRouteDeny(ctx context.Context, logger *audit.Logger, path string, d *engine.DenyReason) {
	if logger == nil {
		return
	}
	code, target, action := "routing_admin_denied", "routing.admin", audit.ActionRoutingAdminDenied
	if d != nil && d.Code != "" {
		code = d.Code
	}
	if code == engine.DenyCodeSensitiveLocal {
		target, action = "routing.sensitive", audit.ActionRoutingSensitiveRefused
	}
	_ = logger.LogActionCtx(ctx, string(action), target, "routing refused the model request: "+boundedRouterLabel(code, 96)+" path="+boundedRouterLabel(path, 128))
}

// routerActive reports whether this request is routed at all.
func (p *GuardrailProxy) routerActive(ctx context.Context) bool {
	if p == nil || p.modelRouter == nil {
		return false
	}
	if a, ok := p.modelRouter.(routerActivity); ok {
		return a.RouterActive(ctx)
	}
	return true
}

// routeCallerFromContext builds the routing caller from the identity the
// authentication paths attached. Headers never contribute.
func routeCallerFromContext(ctx context.Context) (engine.Caller, []string) {
	var caller engine.Caller
	if s, ok := verifiedSubjectFromContext(ctx); ok {
		caller = engine.Caller{Verified: true, Key: s.UserID, Source: s.Source}
		if key, ok := substrateActorPersonKey(ctx); ok {
			// An actor's calls are charged to its person across issuers
			// and actors, never to the bare OIDC subject.
			caller.Key = key
		}
		caller.Matches = routingCallerMatcher(ctx)
		// Name the fact an unconfirmed selector waits on (directory,
		// groups) in identity_unconfirmed:<fact>, not the bare identity
		// (rel-1-0-10:GAP-1155).
		facts := profileSubjectFromVerified(s, identityLookupBlocking.Load())
		caller.LookupFailed, caller.GroupsUnknown = facts.LookupFailed, facts.GroupsUnknown
	}
	// An actor call names its actor whether or not a person owns it: an
	// attributed actor is still an actor call (enforced, actor budgets).
	caller.Actor = substrateRouteActor(ctx)
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || !caller.Verified {
		return caller, nil
	}
	d := resolved.decision
	if d.Refused != "" {
		caller.LookupFailed = true
		return caller, nil
	}
	if len(d.Candidates) > 0 {
		return caller, append([]string(nil), d.Candidates...)
	}
	if d.Name != "" {
		return caller, []string{d.Name}
	}
	return caller, nil
}
