// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// routerClassifierTextLimit bounds the text a classifier sees.
const routerClassifierTextLimit = 8 * 1024

// engineRouter is the production ModelRouter: the routing engine of the
// config generation a request pinned, built once per generation, so routing
// policy changes apply without a restart (DESIGN 8.2). Only the vLLM
// Semantic Router container (classifier vllm_sr) stays restart-bound; its
// client comes from the sidecar.
type engineRouter struct {
	boot       *config.Config
	classifier engine.Classifier // vllm_sr client, nil unless started
	dotenv     string

	mu    sync.Mutex
	cache *engineCacheEntry
}

type engineCacheEntry struct {
	gen uint64
	cfg *config.Config
	eng *engine.Engine
}

func newEngineRouter(boot *config.Config, classifier engine.Classifier, dotenv string) *engineRouter {
	return &engineRouter{boot: boot, classifier: classifier, dotenv: dotenv}
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
	if c := r.cache; c != nil && c.gen == gen && c.cfg == cfg {
		return c.eng, c.cfg
	}
	eng, err := engine.New(cfg, engine.Options{
		Classifier:   r.classifierFor(cfg),
		Admin:        routingAdminRuntime.For(cfg),
		Managed:      cfg != nil && cfg.StandaloneEnterprise(),
		CredentialOK: func(b engine.Backend, _ engine.Request) bool { return r.backendCredentialOK(cfg, b) },
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[routing] policy build failed, routing off for this generation: %v\n", err)
		eng = nil
	}
	r.cache = &engineCacheEntry{gen: gen, cfg: cfg, eng: eng}
	return eng, cfg
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
		return cfg.RoutingCredential(b.Credential)
	}
	if b.APIKeyEnv == "" {
		return ""
	}
	return ResolveAPIKey(b.APIKeyEnv, r.dotenv)
}

func (r *engineRouter) backendCredentialOK(cfg *config.Config, b engine.Backend) bool {
	needs := b.APIKeyEnv != "" || b.Credential != ""
	if cfg != nil && cfg.StandaloneEnterprise() {
		needs = b.Credential != "" || b.APIKeyEnv != ""
	}
	return !needs || r.backendKey(cfg, b) != ""
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
	d := eng.Decide(ctx, engineRequest(in))
	recordRoutingDecision(ctx, in, &d, cfg != nil && cfg.StandaloneEnterprise())
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
		return mergeEngineFacts(outcomeFromDecision(in, decision, out.Latency), &d)
	default:
		out.FailureCode = d.FailureCode
	}
	return normalizeSemanticRouteOutcome(out)
}

func mergeEngineFacts(o SemanticRouteOutcome, d *engine.Decision) SemanticRouteOutcome {
	o.Route = d
	return o
}

// engineRequest turns the proxy input into the engine request. The
// classifier text is the newest user turn (never tool output), bounded.
func engineRequest(in *ModelRouterInput) engine.Request {
	req := engine.Request{
		APIFamily: in.APIFamily, Connector: in.Connector, Listener: in.Listener, Severity: in.Severity,
		RequestedModel: strings.TrimSpace(in.RequestModel), RequestedProvider: in.RequestedProvider,
		CredentialClass: in.CredentialClass, HasTools: len(in.Tools) > 0, HasImages: in.HasImages,
		ConversationID: in.ConversationID, Profiles: in.Profiles, Caller: in.Caller,
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
	text := in.Text
	if n := len(in.Messages); n > 0 {
		req.ToolTurn = in.Messages[n-1].Role == "tool"
		if text == "" {
			for i := n - 1; i >= 0; i-- {
				if in.Messages[i].Role == "user" {
					text = in.Messages[i].Content
					break
				}
			}
		}
	}
	req.Text = truncateUTF8(text, routerClassifierTextLimit)
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
	}
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
