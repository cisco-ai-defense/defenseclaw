// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// routingAdminRuntime holds the process-wide part of routing.admin rules
// and budgets: the spend ledger (only while budgets exist) and the recent
// decisions `routing explain` and `routing status` read. Each config
// generation compiles its own evaluator from it (routingAdminRuntime.For).
var routingAdminRuntime = routingadmin.NewRuntime()

// activeEngineRouter is the sidecar's routing engine, for the dry run of
// POST /api/v1/routing/test (nil until routing starts).
var activeEngineRouter atomic.Pointer[engineRouter]

// recordRoutingDecision keeps one routed call in the recent-decisions ring:
// no prompt text, headers or credentials, and the verified caller key only.
func recordRoutingDecision(ctx context.Context, in *ModelRouterInput, d *engine.Decision, managed bool) {
	if in == nil || d == nil {
		return
	}
	entry := routingadmin.DecisionEntry{
		Time:           time.Now().UTC(),
		RequestID:      RequestIDFromContext(ctx),
		CallerKey:      routingadmin.CallerFromEngine(in.Caller, managed).Key,
		Connector:      in.Connector,
		Listener:       in.Listener,
		APIFamily:      in.APIFamily,
		Category:       d.Category,
		RequestedModel: in.RequestModel,
		Outcome:        d.Outcome,
		Source:         d.Source,
		RuleIDs:        d.RuleIDs,
		Warnings:       d.Warnings,
	}
	if entry.RequestedModel == "" {
		entry.RequestedModel = in.Model
	}
	if d.Backend != nil {
		entry.SelectedAlias, entry.SelectedModel = d.Backend.Alias, d.Backend.Model
	}
	if d.FailureCode != "" && d.FailureCode != engine.FailureNone {
		entry.Reasons = append(entry.Reasons, d.FailureCode)
	}
	if d.FilteredBy != "" {
		entry.Reasons = append(entry.Reasons, "filtered_by:"+d.FilteredBy)
	}
	if d.Deny != nil {
		entry.Reasons = append(entry.Reasons, d.Deny.Code)
	}
	routingAdminRuntime.Decisions().Record(entry)
}

// routingCallerMatcher answers routing.admin identity selectors (groups,
// users, agents) for ctx's verified subject with the proof rules of
// guardrail.profile_assignments (assignmentState): yes, no, or maybe when a
// fact is not proven. nil when the request has no verified subject.
func routingCallerMatcher(ctx context.Context) func(config.ProfileMatch) engine.Tri {
	subject, source := profileRequestSubject(ctx)
	if subject == nil || source == "" {
		return nil
	}
	cfg := routingRequestConfig(ctx)
	set := &guardrailProfileSet{base: cfg, groupSIDs: routingGroupSIDsFor(cfg)}
	res := resolveIdentity(subject, nil)
	connectorName := profileAssignmentConnector(ctx)
	agent := ""
	if id, ok := profileAgentSource(ctx); ok {
		agent = strings.TrimSpace(id)
	}
	return func(m config.ProfileMatch) engine.Tri {
		state, _, _, _ := set.assignmentState(m, subject, res, true, connectorName, agent)
		switch state {
		case matchYes:
			return engine.Yes
		case matchMaybe:
			return engine.Maybe
		default:
			return engine.No
		}
	}
}

// routingRequestConfig is the config of the generation ctx pinned, else the
// current one.
func routingRequestConfig(ctx context.Context) *config.Config {
	if g := pinnedGeneration(ctx); g.published() && g.Config != nil {
		return g.Config
	}
	if g := currentGeneration(); g.published() {
		return g.Config
	}
	return nil
}

// routingGroupSIDs resolves the group names routing.admin rules and budgets
// name, as the profile set does for assignments: on a standalone Windows
// device a group name matches its SID only (GAP-0860). One table per
// config generation.
var routingGroupSIDs struct {
	sync.Mutex
	cfg   *config.Config
	table *profileGroupSIDs
}

func routingGroupSIDsFor(cfg *config.Config) *profileGroupSIDs {
	if cfg == nil || cfg.Routing.Admin == nil || runtime.GOOS != "windows" || !cfg.StandaloneEnterprise() || profileGroupSIDLookup == nil {
		return nil
	}
	routingGroupSIDs.Lock()
	defer routingGroupSIDs.Unlock()
	if routingGroupSIDs.cfg == cfg {
		return routingGroupSIDs.table
	}
	var names []config.ProfileAssignment
	for _, r := range cfg.Routing.Admin.Rules {
		if len(r.Match.Groups) > 0 {
			names = append(names, config.ProfileAssignment{Match: config.ProfileMatch{Groups: r.Match.Groups}})
		}
	}
	for _, b := range cfg.Routing.Admin.Budgets {
		if b.Scope == config.RoutingBudgetScopeGroup {
			names = append(names, config.ProfileAssignment{Match: config.ProfileMatch{Groups: []string{b.Subject}}})
		}
	}
	routingGroupSIDs.cfg = cfg
	routingGroupSIDs.table = nil
	if len(names) > 0 {
		routingGroupSIDs.table = buildProfileGroupSIDs(names, profileGroupSIDLookup, profileGroupLocalSIDLookup, profileGroupSIDWait)
	}
	return routingGroupSIDs.table
}

// adminFor is the evaluator of cfg's generation: one installed with
// SetAdminEvaluator wins (tests), else routing.admin rules and budgets of
// cfg compiled once per generation (nil when there are none).
func (r *engineRouter) adminFor(cfg *config.Config) engine.AdminEvaluator {
	if r.admin != nil {
		return r.admin
	}
	return routingAdminRuntime.For(cfg)
}

// startRoutingAdmin wires budgets for the run: the usage engine charges each
// agent call's computed cost to the runtime, and this device's spend file
// (data_dir/routing/routing_budgets.db) keeps spend across restarts. Nothing
// runs while no budget is configured; the sync loop stops with ctx after a
// last store. A fleet counter plugs in through routingadmin.SpendCounter.
func (s *Sidecar) startRoutingAdmin(ctx context.Context) {
	if s == nil {
		return
	}
	s.modelUsage().engine.SetSpendSink(routingAdminRuntime)
	if s.cfg == nil || s.cfg.DataDir == "" {
		return
	}
	routingAdminRuntime.SetCounters(ctx, routingadmin.NewLocalCounter(s.cfg.DataDir), nil, 0)
}

// gateOriginal re-runs the admin gate when a routed decision ends up sending
// the original request (a stored response id of the original provider, a
// backend with no known origin): on a managed device an allow list or a
// budget downgrade binds that exit too.
func (p *GuardrailProxy) gateOriginal(ctx context.Context, o SemanticRouteOutcome, provider, model string) SemanticRouteOutcome {
	if o.Result == SemanticRouteDenied {
		return o
	}
	o.Result, o.Decision = SemanticRouteFallback, nil
	p.applyRouteGate(ctx, &o, provider, model)
	return o
}

// gateUnrouted applies routing.admin rules and budgets to a passthrough
// request the router does not route (an API family it does not rewrite such
// as count_tokens, a signed Bedrock body): the request still goes to its
// own model, which a managed allow list or downgrade may refuse. Read-only
// GET requests (model lists) are exempt. Nothing runs unless routing is on
// and routing.admin has rules or budgets.
func (p *GuardrailProxy) gateUnrouted(r *http.Request, in passthroughRouteInput) SemanticRouteOutcome {
	if p == nil || r.Method == http.MethodGet {
		return SemanticRouteOutcome{}
	}
	ctx := r.Context()
	router, ok := p.modelRouter.(*engineRouter)
	if !ok || !p.routerActive(ctx) {
		return SemanticRouteOutcome{}
	}
	eng, cfg := router.engineFor(ctx)
	if eng == nil || cfg == nil || router.adminFor(cfg) == nil {
		return SemanticRouteOutcome{}
	}
	model := in.Model
	if strings.Contains(r.URL.Path, "/model/") {
		model = bedrockModelFromPath(r.URL.Path)
	}
	caller, profiles := routeCallerFromContext(ctx)
	d := eng.Decide(ctx, engineRequest(&ModelRouterInput{
		Model: model, RequestModel: model, APIFamily: in.APIFamily, Connector: p.connectorName(),
		Listener: engine.ListenerGuardrail, Severity: in.Severity, RequestedProvider: in.Provider,
		Text: in.Text, Caller: caller, Profiles: profiles,
	}))
	o := SemanticRouteOutcome{Result: SemanticRouteFallback, Route: &d}
	if d.Deny != nil {
		o.Result, o.Deny = SemanticRouteDenied, d.Deny
		return o
	}
	p.applyRouteGate(ctx, &o, in.Provider, model)
	return o
}
