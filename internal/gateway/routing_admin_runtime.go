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
	if s, ok := verifiedSubjectFromContext(ctx); ok {
		routingNoteFleetUser(s)
	}
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
// agent call's computed cost to the runtime, this device's spend file
// (data_dir/routing/routing_budgets.db) keeps spend across restarts, and the
// opt-in fleet budget store is installed from routing.admin.budget_store.
// The first sync runs before the first request (2 s bound), so budgets are
// loaded when routing starts. Nothing runs while no budget is configured.
func (s *Sidecar) startRoutingAdmin(ctx context.Context) {
	if s == nil {
		return
	}
	s.modelUsage().engine.SetSpendSink(routingAdminRuntime)
	cfg := s.currentConfig()
	if cfg == nil || cfg.DataDir == "" {
		return
	}
	s.applyRoutingAdmin(cfg)
	routingAdminRuntime.SetCounters(ctx, routingadmin.NewLocalCounter(cfg.DataDir), routingAdminFleet.counter(), 0)
	if routingAdminRuntime.For(cfg) != nil {
		first, cancel := context.WithTimeout(ctx, 2*time.Second)
		routingAdminRuntime.SyncOnce(first)
		cancel()
	}
}

// stopRoutingAdmin stores this process's spend once more after the usage
// engine drained (calls that ended during shutdown are counted).
func (s *Sidecar) stopRoutingAdmin() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	routingAdminRuntime.Flush(ctx)
}

// applyRoutingAdmin applies a validated config (start and every reload):
// whether agent call costs feed the budgets, and the fleet budget store.
func (s *Sidecar) applyRoutingAdmin(cfg *config.Config) {
	if cfg == nil {
		return
	}
	routingAdminRuntime.SetFeed(cfg.BudgetFeedReady())
	routingAdminFleet.apply(cfg)
	routingAdminRuntime.SetFleet(routingAdminFleet.counter(), routingAdminFleet.mapper(), routingAdminFleet.hasher())
}

// routingAdminIdentitySelectors lists the groups routing.admin rules and
// group budgets name, and whether any rule or named budget selects by group
// or user (the identity facts then need a blocking lookup).
func routingAdminIdentitySelectors(cfg *config.Config) ([]string, bool) {
	if cfg == nil || cfg.Routing.Admin == nil {
		return nil, false
	}
	var groups []string
	selects := false
	for _, r := range cfg.Routing.Admin.Rules {
		groups = append(groups, r.Match.Groups...)
		selects = selects || len(r.Match.Groups) > 0 || len(r.Match.Users) > 0
	}
	for _, b := range cfg.Routing.Admin.Budgets {
		switch {
		case b.Scope == config.RoutingBudgetScopeGroup:
			groups, selects = append(groups, b.Subject), true
		case b.Scope == config.RoutingBudgetScopeUser && b.Subject != config.RoutingBudgetSubjectAll:
			selects = true
		}
	}
	return groups, selects
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
// request the router does not route (count_tokens, an API family it does not
// rewrite, a signed Bedrock body): the request goes to its own model, which a
// managed allow list or budget downgrade may refuse, and its cost is charged
// to the budgets. Only the admin evaluator runs (no classifier, no alias
// eligibility): category rules apply to routed calls only. Nothing runs
// unless routing is on and routing.admin has rules or budgets.
func (p *GuardrailProxy) gateUnrouted(r *http.Request, in passthroughRouteInput) SemanticRouteOutcome {
	if p == nil {
		return SemanticRouteOutcome{}
	}
	ctx := r.Context()
	router, ok := p.modelRouter.(*engineRouter)
	if !ok || !p.routerActive(ctx) {
		return SemanticRouteOutcome{}
	}
	eng, cfg := router.engineFor(ctx)
	admin := router.adminFor(cfg)
	if eng == nil || cfg == nil || admin == nil {
		return SemanticRouteOutcome{}
	}
	model := passthroughModel(r.URL.Path, in.Model)
	caller, profiles := routeCallerFromContext(ctx)
	req := engineRequest(&ModelRouterInput{
		Model: model, RequestModel: model, APIFamily: in.APIFamily, Connector: p.connectorName(),
		Listener: engine.ListenerGuardrail, Severity: in.Severity, RequestedProvider: in.Provider,
		Caller: caller, Profiles: profiles,
	})
	verdict := admin.Evaluate(ctx, engine.Policy{}, req, "", false)
	d := engine.Decision{Outcome: engine.OutcomeFallback, Warnings: verdict.Warnings, RuleIDs: verdict.RuleIDs, ChargeKeys: verdict.ChargeKeys}
	o := SemanticRouteOutcome{Result: SemanticRouteFallback, Route: &d}
	managed := cfg.StandaloneEnterprise()
	if verdict.Deny != nil && managed {
		d.Outcome, d.Deny = engine.OutcomeDenied, verdict.Deny
		o.Result, o.Deny = SemanticRouteDenied, verdict.Deny
		return o
	}
	if deny := admin.Gate(verdict, engine.GateTarget{Provider: in.Provider, Model: model}, managed); deny != nil {
		d.Outcome, d.Deny = engine.OutcomeDenied, deny
		o.Result, o.Deny = SemanticRouteDenied, deny
	}
	return o
}

// passthroughModel is the model of a passthrough request: the body's, or the
// one in the path for Bedrock (/model/<id>/...) and Gemini (/models/<id>:verb).
func passthroughModel(path, body string) string {
	if strings.Contains(path, "/model/") {
		return bedrockModelFromPath(path)
	}
	if i := strings.Index(path, "/models/"); i >= 0 {
		rest := path[i+len("/models/"):]
		if j := strings.IndexAny(rest, ":/"); j >= 0 {
			rest = rest[:j]
		}
		if rest != "" {
			return rest
		}
	}
	return body
}
