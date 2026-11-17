// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"runtime"
	"slices"
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
// It returns the caller key of the entry (amendRoutingDecision amends only
// that caller's).
func recordRoutingDecision(ctx context.Context, in *ModelRouterInput, d *engine.Decision, managed bool) string {
	if in == nil || d == nil {
		return ""
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
	if d.Sensitive.Source != "" || d.Sensitive.CheckFailure != "" {
		entry.Reasons = append(entry.Reasons, "sensitive:"+boundedRouterLabel(d.Sensitive.Source, 32)+":"+boundedRouterLabel(d.Sensitive.Reason, 64))
	}
	routingAdminRuntime.Decisions().Record(entry)
	return entry.CallerKey
}

// amendRoutingDecision rewrites the recorded decision of the request in ctx
// when the exit changed after the engine decided (a gate refusal, a route
// attempt that could not be prepared), so `routing explain` and `routing
// status` show what was done (GAP-0576).
func amendRoutingDecision(ctx context.Context, o SemanticRouteOutcome) {
	outcome := engine.OutcomeFallback
	switch o.Result {
	case SemanticRouteDenied:
		outcome = engine.OutcomeDenied
	case SemanticRouteApplied:
		return
	}
	routingAdminRuntime.Decisions().Amend(RequestIDFromContext(ctx), o.recordCaller, func(e *routingadmin.DecisionEntry) {
		e.Outcome, e.SelectedAlias, e.SelectedModel = outcome, "", ""
		if o.Deny != nil && o.Deny.Code != "" && !slices.Contains(e.Reasons, o.Deny.Code) {
			e.Reasons = append(e.Reasons, o.Deny.Code)
		}
		if o.Route != nil {
			e.Warnings = slices.Clone(o.Route.Warnings)
		}
	})
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
	routingGroupSIDs.cfg = cfg
	routingGroupSIDs.table = nil
	if names := routingAdminGroupNames(cfg); len(names) > 0 {
		assignment := []config.ProfileAssignment{{Match: config.ProfileMatch{Groups: names}}}
		routingGroupSIDs.table = buildProfileGroupSIDs(assignment, profileGroupSIDLookup, profileGroupLocalSIDLookup, profileGroupSIDWait)
	}
	return routingGroupSIDs.table
}

// routingAdminGroupNames lists, once each in config order (the first
// spelling of names that differ only in case, as the matcher folds case),
// the groups that routing.admin rules (match.groups) and group budgets name.
func routingAdminGroupNames(cfg *config.Config) []string {
	if cfg == nil || cfg.Routing.Admin == nil {
		return nil
	}
	var names []string
	add := func(group string) {
		if strings.TrimSpace(group) != "" && !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, group) }) {
			names = append(names, group)
		}
	}
	for _, r := range cfg.Routing.Admin.Rules {
		for _, group := range r.Match.Groups {
			add(group)
		}
	}
	for _, b := range cfg.Routing.Admin.Budgets {
		if b.Scope == config.RoutingBudgetScopeGroup {
			add(b.Subject)
		}
	}
	return names
}

// usageGroupsMax bounds the groups one usage record carries.
const usageGroupsMax = 16

// usageCallerGroups names the routing.admin groups (rules match.groups and
// group budgets, as the administrator wrote them) the verified caller is
// proved a member of, with the matcher routing.admin rules and group budgets
// use, so GET /usage?by=group rolls usage up by the groups routing acts on.
// Before, nothing set the groups of a usage record and by=group was always
// empty (rel-1-0-10:GAP-1154). Managed hosts only (identity selectors do not
// apply on a per-user gateway); nil for an unverified caller and for groups
// the facts cannot prove. Bounded: configured names only, at most
// usageGroupsMax, whatever the account's directory membership.
func usageCallerGroups(cfg *config.Config, caller engine.Caller) []string {
	if cfg == nil || !cfg.StandaloneEnterprise() || !caller.Verified || caller.Matches == nil {
		return nil
	}
	var groups []string
	for _, group := range routingAdminGroupNames(cfg) {
		if caller.Matches(config.ProfileMatch{Groups: []string{group}}) == engine.Yes {
			if groups = append(groups, group); len(groups) == usageGroupsMax {
				break
			}
		}
	}
	return groups
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
	routingAdminRuntime.SetCounters(ctx, routingadmin.NewLocalCounter(cfg.DataDir), routingAdminFleet.counter(), routingAdminSyncInterval(cfg))
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
	routingAdminRuntime.SetInterval(routingAdminSyncInterval(cfg))
	routingAdminRuntime.SetFleet(routingAdminFleet.counter(), routingAdminFleet.mapper())
}

// routingAdminSyncInterval is routing.admin.budget_store.sync_interval (the
// default without a store).
func routingAdminSyncInterval(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.Routing.Admin != nil && cfg.Routing.Admin.BudgetStore != nil {
		return cfg.Routing.Admin.BudgetStore.EffectiveSyncInterval()
	}
	return routingadmin.DefaultSyncInterval
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
// cause says why the routed backend cannot be used: a sensitive decision is
// refused with it (GAP-0576), any other gets a route_fallback warning.
func (p *GuardrailProxy) gateOriginal(ctx context.Context, o SemanticRouteOutcome, provider, model, cause string) SemanticRouteOutcome {
	if o.Result == SemanticRouteDenied {
		return o
	}
	if o.Route != nil && o.Route.SensitiveNarrowed() {
		alias := ""
		if o.Route.Backend != nil {
			alias = o.Route.Backend.Alias
		}
		o.Result, o.Decision, o.FailureCode = SemanticRouteDenied, nil, SemanticRouteFailureFiltered
		o.Deny = engine.SensitiveLocalDeny(o.Route.Sensitive.Source, "DefenseClaw cannot send it to model "+alias+": "+cause)
		amendRoutingDecision(ctx, o)
		return o
	}
	if o.Route != nil {
		o.Route.Warnings = append(o.Route.Warnings, "route_fallback:"+boundedRouterLabel(cause, 96))
	}
	o.Result, o.Decision = SemanticRouteFallback, nil
	p.applyRouteGate(ctx, &o, provider, model)
	amendRoutingDecision(ctx, o)
	return o
}

// gateUnrouted applies routing.admin rules and budgets to a passthrough
// request the router does not route (count_tokens, an API family it does not
// rewrite, a signed Bedrock body): the request goes to its own model, which a
// managed allow list or budget downgrade may refuse, and its cost is charged
// to the budgets. Only the admin evaluator runs (no classifier, no alias
// eligibility): category rules apply to routed calls only. A request
// routing.sensitive marks is refused (it cannot be re-routed, GAP-0576).
// Nothing runs unless routing is on and routing.sensitive or routing.admin
// is set.
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
	if eng == nil || cfg == nil {
		return SemanticRouteOutcome{}
	}
	admin := router.adminFor(cfg)
	if admin == nil && !eng.SensitiveConfigured() {
		return SemanticRouteOutcome{}
	}
	model := passthroughModel(r.URL.Path, in.Model)
	caller, profiles := routeCallerFromContext(ctx)
	routerIn := &ModelRouterInput{
		Model: model, RequestModel: model, APIFamily: in.APIFamily, Connector: p.connectorName(),
		Listener: engine.ListenerGuardrail, Severity: in.Severity, RequestedProvider: in.Provider,
		ConversationID: routeConversationID(r), Text: in.Text, Caller: caller, Profiles: profiles,
	}
	req := engineRequest(routerIn)
	if src := eng.SensitiveFloor(req); src != "" {
		// The router cannot send this request to a local model, and a
		// sensitive request never goes to the cloud (GAP-0576).
		deny := engine.SensitiveLocalDeny(src, "DefenseClaw cannot re-route this request (a signed Bedrock body or an API it does not rewrite)")
		d := engine.Decision{Outcome: engine.OutcomeDenied, Deny: deny, FailureCode: engine.FailureFiltered, Source: engine.SourceSensitive,
			FilteredBy: "sensitive", Sensitive: engine.SensitiveOutcome{Source: src, Reason: "positive"}}
		caller := recordRoutingDecision(ctx, routerIn, &d, cfg.StandaloneEnterprise())
		return SemanticRouteOutcome{Result: SemanticRouteDenied, Deny: deny, Route: &d, recordCaller: caller}
	}
	if admin == nil {
		return SemanticRouteOutcome{}
	}
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
