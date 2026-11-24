// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// Routing API (defenseclaw routing status | budgets | explain | test).
// Users see only their own decisions and budgets; administrators see all.
// On an OSS per-user gateway the caller is its owner and administrator.
const (
	routingTestBodyMax   = 16 << 10
	routingTestPromptMax = 8 << 10
	routingRecentMax     = 50
)

// routingAPIPrefix is the path prefix of the routing API (also reachable on
// the managed hook socket for any kernel-verified account).
const routingAPIPrefix = "/api/v1/routing/"

func (a *APIServer) registerRoutingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/routing/effective", a.handleRoutingEffective)
	mux.HandleFunc("/api/v1/routing/budgets", a.handleRoutingBudgets)
	mux.HandleFunc("/api/v1/routing/explain/", a.handleRoutingExplain)
	mux.HandleFunc("/api/v1/routing/test", a.handleRoutingTest)
}

// routingAPICaller returns the caller key and whether the caller is an
// administrator. ok is false for a caller who may read nothing (a managed
// device's TCP API without the administrator token).
func (a *APIServer) routingAPICaller(r *http.Request, cfg *config.Config) (key string, admin, ok bool) {
	if sid, viaPipe := routingPipeCallerFromContext(r.Context()); viaPipe {
		// The Windows own-status pipe: the account its client token names,
		// never an administrator, whatever the configuration says.
		if cfg != nil && cfg.Routing.Admin != nil && cfg.Routing.Admin.Visibility.EffectiveUsersSee() == config.RoutingUsersSeeNone {
			return "", false, false
		}
		return sid, false, true
	}
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return routingadmin.OwnerKey, true, true
	}
	admin = a.healthAdministratorCaller(r, cfg)
	if peer, viaHookSocket := managedHookPeerFromContext(r.Context()); viaHookSocket {
		key = strconv.Itoa(peer.UID)
	}
	if !admin && cfg.Routing.Admin != nil && cfg.Routing.Admin.Visibility.EffectiveUsersSee() == config.RoutingUsersSeeNone {
		// routing.admin.visibility.users_see none: only administrators read.
		return "", false, false
	}
	return key, admin, admin || key != ""
}

func writeRoutingJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func routingAPIError(w http.ResponseWriter, status int, message string) {
	writeRoutingJSON(w, status, map[string]string{"error": message})
}

// routingBudgetView is one budget as the caller may see it.
type routingBudgetView struct {
	ID          string   `json:"id"`
	Scope       string   `json:"scope"`
	Subject     string   `json:"subject,omitempty"`
	Period      string   `json:"period"`
	LimitUSD    float64  `json:"limit_usd"`
	OnExceed    string   `json:"on_exceed"`
	SpentUSD    *float64 `json:"spent_usd,omitempty"`
	PercentUsed *float64 `json:"percent_used,omitempty"`
	Exceeded    bool     `json:"exceeded"`
	ResetsAt    string   `json:"resets_at"`
	Seed        string   `json:"seed,omitempty"`
	// RetiredKeys is, for an administrator, how many evicted keys of an
	// actor or batch budget wait to be stored and how many the bound
	// dropped (GAP-0848): doctor warns at half the bound.
	RetiredKeys *routingRetiredKeys `json:"retired_keys,omitempty"`
}

// routingRetiredKeys is the retired-key state of one launcher-keyed budget
// on this process (Ledger.RetiredKeys), with its bound.
type routingRetiredKeys struct {
	Waiting int `json:"waiting"`
	Dropped int `json:"dropped"`
	Cap     int `json:"cap"`
	// Replica names the gateway process these counts are of (the host
	// name: the pod in a cluster). They are per process by nature; doctor
	// says "this replica" (GAP-0894).
	Replica string `json:"replica,omitempty"`
}

// routingReplicaName is this gateway's host name (the pod name in a
// cluster), read once.
var routingReplicaName = sync.OnceValue(func() string {
	name, _ := os.Hostname()
	return name
})

// routingBudgetViews lists the budgets the caller may see with their spend:
// an administrator sees every budget (a * budget as the sum over its
// subjects); a user sees the budgets that apply to them: * user budgets and
// a user budget that names them, with their own spend, and the budget of a
// group they are proved a member of (own, the routingOwnCaller facts) with
// only whether it is used up, since its spend is the group pool. A user never
// sees a subject, nor a budget of another user or group (their selectors
// are the administrator's policy). Before, a user saw only * budgets, so
// routing budgets list was empty for a user a named budget applies to
// (rel-1-0-10:GAP-1129).
func routingBudgetViews(cfg *config.Config, key string, admin bool, own routingadmin.Caller, now time.Time) []routingBudgetView {
	// Always a non-nil slice: JSON null would reach the CLI as a missing list
	// (GAP-0561).
	views := []routingBudgetView{}
	if cfg == nil || cfg.Routing.Admin == nil {
		return views
	}
	ledger := routingAdminRuntime.Ledger()
	for _, b := range cfg.Routing.Admin.Budgets {
		view := routingBudgetView{ID: b.ID, Scope: b.Scope, Period: b.Period, LimitUSD: b.LimitUSD, OnExceed: b.OnExceed,
			ResetsAt: routingadmin.NextReset(b.Period, now).Format(time.RFC3339)}
		if ledger != nil {
			view.Seed = ledger.SeedState([]string{b.ID})
		}
		var spend float64
		var known, pooled bool
		var ownKey string
		switch {
		case admin:
			view.Subject = b.Subject
			if b.Scope == config.RoutingBudgetScopeActor || b.Scope == config.RoutingBudgetScopeBatch {
				if waiting, dropped := ledger.RetiredKeys(b.ID); waiting > 0 || dropped > 0 {
					view.RetiredKeys = &routingRetiredKeys{Waiting: waiting, Dropped: dropped, Cap: ledger.KeyCap(), Replica: routingReplicaName()}
				}
			}
			spend, known = ledger.SpendPrefix(b.Scope+":"+b.ID+":", b.Period, now)
		case b.Scope == config.RoutingBudgetScopeUser && b.Subject == config.RoutingBudgetSubjectAll:
			if key == "" {
				continue
			}
			spend, known = ledger.Spend("user:"+b.ID+":*:"+key, b.Period, now)
		case b.Scope == config.RoutingBudgetScopeUser && routingadmin.NamesCaller(own, config.ProfileMatch{Users: []string{b.Subject}}):
			ownKey = routingadmin.BudgetChargeKey(b)
			spend, known = ledger.Spend(ownKey, b.Period, now)
		case b.Scope == config.RoutingBudgetScopeGroup && routingadmin.NamesCaller(own, config.ProfileMatch{Groups: []string{b.Subject}}):
			ownKey = routingadmin.BudgetChargeKey(b)
			spend, known = ledger.Spend(ownKey, b.Period, now)
			pooled = true
		default:
			continue
		}
		if pooled {
			// A group pool shows only whether it is used up: its spend or
			// percent (with the limit) is the other members' spend too.
			view.Exceeded = known && spend >= b.LimitUSD
			views = append(views, view)
			continue
		}
		if known && spend >= budgetstore.ExceededUSD/2 {
			// The fleet store answers a pooled budget with over the limit
			// only, never its total.
			view.Exceeded = true
			views = append(views, view)
			continue
		}
		if known {
			s := spend
			view.SpentUSD = &s
			if b.LimitUSD > 0 {
				p := 100 * spend / b.LimitUSD
				view.PercentUsed = &p
			}
			view.Exceeded = spend >= b.LimitUSD
		}
		views = append(views, view)
	}
	return views
}

func (a *APIServer) handleRoutingEffective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		routingAPIError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	cfg := a.liveConfig()
	key, admin, ok := a.routingAPICaller(r, cfg)
	if !ok {
		routingAPIError(w, http.StatusForbidden, "")
		return
	}
	recent, _ := strconv.Atoi(r.URL.Query().Get("recent"))
	if recent <= 0 || recent > routingRecentMax {
		recent = 5
	}
	var own routingadmin.Caller
	if !admin {
		own = routingOwnCaller(r.Context(), cfg, key)
	}
	body := map[string]any{
		"enabled": cfg != nil && cfg.Routing.Enabled,
		"admin":   admin,
		"budgets": routingBudgetViews(cfg, key, admin, own, time.Now()),
		"recent":  nonNilSlice(routingAdminRuntime.Decisions().Recent(key, admin, recent)),
		// Aliases whose calls the original model served instead, so a dead
		// endpoint is not only a "fallback" row in the recent decisions.
		"alias_failures": routingAliasFailures(routingAdminRuntime.Decisions().Recent(key, admin, routingadmin.DecisionsSize), time.Now()),
	}
	switch {
	case admin && cfg != nil && cfg.Routing.Admin != nil:
		body["rules"] = nonNilSlice(cfg.Routing.Admin.Rules)
		body["allowed_aliases"] = nonNilSlice(cfg.Routing.Admin.AllowedAliases)
	case !admin:
		body["rules"] = routingOwnRules(cfg, own)
	}
	writeRoutingJSON(w, http.StatusOK, body)
}

// routingAliasFailure is one routed alias whose calls failed before their
// first byte and were served by the original model.
type routingAliasFailure struct {
	Alias string `json:"alias"`
	// Count is the failures since the alias last served a call.
	Count int `json:"count"`
	// Cause is the latest one: unreachable, http_<status>, or a route-only
	// preparation code (signing, credential, ...).
	Cause string `json:"cause"`
	// Connector and LastAt describe the latest failure.
	Connector string `json:"connector,omitempty"`
	LastAt    string `json:"last_at"`
}

// routingAliasFailureWindow bounds how old a failure may be and still be
// reported: an alias that failed days ago and has not been used since is not
// "failing" now.
const routingAliasFailureWindow = 24 * time.Hour

// routingAliasFailures lists the aliases whose newest recorded event is a
// failure that the original model served (the warning amendRoutedCallFailed
// and the route-only fallback add), newest decision first as Recent returns
// them. A later call that the alias served ends its failure.
func routingAliasFailures(entries []routingadmin.DecisionEntry, now time.Time) []routingAliasFailure {
	out := []routingAliasFailure{}
	index := map[string]int{}
	served := map[string]bool{}
	for _, e := range entries {
		if now.Sub(e.Time) > routingAliasFailureWindow {
			continue
		}
		if e.Outcome == engine.OutcomeApplied && e.SelectedAlias != "" {
			// Older failures of this alias are over; newer ones were counted.
			served[e.SelectedAlias] = true
			continue
		}
		for _, w := range e.Warnings {
			rest, ok := strings.CutPrefix(w, routedAliasFailedPrefix)
			if !ok {
				continue
			}
			alias, cause, _ := strings.Cut(rest, ":")
			if alias == "" || served[alias] {
				continue
			}
			if i, seen := index[alias]; seen {
				out[i].Count++
				continue
			}
			index[alias] = len(out)
			out = append(out, routingAliasFailure{Alias: alias, Count: 1, Cause: cause, Connector: e.Connector, LastAt: e.Time.UTC().Format(time.RFC3339)})
		}
	}
	return out
}

func (a *APIServer) handleRoutingBudgets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		routingAPIError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	cfg := a.liveConfig()
	key, admin, ok := a.routingAPICaller(r, cfg)
	if !ok {
		routingAPIError(w, http.StatusForbidden, "")
		return
	}
	var own routingadmin.Caller
	if !admin {
		own = routingOwnCaller(r.Context(), cfg, key)
	}
	writeRoutingJSON(w, http.StatusOK, map[string]any{"budgets": routingBudgetViews(cfg, key, admin, own, time.Now())})
}

// routingOwnCaller is the routing.admin caller of a managed own read (key
// from routingAPICaller: the hook socket kernel peer uid, or the Windows
// own-status pipe SID), with the directory matcher the route-only and proxy
// paths give routing.admin (routeCallerFromContext), so a list names the
// rules and budgets the evaluator applies to that account. Zero (no rule
// or budget proved) off a managed host, for an empty key, and when the
// account cannot be verified.
func routingOwnCaller(ctx context.Context, cfg *config.Config, key string) routingadmin.Caller {
	if cfg == nil || !cfg.StandaloneEnterprise() || key == "" {
		return routingadmin.Caller{}
	}
	if s, ok := verifiedSubjectFromContext(ctx); !ok || s.UserID != key {
		source := subjectSourcePeerCredentials
		if _, viaPipe := routingPipeCallerFromContext(ctx); viaPipe {
			source = unenrolledRefusalSubject
		}
		ctx = attachVerifiedSubject(ctx, nil, key, sanitizeLLMEventUser(userScopedIdentityName(key)), source)
	}
	caller, _ := routeCallerFromContext(ctx)
	if !caller.Verified || caller.Key != key {
		return routingadmin.Caller{}
	}
	return routingadmin.CallerFromEngine(caller, true)
}

// routingOwnRuleView is a routing.admin rule as the account it applies to
// reads it (the routing rules list shape): no users, groups or agents
// selector.
type routingOwnRuleView struct {
	ID      string               `json:"id"`
	Match   *routingOwnRuleMatch `json:"match,omitempty"`
	Action  string               `json:"action,omitempty"`
	Allow   []string             `json:"allow,omitempty"`
	Default string               `json:"default,omitempty"`
	Message string               `json:"message,omitempty"`
}

// routingOwnRuleMatch is the part of a rule match that names no account.
type routingOwnRuleMatch struct {
	Connectors      []string `json:"connectors,omitempty"`
	Categories      []string `json:"categories,omitempty"`
	SeverityAtLeast string   `json:"severity_at_least,omitempty"`
}

// routingOwnRules are the routing.admin rules that apply to the caller of a
// managed own read: a rule that names no user, group or agent, or one whose
// users and groups selectors the facts prove name the caller (the evaluator
// matcher). A rule that selects by agents only is not listed (an agent id
// can stand for another person's agent), and users, groups and agents are
// never shown: they are the administrator's policy and can name other
// accounts. Before, a user got no rules at all,
// so routing rules list said [] scope own while those rules applied to the
// account (rel-1-0-10:GAP-1129).
func routingOwnRules(cfg *config.Config, own routingadmin.Caller) []routingOwnRuleView {
	rules := []routingOwnRuleView{}
	if cfg == nil || cfg.Routing.Admin == nil || !cfg.StandaloneEnterprise() || !own.Verified {
		return rules
	}
	for _, rule := range cfg.Routing.Admin.Rules {
		m := rule.Match
		person := len(m.Users) > 0 || len(m.Groups) > 0
		if (!person && len(m.Agents) > 0) || (person && !routingadmin.NamesCaller(own, config.ProfileMatch{Users: m.Users, Groups: m.Groups})) {
			continue
		}
		view := routingOwnRuleView{ID: rule.ID, Action: rule.Action, Allow: rule.Allow, Default: rule.Default, Message: rule.Message}
		if len(m.Connectors)+len(m.Categories) > 0 || m.SeverityAtLeast != "" {
			view.Match = &routingOwnRuleMatch{Connectors: m.Connectors, Categories: m.Categories, SeverityAtLeast: m.SeverityAtLeast}
		}
		rules = append(rules, view)
	}
	return rules
}

func (a *APIServer) handleRoutingExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		routingAPIError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	key, admin, ok := a.routingAPICaller(r, a.liveConfig())
	if !ok {
		routingAPIError(w, http.StatusForbidden, "")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/routing/explain/")
	if id == "" || len(id) > 256 || strings.Contains(id, "/") {
		routingAPIError(w, http.StatusBadRequest, "name one request id")
		return
	}
	entry, found := routingAdminRuntime.Decisions().Find(id, key, admin)
	if !found {
		// Another user's decision is reported the same way as an unknown id.
		routingAPIError(w, http.StatusNotFound, "")
		return
	}
	writeRoutingJSON(w, http.StatusOK, entry)
}

// routingTestLimiter allows one dry run per caller every 200 ms for an
// administrator and every 2 s for a user (each runs the classifier).
var routingTestLimiter = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func routingTestAllowed(key string, admin bool, now time.Time) bool {
	gap := 2 * time.Second
	if admin {
		gap = 200 * time.Millisecond
	}
	routingTestLimiter.Lock()
	defer routingTestLimiter.Unlock()
	if t, ok := routingTestLimiter.last[key]; ok && now.Sub(t) < gap {
		return false
	}
	if len(routingTestLimiter.last) > 1024 {
		routingTestLimiter.last = map[string]time.Time{}
	}
	routingTestLimiter.last[key] = now
	return true
}

type routingTestRequest struct {
	Prompt    string `json:"prompt"`
	Connector string `json:"connector"`
	Profile   string `json:"profile"`
	User      string `json:"user"`
}

func (a *APIServer) handleRoutingTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		routingAPIError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	cfg := a.liveConfig()
	key, admin, ok := a.routingAPICaller(r, cfg)
	if !ok {
		routingAPIError(w, http.StatusForbidden, "")
		return
	}
	var req routingTestRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, routingTestBodyMax)).Decode(&req); err != nil {
		routingAPIError(w, http.StatusBadRequest, "send JSON {prompt, connector}")
		return
	}
	if req.Prompt == "" || len(req.Prompt) > routingTestPromptMax {
		routingAPIError(w, http.StatusBadRequest, "the prompt must be 1 byte to 8 KiB")
		return
	}
	if (req.Profile != "" || req.User != "") && !admin {
		routingAPIError(w, http.StatusForbidden, "only an administrator may test as another profile or user")
		return
	}
	if !routingTestAllowed(key, admin, time.Now()) {
		routingAPIError(w, http.StatusTooManyRequests, "one routing test at a time; try again in a moment")
		return
	}
	router := activeEngineRouter.Load()
	if router == nil {
		routingAPIError(w, http.StatusServiceUnavailable, "routing is not running on this gateway (defenseclaw routing enable, then restart the gateway)")
		return
	}
	eng, _ := router.engineFor(r.Context())
	if eng == nil {
		routingAPIError(w, http.StatusServiceUnavailable, "routing is off for the configuration the gateway runs")
		return
	}
	caller, profiles := routeCallerFromContext(r.Context())
	in := &ModelRouterInput{Text: req.Prompt, Connector: config.NormalizeConnectorName(req.Connector),
		Listener: engine.ListenerGuardrail, Caller: caller, Profiles: profiles}
	var simulated []string
	if family, ok := routeOnlyTestFamily(cfg, in.Connector); ok {
		// A route-only connector is decided as its listener decides (its API
		// family and upstream provider), so a model that listener cannot
		// reach is filtered here too (rel-1-0-10:GAP-1167).
		in.Listener, in.APIFamily, in.RequestedProvider = engine.ListenerRouteOnly, family, routeOnlyProvider(family)
		simulated = append(simulated, "route-only "+family+" call (the agent credential is not simulated)")
	}
	if req.Profile != "" {
		in.Profiles, simulated = []string{req.Profile}, append(simulated, "profile "+req.Profile)
	}
	if req.User != "" {
		// The administrator names a user; the directory facts are not
		// looked up, so identity rules see an unconfirmed caller.
		in.Caller = engine.Caller{Verified: true, Key: req.User}
		simulated = append(simulated, "user "+req.User+" (groups not looked up)")
	}
	d := eng.Decide(r.Context(), engineRequest(in))
	body := map[string]any{
		"category": d.Category, "confidence": d.Confidence, "candidate_alias": d.Candidate,
		"filtered_by": d.FilteredBy, "rule_ids": nonNilSlice(d.RuleIDs), "outcome": d.Outcome, "source": d.Source,
		"warnings": nonNilSlice(d.Warnings), "failure": d.FailureCode, "simulated": nonNilSlice(simulated),
	}
	if d.Backend != nil {
		body["selected_alias"], body["selected_model"] = d.Backend.Alias, d.Backend.Model
	}
	if d.Deny != nil {
		body["deny"] = map[string]string{"code": d.Deny.Code, "message": d.Deny.Message}
	}
	writeRoutingJSON(w, http.StatusOK, body)
}

// routeOnlyTestFamily is the API family the route-only listener sees from
// connector: its routing.route_only.upstreams api, else the connector own
// API. ok is false when routing does not send the connector through that
// listener.
func routeOnlyTestFamily(cfg *config.Config, connector string) (string, bool) {
	if !cfg.RouteOnlyRouted(connector) {
		return "", false
	}
	if up, ok := cfg.Routing.RouteOnly.Upstreams[connector]; ok && slices.Contains(config.RoutingAPIs, up.API) {
		return up.API, true
	}
	if connector == "codex" {
		return config.RoutingAPIResponses, true
	}
	return config.RoutingAPIMessages, true
}

// nonNilSlice returns v, or an empty slice for a nil one, so the JSON answer
// holds [] and never null.
func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
