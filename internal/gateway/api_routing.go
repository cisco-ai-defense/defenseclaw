// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
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
}

// routingBudgetViews lists the budgets the caller may see with their spend:
// an administrator sees every budget (a * budget as the sum over its
// subjects); a user sees * user budgets for themselves and, for a pooled
// budget, only the percent used. Named user and group budgets are not shown
// to a user (their selectors are the administrator's policy).
func routingBudgetViews(cfg *config.Config, key string, admin bool, now time.Time) []routingBudgetView {
	if cfg == nil || cfg.Routing.Admin == nil {
		return nil
	}
	ledger := routingAdminRuntime.Ledger()
	var views []routingBudgetView
	for _, b := range cfg.Routing.Admin.Budgets {
		view := routingBudgetView{ID: b.ID, Scope: b.Scope, Period: b.Period, LimitUSD: b.LimitUSD, OnExceed: b.OnExceed,
			ResetsAt: routingadmin.NextReset(b.Period, now).Format(time.RFC3339)}
		if ledger != nil {
			view.Seed = ledger.SeedState([]string{b.ID})
		}
		var spend float64
		var known bool
		switch {
		case admin:
			view.Subject = b.Subject
			spend, known = ledger.SpendPrefix(b.Scope+":"+b.ID+":", b.Period, now)
		case b.Scope == config.RoutingBudgetScopeUser && b.Subject == config.RoutingBudgetSubjectAll && key != "":
			spend, known = ledger.Spend("user:"+b.ID+":*:"+key, b.Period, now)
		default:
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
	body := map[string]any{
		"enabled": cfg != nil && cfg.Routing.Enabled,
		"admin":   admin,
		"budgets": routingBudgetViews(cfg, key, admin, time.Now()),
		"recent":  routingAdminRuntime.Decisions().Recent(key, admin, recent),
	}
	if admin && cfg != nil && cfg.Routing.Admin != nil {
		body["rules"] = cfg.Routing.Admin.Rules
		body["allowed_aliases"] = cfg.Routing.Admin.AllowedAliases
	}
	writeRoutingJSON(w, http.StatusOK, body)
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
	writeRoutingJSON(w, http.StatusOK, map[string]any{"budgets": routingBudgetViews(cfg, key, admin, time.Now())})
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
		"filtered_by": d.FilteredBy, "rule_ids": d.RuleIDs, "outcome": d.Outcome, "source": d.Source,
		"warnings": d.Warnings, "failure": d.FailureCode, "simulated": simulated,
	}
	if d.Backend != nil {
		body["selected_alias"], body["selected_model"] = d.Backend.Alias, d.Backend.Model
	}
	if d.Deny != nil {
		body["deny"] = map[string]string{"code": d.Deny.Code, "message": d.Deny.Message}
	}
	writeRoutingJSON(w, http.StatusOK, body)
}
