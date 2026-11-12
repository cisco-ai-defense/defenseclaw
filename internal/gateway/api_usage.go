// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// SetModelUsage binds the local usage store the /usage endpoint reads.
func (a *APIServer) SetModelUsage(store *modelusage.Store) {
	if a != nil {
		a.modelUsage.Store(store)
	}
}

// usageScope decides whose rows a caller may read. On a per-user gateway
// every caller is the account that owns it. On a managed gateway an
// administrator (root hook-socket peer or the gateway token holder) reads
// all rows; any other caller reads only the rows of the identity the gateway
// verified for the request, and nothing when it verified none. The filter is
// applied in the SQL WHERE clause by the store.
func (a *APIServer) usageScope(r *http.Request) (owner string, admin bool) {
	cfg := a.runtimeConfigSnapshot()
	if a.healthAdministratorCaller(r, cfg) {
		return "", true
	}
	caller, ok := verifiedAuditCaller(r.Context())
	if !ok {
		return "", false
	}
	return modelusage.OwnerID(modelusage.CallFacts{Subject: caller.ID, SubjectKind: caller.IDKind, IdentityVerified: true}), false
}

func parseUsageWindow(since string, now time.Time) (time.Time, error) {
	since = strings.TrimSpace(since)
	if since == "" {
		return now.Add(-24 * time.Hour), nil
	}
	if strings.HasSuffix(since, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(since, "d"))
		if err != nil || n < 1 || n > 3650 {
			return time.Time{}, errors.New("since: use a number of days from 1 to 3650, for example 7d")
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(since)
	if err != nil || d <= 0 || d > 3650*24*time.Hour {
		return time.Time{}, errors.New("since: use a duration such as 24h or a number of days such as 7d")
	}
	return now.Add(-d), nil
}

// handleUsage serves GET /usage?by=model|connector|route|profile|role|provider|user|group|hour&since=24h|7d&limit=N.
func (a *APIServer) handleUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	store := a.modelUsage.Load()
	if store == nil || !store.Enabled() {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"hint":    "set observability.tokenomics.enabled and observability.tokenomics.local_store.enabled to true in config.yaml",
			"rows":    []modelusage.Row{},
		})
		return
	}
	now := time.Now()
	from, err := parseUsageWindow(r.URL.Query().Get("since"), now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	by := strings.TrimSpace(r.URL.Query().Get("by"))
	if by == "" {
		by = "model"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	owner, admin := a.usageScope(r)
	rows, err := store.Run(r.Context(), modelusage.Query{By: by, From: from, To: now, Owner: owner, AllOwners: admin, Limit: limit})
	switch {
	case errors.Is(err, modelusage.ErrAdminOnly):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scope := "own"
	if admin {
		scope = "all"
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "by": by, "scope": scope,
		"from": from.UTC().Format(time.RFC3339), "to": now.UTC().Format(time.RFC3339),
		"rows": rows,
	})
}

// ownUsageSummary is the last 24 hours of the verified caller own usage, for
// the own-status answer. A standard account on a managed Windows host reaches
// the gateway only through the own-status pipe, so this is how it sees what
// it used; Linux and macOS accounts get the same field. nil when the usage
// store is off or the caller has no recorded usage.
func (a *APIServer) ownUsageSummary(ctx context.Context, idKey, self string) map[string]any {
	store := a.modelUsage.Load()
	if store == nil || !store.Enabled() {
		return nil
	}
	kind := useridentity.KindPOSIXUID
	if idKey == "sid" {
		kind = useridentity.KindWindowsSID
	}
	owner := modelusage.OwnerID(modelusage.CallFacts{Subject: self, SubjectKind: kind, IdentityVerified: true})
	now := time.Now()
	rows, err := store.Run(ctx, modelusage.Query{By: "hour", Owner: owner, From: now.Add(-24 * time.Hour), To: now, Limit: 1000})
	if err != nil || len(rows) == 0 {
		return nil
	}
	var calls, in, out, costCalls int64
	var cost float64
	for _, r := range rows {
		calls += r.Calls
		in += r.Input
		out += r.Output
		costCalls += r.CostCalls
		if r.CostUSD != nil {
			cost += *r.CostUSD
		}
	}
	summary := map[string]any{"window": "24h", "calls": calls, "input_tokens": in, "output_tokens": out, "cost_calls": costCalls}
	if costCalls > 0 {
		summary["cost_usd"] = cost
	}
	return summary
}
