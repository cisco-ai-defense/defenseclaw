// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ownRoutingSummary is the routing member of the own-status answer
// (rel-1-0-10 GAP-0574): whether model routing is on, which connectors are
// route-only, and the caller budget nearest its limit. It is the caller own
// view only, built from the routing API rules: with
// routing.admin.visibility.users_see none a standard account gets the
// organization-wide facts (on or off, the routed connectors) and no budget.
// nil when there is no configuration.
func ownRoutingSummary(cfg *config.Config, key string, now time.Time) map[string]any {
	if cfg == nil {
		return nil
	}
	summary := map[string]any{"enabled": cfg.Routing.Enabled}
	if len(cfg.Routing.RouteOnly.Connectors) > 0 {
		summary["route_only"] = append([]string(nil), cfg.Routing.RouteOnly.Connectors...)
	}
	if cfg.Routing.Admin != nil && cfg.Routing.Admin.Visibility.EffectiveUsersSee() == config.RoutingUsersSeeNone {
		return summary
	}
	var nearest *routingBudgetView
	for _, view := range routingBudgetViews(cfg, key, false, now) {
		view := view
		if view.PercentUsed == nil {
			continue
		}
		if nearest == nil || *view.PercentUsed > *nearest.PercentUsed {
			nearest = &view
		}
	}
	if nearest != nil {
		budget := map[string]any{
			"id": nearest.ID, "period": nearest.Period, "limit_usd": nearest.LimitUSD,
			"percent_used": *nearest.PercentUsed, "on_exceed": nearest.OnExceed, "exceeded": nearest.Exceeded,
		}
		if nearest.ResetsAt != "" {
			budget["resets_at"] = nearest.ResetsAt
		}
		summary["budget"] = budget
	}
	return summary
}
