// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// ownNoHomeReason is what the routing member says when the gateway could not
// resolve a home directory for the caller account, so the route settings a
// route-only connector needs (the agent's own per-user settings file with the
// base URL and route credential) are not known to exist for it. It says "not
// resolved", not "none": a slow or failed directory lookup looks the same.
const ownNoHomeReason = "home directory not resolved"

// ownAccountHomeless reports whether the caller account, as the kernel-proved
// hook socket peer, has no usable home directory: none could be resolved, or
// it is a placeholder an account without a home gets (a directory account
// that sets none has /var/empty on macOS), or a path that does not exist. A
// caller that is not a hook
// socket peer is never homeless here.
func ownAccountHomeless(ctx context.Context) bool {
	peer, ok := managedHookPeerFromContext(ctx)
	if !ok {
		return false
	}
	home := strings.TrimSpace(peer.Home)
	switch home {
	case "", "/var/empty", "/dev/null", "/nonexistent":
		return true
	}
	// A home the directory names but nobody created holds no settings either.
	_, err := os.Stat(home)
	return errors.Is(err, fs.ErrNotExist)
}

// ownRoutingSummary is the routing member of the own-status answer
// (rel-1-0-10 GAP-0574): whether model routing is on, which connectors are
// route-only, and the caller budget nearest its limit. It is the caller own
// view only, built from the routing API rules: with
// routing.admin.visibility.users_see none a standard account gets the
// organization-wide facts (on or off, the routed connectors) and no budget.
// nil when there is no configuration.
func ownRoutingSummary(cfg *config.Config, key string, own routingadmin.Caller, now time.Time) map[string]any {
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
	for _, view := range routingBudgetViews(cfg, key, false, own, now) {
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
