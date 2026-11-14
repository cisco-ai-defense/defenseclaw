// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// MachinePolicyRouteOnly reports whether a machine-policy connector
// (Claude Code, Codex on managed Linux and macOS) is routed by route-only
// on this standalone managed host. Such a connector gets a per-user row for
// every enrolled account whatever enrollment.unenrolled_users says: the row
// carries the account's own route render (its ~/.claude/settings.json env
// or ~/.codex/config.toml provider; never a machine-wide file) and lets the
// gateway verify the account's route credential (rel-1-0-10 GAP-0568).
func MachinePolicyRouteOnly(cfg *config.Config, connectorName string) bool {
	return cfg != nil && cfg.StandaloneEnterprise() && cfg.RouteOnlyRouted(connectorName)
}
