// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// routeOnlyAliasWithoutKey reports whether the gateway cannot call m for a
// route-only connector whose upstream is provider: it names a key (a
// protected credential or api_key_env) that does not resolve, or it names
// none and the agent credential cannot serve it (another provider, not a
// loopback model, no Bedrock block). It mirrors routeOnlyCredentialFits.
func routeOnlyAliasWithoutKey(cfg *config.Config, m config.RoutingModelBackend, provider string) bool {
	switch {
	case strings.TrimSpace(m.Credential) != "":
		return routingCredentialValue(cfg, m.Credential) == ""
	case strings.TrimSpace(m.APIKeyEnv) != "":
		return ResolveAPIKey(m.APIKeyEnv, filepath.Join(cfg.DataDir, ".env")) == ""
	case strings.EqualFold(strings.TrimSpace(m.Provider), provider), m.Bedrock != nil:
		return false
	}
	bedrock := strings.EqualFold(strings.TrimSpace(m.Provider), "bedrock")
	return bedrock || strings.TrimSpace(m.BaseURL) == "" || !isLoopbackBaseURL(m.BaseURL)
}

// deadAllowRule is a routing.admin rule whose allowed aliases all lack a key.
type deadAllowRule struct {
	ID      string
	Aliases []string
}

// routeOnlyDeadAllowRules returns, in rule order, the routing.admin rules
// that apply to connector and allow only aliases the gateway cannot call,
// with those aliases: every call that matches such a rule is refused, so the
// connector is not ready (rel-1-0-10 GAP-0921). Managed hosts only: OSS
// reports an allow list and keeps routing.
func routeOnlyDeadAllowRules(cfg *config.Config, connector, provider string) []deadAllowRule {
	if cfg == nil || cfg.Routing.Admin == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	var out []deadAllowRule
	for _, rule := range cfg.Routing.Admin.Rules {
		if rule.Action == config.RoutingRuleActionDeny || len(rule.Allow) == 0 {
			continue
		}
		if len(rule.Match.Connectors) > 0 && !slices.ContainsFunc(rule.Match.Connectors, func(c string) bool { return strings.EqualFold(strings.TrimSpace(c), connector) }) {
			continue
		}
		var dead []string
		usable := false
		for _, alias := range rule.Allow {
			i := slices.IndexFunc(cfg.Routing.Models, func(m config.RoutingModelBackend) bool { return m.Name == alias })
			if i < 0 {
				continue
			}
			if routeOnlyAliasWithoutKey(cfg, cfg.Routing.Models[i], provider) {
				dead = append(dead, alias)
			} else {
				usable = true
			}
		}
		if len(dead) > 0 && !usable {
			out = append(out, deadAllowRule{ID: rule.ID, Aliases: dead})
		}
	}
	return out
}
