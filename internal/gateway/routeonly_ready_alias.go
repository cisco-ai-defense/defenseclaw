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

// routeOnlyConnectorWideRule reports whether rule applies to every caller of
// connector: its match names only connectors (and the connector is one of
// them), with no user, group, agent, category or severity selector. Only such
// a rule decides the readiness of the connector; a scoped rule can refuse a
// subset of callers and leave the rest served.
func routeOnlyConnectorWideRule(rule config.RoutingAdminRule, connector string) bool {
	m := rule.Match
	if len(m.Users)+len(m.Groups)+len(m.Agents)+len(m.Categories) > 0 || strings.TrimSpace(m.SeverityAtLeast) != "" {
		return false
	}
	return len(m.Connectors) == 0 || slices.ContainsFunc(m.Connectors, func(c string) bool { return strings.EqualFold(strings.TrimSpace(c), connector) })
}

// routeOnlyAllowedWithoutKey reports, for the routing.admin allow rules that
// can refuse calls of connector, whether one that applies to every caller
// allows only aliases the gateway cannot call (blocking: every call is
// refused), and whether a scoped rule does (a warning: some callers are
// refused). It reports no names: its result goes into the credentialless
// /health, and an administrator sees which rule and model through doctor
// (policy privacy, rel-1-0-10 GAP-0666). Managed hosts only: OSS reports an
// allow list and keeps routing.
func routeOnlyAllowedWithoutKey(cfg *config.Config, connector, provider string) (blocking, scoped bool) {
	if cfg == nil || cfg.Routing.Admin == nil || !cfg.StandaloneEnterprise() {
		return false, false
	}
	for _, rule := range cfg.Routing.Admin.Rules {
		if rule.Action == config.RoutingRuleActionDeny || len(rule.Allow) == 0 {
			continue
		}
		if len(rule.Match.Connectors) > 0 && !slices.ContainsFunc(rule.Match.Connectors, func(c string) bool { return strings.EqualFold(strings.TrimSpace(c), connector) }) {
			continue
		}
		dead, usable := false, false
		for _, alias := range rule.Allow {
			i := slices.IndexFunc(cfg.Routing.Models, func(m config.RoutingModelBackend) bool { return m.Name == alias })
			if i < 0 {
				continue
			}
			if routeOnlyAliasWithoutKey(cfg, cfg.Routing.Models[i], provider) {
				dead = true
			} else {
				usable = true
			}
		}
		if !dead || usable {
			continue
		}
		if routeOnlyConnectorWideRule(rule, connector) {
			blocking = true
		} else {
			scoped = true
		}
	}
	return blocking, scoped
}
