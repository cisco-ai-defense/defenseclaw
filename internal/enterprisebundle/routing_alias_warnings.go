// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"net/url"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// WarnRoutingAliasNoCredential names a routing.admin allow-list model that
// names no gateway key while no route-only connector can serve it with the
// agent credential: a call that has to use it is refused.
const WarnRoutingAliasNoCredential = "routing_allowed_alias_no_credential"

// RoutingAliasCredentialWarnings returns one warning per model that a
// routing.admin rule allows, that names neither routing.models[].credential
// nor api_key_env, has no Bedrock block and no loopback base_url, and whose
// provider no route-only upstream shares (rel-1-0-10 GAP-0921: the call was
// refused as "not allowed" with no hint that a credential was missing).
func RoutingAliasCredentialWarnings(cfg *config.Config) []Warning {
	if cfg == nil || !cfg.Routing.Enabled || cfg.Routing.Admin == nil || len(cfg.Routing.RouteOnly.Connectors) == 0 {
		return nil
	}
	var providers []string
	for _, c := range cfg.Routing.RouteOnly.Connectors {
		if up, ok := cfg.Routing.RouteOnly.Upstreams[c]; ok {
			providers = append(providers, config.RouteOnlyUpstreamProvider(up.API))
		}
	}
	var out []Warning
	seen := map[string]bool{}
	for _, rule := range cfg.Routing.Admin.Rules {
		if rule.Action == config.RoutingRuleActionDeny {
			continue
		}
		for _, alias := range rule.Allow {
			if seen[alias] {
				continue
			}
			i := slices.IndexFunc(cfg.Routing.Models, func(m config.RoutingModelBackend) bool { return m.Name == alias })
			if i < 0 {
				continue
			}
			m := cfg.Routing.Models[i]
			if strings.TrimSpace(m.Credential) != "" || strings.TrimSpace(m.APIKeyEnv) != "" || m.Bedrock != nil || loopbackModelURL(m.BaseURL) ||
				slices.ContainsFunc(providers, func(p string) bool { return strings.EqualFold(p, strings.TrimSpace(m.Provider)) }) {
				continue
			}
			seen[alias] = true
			out = append(out, Warning{Code: WarnRoutingAliasNoCredential, Subject: boundedText(alias, 64),
				Message: "routing.admin rule " + boundedText(rule.ID, 64) + " allows model " + boundedText(alias, 64) + ", which has no routing.models[].credential: calls that must use it are refused until a credential is named and stored (enterprise secret set)"})
		}
	}
	return out
}

func loopbackModelURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), "localhost") || strings.HasPrefix(u.Hostname(), "127.") || u.Hostname() == "::1"
}
