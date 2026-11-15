// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10 GAP-0921: enterprise status said "route-only: codex ready"
// while the only model its rule allows had no gateway credential, so every
// call was refused.
func TestRouteOnlyReadinessAllowedAliasWithoutCredential(t *testing.T) {
	cfg := readinessConfig(config.RoutingUpstreamConfig{BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses})
	cfg.Routing.RouteOnly.Connectors = []string{"codex"}
	cfg.Routing.RouteOnly.Upstreams = map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fixture-bedrock", Provider: "bedrock", Model: "fixture-model"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fixture-bedrock"}}}}
	useRoutingCredentials(t, map[string]string{})
	var signers bedrockSigners

	r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil))
	if r.Ready || !strings.Contains(r.Problem, "fixture-bedrock") || !strings.Contains(r.Problem, "fixture-rule") || !strings.Contains(r.Fix, "enterprise secret set") {
		t.Fatalf("allowed alias without a key: %+v", r)
	}

	// A named credential that is not stored is the same problem.
	cfg.Routing.Models[0].Credential = "fixture-key"
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); r.Ready || !strings.Contains(r.Problem, "fixture-bedrock") {
		t.Fatalf("unstored credential: %+v", r)
	}

	// Stored: ready.
	useRoutingCredentials(t, map[string]string{"fixture-key": "fixture-value"})
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready || r.Problem != "" {
		t.Fatalf("stored credential: %+v", r)
	}

	// One usable alias in the rule keeps the connector ready.
	useRoutingCredentials(t, map[string]string{})
	cfg.Routing.Models = append(cfg.Routing.Models, config.RoutingModelBackend{Name: "fixture-openai", Provider: "openai", Model: "fixture-model"})
	cfg.Routing.Admin.Rules[0].Allow = []string{"fixture-bedrock", "fixture-openai"}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("a usable alias remains: %+v", r)
	}

	// A rule for another connector does not matter; OSS never refuses.
	cfg.Routing.Admin.Rules[0].Allow = []string{"fixture-bedrock"}
	cfg.Routing.Admin.Rules[0].Match.Connectors = []string{"claudecode"}
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("other connector rule: %+v", r)
	}
	cfg.Routing.Admin.Rules[0].Match.Connectors = []string{"codex"}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "", ""
	if r := onlyReadiness(t, routeOnlyReadinessFor(cfg, "linux", &signers, nil)); !r.Ready {
		t.Fatalf("OSS host: %+v", r)
	}
}
