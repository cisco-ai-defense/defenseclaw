// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRoutingAliasCredentialWarnings(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex"}, Upstreams: map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com", API: config.RoutingAPIResponses}}}
	cfg.Routing.Models = []config.RoutingModelBackend{
		{Name: "fixture-bedrock", Provider: "bedrock", Model: "m"},
		{Name: "fixture-keyed", Provider: "bedrock", Model: "m", Credential: "fixture-key"},
		{Name: "fixture-same", Provider: "openai", Model: "m"},
		{Name: "fixture-local", Provider: "ollama", Model: "m", BaseURL: "http://127.0.0.1:11434"},
	}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: []config.RoutingAdminRule{{ID: "fixture-rule", Allow: []string{"fixture-bedrock", "fixture-keyed", "fixture-same", "fixture-local"}}}}
	got := RoutingAliasCredentialWarnings(cfg)
	if len(got) != 1 || got[0].Code != WarnRoutingAliasNoCredential || got[0].Subject != "fixture-bedrock" || !strings.Contains(got[0].Message, "fixture-rule") {
		t.Fatalf("warnings = %+v", got)
	}
	cfg.Routing.Models[0].Credential = "fixture-key"
	if got := RoutingAliasCredentialWarnings(cfg); len(got) != 0 {
		t.Fatalf("with a credential: %+v", got)
	}
	if RoutingAliasCredentialWarnings(nil) != nil {
		t.Fatal("nil config")
	}
}
