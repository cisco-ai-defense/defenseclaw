// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateManagedRoutingRefusals(t *testing.T) {
	routed := func() *Config {
		c := &Config{}
		c.Routing.Enabled = true
		c.Routing.Models = []RoutingModelBackend{{Name: "haiku", Provider: "anthropic", Model: "claude-haiku-4-5", Credential: "anthropic-org"}}
		c.Routing.RouteOnly = RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]RoutingUpstreamConfig{"claudecode": {BaseURL: "https://api.anthropic.com", API: "messages"}}}
		return c
	}
	cases := []struct {
		name string
		goos string
		mut  func(*Config)
		want string
	}{
		{"credential refs on linux", "linux", nil, ""},
		{"macOS", "darwin", nil, ""},
		{"models api_key_env", "linux", func(c *Config) { c.Routing.Models[0].APIKeyEnv = "ANTHROPIC_API_KEY" }, "models[0].api_key_env"},
		{"models bedrock env", "linux", func(c *Config) {
			c.Routing.Models[0].Bedrock = &RoutingBedrockAuthConfig{AccessKeyEnv: "AWS_ACCESS_KEY_ID"}
		}, "models[0].bedrock.access_key_env"},
		{"route-only upstream bedrock env", "darwin", func(c *Config) {
			c.Routing.RouteOnly.Upstreams["claudecode"] = RoutingUpstreamConfig{BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: "converse", Bedrock: &RoutingBedrockAuthConfig{SessionTokenEnv: "AWS_SESSION_TOKEN"}}
		}, "upstreams.claudecode.bedrock.session_token_env"},
		{"systemone api_key_env", "linux", func(c *Config) { c.Routing.SystemOne = &RoutingSystemOneConfig{APIKeyEnv: "S1_KEY"} }, "systemone.api_key_env"},
		{"managed Windows route-only (interim)", "windows", nil, "windows_no_peer_factor"},
		{"managed Windows without route-only", "windows", func(c *Config) { c.Routing.RouteOnly = RoutingRouteOnlyConfig{} }, ""},
		{"connector without base_url capability", "linux", func(c *Config) { c.Routing.RouteOnly.Connectors = []string{"cursor"} }, "no routing base_url capability"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := routed()
			if tc.mut != nil {
				tc.mut(c)
			}
			err := validateManagedRouting(c, tc.goos)
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
