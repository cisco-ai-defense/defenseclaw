// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
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
		{"managed Windows route-only (guardian peer broker)", "windows", nil, ""},
		{"managed Windows route-only bedrock env", "windows", func(c *Config) {
			c.Routing.RouteOnly.Upstreams["claudecode"] = RoutingUpstreamConfig{BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: "converse", Bedrock: &RoutingBedrockAuthConfig{AccessKeyEnv: "AWS_ACCESS_KEY_ID"}}
		}, "upstreams.claudecode.bedrock.access_key_env"},
		{"managed Windows without route-only", "windows", func(c *Config) { c.Routing.RouteOnly = RoutingRouteOnlyConfig{} }, ""},
		{"connector without base_url capability", "linux", func(c *Config) { c.Routing.RouteOnly.Connectors = []string{"cursor"} }, "no routing base_url capability"},
		{"bedrock auth profile on a route-only upstream", "darwin", func(c *Config) {
			c.Routing.RouteOnly.Upstreams["claudecode"] = RoutingUpstreamConfig{BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", API: "invoke", Bedrock: &RoutingBedrockAuthConfig{Auth: RoutingBedrockAuthProfile, Profile: "default"}}
		}, "upstreams.claudecode.bedrock.auth profile"},
		{"bedrock auth profile on a model", "linux", func(c *Config) {
			c.Routing.Models[0].Bedrock = &RoutingBedrockAuthConfig{Auth: "Profile"}
		}, "models[0].bedrock.auth profile"},
		{"bedrock instance_role", "linux", func(c *Config) {
			c.Routing.Models[0].Bedrock = &RoutingBedrockAuthConfig{Auth: RoutingBedrockAuthInstanceRole}
		}, ""},
		{"systemone api_key_env with routing off", "linux", func(c *Config) {
			c.Routing.Enabled = false
			c.Routing.SystemOne = &RoutingSystemOneConfig{APIKeyEnv: "S1_KEY"}
		}, "systemone.api_key_env"},
		{"bedrock env with routing off", "linux", func(c *Config) {
			c.Routing.Enabled = false
			c.Routing.Models[0].Bedrock = &RoutingBedrockAuthConfig{SecretKeyEnv: "AWS_SECRET_ACCESS_KEY"}
		}, "models[0].bedrock.secret_key_env"},
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

// A 1.0.9 managed config with a routing.models block that names
// api_key_env and routing off (vllm_sr era) still validates after the
// 1.0.10 package lands (upgrade path, REVIEW-code-slice4 P2-1); the name is
// reported as ignored. Turning routing on refuses it.
func TestValidateManagedRoutingAccepts109ManagedShape(t *testing.T) {
	var warned bytes.Buffer
	prev := managedRoutingWarnings
	managedRoutingWarnings = &warned
	t.Cleanup(func() { managedRoutingWarnings = prev })
	c := &Config{}
	c.Routing = RoutingConfig{
		Enabled: false, Version: "0.3.0", Port: 8801,
		Models: []RoutingModelBackend{
			{Name: "fast", Provider: "openai", Model: "gpt-4.1-mini", APIKeyEnv: "OPENAI_API_KEY"},
			{Name: "local", Provider: "ollama", Model: "llama3.1", BaseURL: "http://127.0.0.1:11434"},
		},
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		warned.Reset()
		if err := validateManagedRouting(c, goos); err != nil {
			t.Fatalf("%s: a 1.0.9 managed config is refused after upgrade: %v", goos, err)
		}
		if !strings.Contains(warned.String(), "routing.models[0].api_key_env is ignored") {
			t.Fatalf("%s: no warning for the ignored name: %q", goos, warned.String())
		}
	}
	c.Routing.Enabled = true
	if err := validateManagedRouting(c, "linux"); err == nil || !strings.Contains(err.Error(), "models[0].api_key_env") {
		t.Fatalf("routing on with api_key_env = %v, want a refusal", err)
	}
}
