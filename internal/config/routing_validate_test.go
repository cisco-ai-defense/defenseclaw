// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func validRoutingConfigForTest() RoutingConfig {
	return RoutingConfig{
		Enabled: true,
		Version: "0.3.0",
		Port:    8888,
		Models: []RoutingModelBackend{
			{Name: "fast", Provider: "ollama", Model: "qwen2.5:0.5b", BaseURL: "http://127.0.0.1:11434"},
			{Name: "reasoning", Provider: "openai", Model: "gpt-4.1", APIKeyEnv: "OPENAI_API_KEY"},
		},
		Signals: RoutingSignalConfig{Keywords: []RoutingKeywordSignal{{
			Name: "code", Keywords: []string{"debug", "implement"}, Operator: "OR",
		}}},
		Decisions: []RoutingDecisionRule{{Name: "default", ModelRefs: []string{"fast"}}},
	}
}

func TestRoutingConfigValidateAcceptsConfiguredBackends(t *testing.T) {
	cfg := validRoutingConfigForTest()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestRoutingConfigValidateRemoteEndpointTransportPolicy(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  string
	}{
		{name: "IPv4 loopback HTTP", endpoint: "http://127.0.0.1:8080"},
		{name: "IPv6 loopback HTTP", endpoint: "http://[::1]:8080"},
		{name: "localhost HTTP", endpoint: "http://localhost:8080"},
		{name: "private IPv4 HTTPS", endpoint: "https://10.0.0.8:8080"},
		{name: "private IPv6 HTTPS", endpoint: "https://[fd00::8]:8080"},
		{name: "public HTTPS", endpoint: "https://router.example.test"},
		{name: "private IPv4 HTTP", endpoint: "http://10.0.0.8:8080", wantErr: "must use https for non-loopback destinations"},
		{name: "private IPv6 HTTP", endpoint: "http://[fd00::8]:8080", wantErr: "must use https for non-loopback destinations"},
		{name: "Docker host HTTP", endpoint: "http://host.docker.internal:8080", wantErr: "must use https for non-loopback destinations"},
		{name: "Docker gateway HTTP", endpoint: "http://gateway.docker.internal:8080", wantErr: "must use https for non-loopback destinations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validRoutingConfigForTest()
			cfg.Remote.Endpoint = tt.endpoint
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRoutingConfigValidateKeepsPrivateHTTPModelBackendCompatible(t *testing.T) {
	cfg := validRoutingConfigForTest()
	cfg.Models[0].BaseURL = "http://10.0.0.8:11434"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestRoutingConfigValidateRejectsInvalidRelationships(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RoutingConfig)
		want string
	}{
		{name: "enabled without models", edit: func(c *RoutingConfig) { c.Models = nil }, want: "at least one backend"},
		{name: "duplicate alias", edit: func(c *RoutingConfig) { c.Models[1].Name = "fast" }, want: "duplicated"},
		{name: "unknown decision ref", edit: func(c *RoutingConfig) { c.Decisions[0].ModelRefs = []string{"missing"} }, want: "unknown model alias"},
		{name: "duplicate keyword signal", edit: func(c *RoutingConfig) {
			c.Signals.Keywords = append(c.Signals.Keywords, c.Signals.Keywords[0])
		}, want: "duplicated"},
		{name: "empty keyword list", edit: func(c *RoutingConfig) { c.Signals.Keywords[0].Keywords = nil }, want: "at least one keyword"},
		{name: "unknown keyword condition", edit: func(c *RoutingConfig) {
			c.Decisions[0].Conditions = []RoutingCondition{{Type: "keyword", Name: "missing"}}
		}, want: "unknown keyword signal"},
		{name: "unsupported condition", edit: func(c *RoutingConfig) {
			c.Decisions[0].Conditions = []RoutingCondition{{Type: "embedding", Name: "code"}}
		}, want: "unsupported"},
		{name: "invalid signal operator", edit: func(c *RoutingConfig) { c.Signals.Keywords[0].Operator = "XOR" }, want: "AND or OR"},
		{name: "invalid key env", edit: func(c *RoutingConfig) { c.Models[1].APIKeyEnv = "not-valid!" }, want: "environment variable"},
		{name: "credential in URL", edit: func(c *RoutingConfig) { c.Models[0].BaseURL = "https://user:pass@example.test/v1" }, want: "embedded credentials"},
		{name: "query in URL", edit: func(c *RoutingConfig) { c.Models[0].BaseURL = "http://127.0.0.1:11434/v1?token=secret" }, want: "URL query"},
		{name: "public plaintext backend", edit: func(c *RoutingConfig) { c.Models[0].BaseURL = "http://api.example.test/v1" }, want: "must use https"},
		{name: "metadata backend", edit: func(c *RoutingConfig) { c.Models[0].BaseURL = "http://169.254.169.254/latest" }, want: "metadata"},
		{name: "metadata hostname", edit: func(c *RoutingConfig) { c.Remote.Endpoint = "https://metadata.google.internal/computeMetadata/v1" }, want: "metadata"},
		{name: "excessive timeout", edit: func(c *RoutingConfig) { c.Remote.TimeoutMs = 5001 }, want: "must not exceed"},
		{name: "oversized alias", edit: func(c *RoutingConfig) {
			c.Models[0].Name = strings.Repeat("a", 129)
			c.Decisions[0].ModelRefs = []string{c.Models[0].Name}
		}, want: "128 bytes"},
		{name: "unsafe version", edit: func(c *RoutingConfig) { c.Version = "0.3.0;latest" }, want: "semantic version"},
		{name: "untested version", edit: func(c *RoutingConfig) { c.Version = "0.4.0" }, want: "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validRoutingConfigForTest()
			tt.edit(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tt.want)
			}
		})
	}
}
