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

func TestRoutingConfigValidateAcceptsIdentifierV1ProviderModels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model string
	}{
		{name: "Ollama colon ID", model: "qwen2.5:0.5b"},
		{name: "namespaced Ollama ID", model: "library/llama3.2:latest"},
		{name: "provider-qualified ID", model: "anthropic.claude-sonnet-4-6"},
		{name: "256 byte boundary", model: strings.Repeat("a", 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validRoutingConfigForTest()
			cfg.Models[0].Model = tc.model
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v", err)
			}
		})
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
			c.Decisions[0].Conditions = []RoutingCondition{{Type: "magic", Name: "code"}}
		}, want: "unsupported"},
		{name: "invalid signal operator", edit: func(c *RoutingConfig) { c.Signals.Keywords[0].Operator = "XOR" }, want: "AND or OR"},
		{name: "invalid key env", edit: func(c *RoutingConfig) { c.Models[1].APIKeyEnv = "not-valid!" }, want: "environment variable"},
		{name: "oversized provider", edit: func(c *RoutingConfig) { c.Models[0].Provider = strings.Repeat("p", 4097) }, want: "4096 bytes"},
		{name: "empty model", edit: func(c *RoutingConfig) { c.Models[0].Model = "" }, want: "non-empty"},
		{name: "model with spaces", edit: func(c *RoutingConfig) { c.Models[0].Model = "qwen 2.5:0.5b" }, want: "identifier-v1"},
		{name: "oversized model", edit: func(c *RoutingConfig) { c.Models[0].Model = strings.Repeat("a", 257) }, want: "256 bytes"},
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

func TestRoutingFullSignalConfigRoundTrip(t *testing.T) {
	cfg := RoutingConfig{
		Enabled:    true,
		Embeddings: RoutingEmbeddingsConfig{MMBertModelPath: "/tmp/mmbert"},
		Models: []RoutingModelBackend{
			{Name: "cloud", Provider: "openai", Model: "o4-mini", BaseURL: "https://api.openai.com/v1", APIKeyEnv: "OPENAI_API_KEY"},
			{Name: "local", Provider: "openai", Model: "llama3.2:3b", BaseURL: "http://localhost:11434/v1"},
		},
		Signals: RoutingSignalConfig{
			Keywords:   []RoutingKeywordSignal{{Name: "planning", Keywords: []string{"plan", "design"}, Operator: "OR"}},
			Embeddings: []RoutingEmbeddingSignal{{Name: "arch", Description: "architecture", Examples: []string{"design a system"}}},
			Domains:    []RoutingDomainSignal{{Name: "devops", Categories: []string{"kubernetes"}}},
			Complexity: []RoutingComplexitySignal{{Name: "high", MinMessageLength: 500}},
		},
		Decisions: []RoutingDecisionRule{
			{Name: "complex-to-cloud", Priority: 100, ModelRefs: []string{"cloud"},
				Conditions: []RoutingCondition{
					{Type: "embedding", Name: "arch", MinConfidence: 0.8},
					{Type: "complexity", Name: "high"},
				}, Operator: "AND"},
			{Name: "plan-to-cloud", Priority: 90, ModelRefs: []string{"cloud"},
				Conditions: []RoutingCondition{{Type: "keyword", Name: "planning"}}},
			{Name: "devops-to-local", Priority: 80, ModelRefs: []string{"local"},
				Conditions: []RoutingCondition{{Type: "domain", Name: "devops"}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("full signal config should validate, got: %v", err)
	}
}

func TestRoutingEmptySignalsWithEnabledRouting(t *testing.T) {
	cfg := RoutingConfig{
		Enabled: true,
		Models: []RoutingModelBackend{{
			Name: "test", Provider: "openai", Model: "gpt-4o", BaseURL: "https://api.openai.com/v1",
		}},
		Signals:   RoutingSignalConfig{},
		Decisions: nil,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty signals with enabled routing should be valid: %v", err)
	}
}

func TestRoutingExistingKeywordOnlyConfigStillValid(t *testing.T) {
	cfg := RoutingConfig{
		Enabled: true,
		Models: []RoutingModelBackend{{
			Name: "test", Provider: "openai", Model: "gpt-4o", BaseURL: "https://api.openai.com/v1",
		}},
		Signals: RoutingSignalConfig{
			Keywords: []RoutingKeywordSignal{{Name: "code", Keywords: []string{"fix", "debug"}, Operator: "OR"}},
		},
		Decisions: []RoutingDecisionRule{{
			Name: "route-code", Priority: 100, ModelRefs: []string{"test"},
			Conditions: []RoutingCondition{{Type: "keyword", Name: "code"}},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("keyword-only config must remain valid: %v", err)
	}
}

func TestRoutingValidateRejectsEmbeddingWithoutModelPaths(t *testing.T) {
	cfg := RoutingConfig{
		Enabled: true,
		Models: []RoutingModelBackend{{
			Name: "test", Provider: "openai", Model: "gpt-4o", BaseURL: "https://api.openai.com/v1",
		}},
		Signals: RoutingSignalConfig{
			Embeddings: []RoutingEmbeddingSignal{{Name: "arch", Examples: []string{"design"}}},
		},
		Decisions: []RoutingDecisionRule{{
			Name: "route-arch", Priority: 100, ModelRefs: []string{"test"},
			Conditions: []RoutingCondition{{Type: "embedding", Name: "arch"}},
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for embedding condition without model paths")
	}
	if !strings.Contains(err.Error(), "embedding model path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoutingValidateRejectsMinConfidenceOutOfRange(t *testing.T) {
	cfg := RoutingConfig{
		Enabled:    true,
		Embeddings: RoutingEmbeddingsConfig{MMBertModelPath: "/tmp/mmbert"},
		Models: []RoutingModelBackend{{
			Name: "test", Provider: "openai", Model: "gpt-4o", BaseURL: "https://api.openai.com/v1",
		}},
		Signals: RoutingSignalConfig{
			Embeddings: []RoutingEmbeddingSignal{{Name: "arch", Examples: []string{"design"}}},
		},
		Decisions: []RoutingDecisionRule{{
			Name: "route-arch", Priority: 100, ModelRefs: []string{"test"},
			Conditions: []RoutingCondition{{Type: "embedding", Name: "arch", MinConfidence: 1.5}},
		}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for min_confidence > 1.0")
	}
	if !strings.Contains(err.Error(), "min_confidence") {
		t.Fatalf("unexpected error: %v", err)
	}
}
