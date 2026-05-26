// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

func TestSplitModelKnownPrefixes(t *testing.T) {
	tests := []struct {
		input     string
		wantProv  string
		wantModel string
	}{
		{"openai/gpt-4o", "openai", "gpt-4o"},
		{"anthropic/claude-opus-4-5", "anthropic", "claude-opus-4-5"},
		{"openrouter/anthropic/claude-opus-4-5", "openrouter", "anthropic/claude-opus-4-5"},
		{"azure/gpt-4o", "azure", "gpt-4o"},
		{"gemini/gemini-2.0-flash", "gemini", "gemini-2.0-flash"},
		{"gemini-openai/gemini-2.0-flash", "gemini-openai", "gemini-2.0-flash"},
		{"unknown/foo", "", "unknown/foo"},
		{"gpt-4o", "", "gpt-4o"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prov, model := splitModel(tt.input)
			if prov != tt.wantProv || model != tt.wantModel {
				t.Errorf("splitModel(%q) = (%q, %q), want (%q, %q)",
					tt.input, prov, model, tt.wantProv, tt.wantModel)
			}
		})
	}
}

func TestInferProviderNew(t *testing.T) {
	tests := []struct {
		model  string
		apiKey string
		want   string
	}{
		{"claude-opus-4-5", "", "anthropic"},
		{"claude-haiku-4-5", "sk-ant-api123", "anthropic"},
		{"claude-sonnet-4-20250514", "regular-key", "anthropic"},
		{"gpt-4o", "", "openai"},
		{"gpt-4o-mini", "sk-proj-abc", "openai"},
		{"o3-mini", "sk-test", "openai"},
		{"gemini-2.0-flash", "", "gemini"},
		{"anything", "AIzaSyExample", "gemini"},
		{"anything", "sk-ant-api123", "anthropic"},
		{"anything", "sk-proj-abc", "openai"},
		{"anything", "ABSKtest123", "bedrock"},
		{"us.anthropic.claude-3-5-haiku", "ABSKkey", "bedrock"},
		{"unknown-model", "regular-key", "openai"},
	}
	for _, tt := range tests {
		t.Run(tt.model+"_"+tt.apiKey, func(t *testing.T) {
			got := inferProvider(tt.model, tt.apiKey)
			if got != tt.want {
				t.Errorf("inferProvider(%q, %q) = %q, want %q", tt.model, tt.apiKey, got, tt.want)
			}
		})
	}
}

func TestCompositeModelForUpstream_BedrockZeptoNoDoublePrefix(t *testing.T) {
	// URL inference yields "bedrock" for bedrock-runtime.* hosts; the body
	// already names amazon-bedrock/… (OpenClaw / Zepto stock string).
	got := compositeModelForUpstream("bedrock", "amazon-bedrock/us.anthropic.claude-sonnet-4-6")
	want := "amazon-bedrock/us.anthropic.claude-sonnet-4-6"
	if got != want {
		t.Errorf("compositeModelForUpstream(bedrock, amazon-bedrock/…) = %q, want %q", got, want)
	}
	if got := compositeModelForUpstream("bedrock", "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"); got != "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0" {
		t.Errorf("verbatim bedrock-prefixed model: got %q", got)
	}
	if got := compositeModelForUpstream("openai", "gpt-4o"); got != "openai/gpt-4o" {
		t.Errorf("unprefixed + URL prefix: got %q", got)
	}
}

func TestSplitModel_NewProviders(t *testing.T) {
	tests := []struct {
		input     string
		wantProv  string
		wantModel string
	}{
		{"bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", "bedrock", "us.anthropic.claude-3-5-haiku-20241022-v1:0"},
		{"groq/llama-3", "groq", "llama-3"},
		{"mistral/mistral-large", "mistral", "mistral-large"},
		{"ollama/llama3", "ollama", "llama3"},
		{"vertex/gemini-pro", "vertex", "gemini-pro"},
		{"cohere/command-r", "cohere", "command-r"},
		{"perplexity/sonar-small", "perplexity", "sonar-small"},
		{"cerebras/llama3", "cerebras", "llama3"},
		{"fireworks/llama-v3", "fireworks", "llama-v3"},
		{"xai/grok-2", "xai", "grok-2"},
		{"huggingface/meta-llama/Llama-3", "huggingface", "meta-llama/Llama-3"},
		{"replicate/meta/llama-3", "replicate", "meta/llama-3"},
		{"vllm/meta-llama/Llama-3", "vllm", "meta-llama/Llama-3"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prov, model := splitModel(tt.input)
			if prov != tt.wantProv || model != tt.wantModel {
				t.Errorf("splitModel(%q) = (%q, %q), want (%q, %q)",
					tt.input, prov, model, tt.wantProv, tt.wantModel)
			}
		})
	}
}

func TestNewProvider_BifrostType(t *testing.T) {
	p, err := NewProvider("openai/gpt-4", "test-key")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, ok := p.(*bifrostProvider); !ok {
		t.Errorf("expected *bifrostProvider, got %T", p)
	}
}

func TestNewProviderWithBase_BifrostType(t *testing.T) {
	p, err := NewProviderWithBase("anthropic/claude-3-sonnet", "test-key", "http://localhost:8080/v1")
	if err != nil {
		t.Fatalf("NewProviderWithBase: %v", err)
	}
	bp, ok := p.(*bifrostProvider)
	if !ok {
		t.Fatalf("expected *bifrostProvider, got %T", p)
	}
	if bp.baseURL != "http://localhost:8080/v1" {
		t.Errorf("baseURL = %q", bp.baseURL)
	}
}

// TestNewProviderForLLMConfig_InstanceName routes a config that pins
// an instance_name through NewProviderForInstance and asserts the
// overlay's base_url + TLS bundle end up on the bifrostProvider.
func TestNewProviderForLLMConfig_InstanceName(t *testing.T) {
	registry := &configs.ProvidersConfig{
		Providers: []configs.Provider{
			{
				Name:             "acme-internal",
				BaseProviderType: "openai",
				BaseURL:          "https://llm.internal:8443",
				EnvKeys:          []string{"ACME_KEY"},
				TLS: &configs.ProviderTLS{
					CACertPEM:          "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
					InsecureSkipVerify: true,
				},
			},
		},
	}
	p, err := NewProviderForLLMConfig(
		"acme-internal/some-model",
		"key-1",
		"",
		"acme-internal",
		registry,
	)
	if err != nil {
		t.Fatalf("NewProviderForLLMConfig: %v", err)
	}
	bp, ok := p.(*bifrostProvider)
	if !ok {
		t.Fatalf("expected *bifrostProvider, got %T", p)
	}
	if bp.baseURL != "https://llm.internal:8443" {
		t.Errorf("baseURL = %q; want overlay value", bp.baseURL)
	}
	if !bp.tls.InsecureSkipVerify {
		t.Error("InsecureSkipVerify did not propagate from overlay")
	}
}

// TestNewProviderForLLMConfig_FallbackOnMiss verifies a typo'd
// instance_name silently falls back to BaseURL / NewProvider rather
// than failing the call — the gateway should surface the misconfig
// via `defenseclaw doctor` rather than going offline.
func TestNewProviderForLLMConfig_FallbackOnMiss(t *testing.T) {
	registry := &configs.ProvidersConfig{
		Providers: []configs.Provider{
			{Name: "acme-internal", BaseProviderType: "openai", BaseURL: "https://llm.internal"},
		},
	}
	p, err := NewProviderForLLMConfig(
		"openai/gpt-4",
		"test-key",
		"http://fallback:8080",
		"typo-instance",
		registry,
	)
	if err != nil {
		t.Fatalf("NewProviderForLLMConfig: %v", err)
	}
	bp, ok := p.(*bifrostProvider)
	if !ok {
		t.Fatalf("expected *bifrostProvider, got %T", p)
	}
	if bp.baseURL != "http://fallback:8080" {
		t.Errorf("expected fallback to BaseURL on miss; got %q", bp.baseURL)
	}
}
