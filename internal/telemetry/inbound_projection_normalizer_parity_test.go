// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// This parity lock allows the inbound receiver to move to generated registry
// authority without changing the PR #412 provider/model time-series labels.
func TestGeneratedInboundMetricNormalizersPreservePR412Parity(t *testing.T) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatalf("LoadInboundCatalog() error = %v", err)
	}
	provider, ok := catalog.SourceNormalizer("genai-provider-label-v1")
	if !ok {
		t.Fatal("generated provider normalizer missing")
	}
	model, ok := catalog.SourceNormalizer("genai-model-label-v1")
	if !ok {
		t.Fatal("generated model normalizer missing")
	}
	providerInputs := []string{
		"", " ", "Anthropic", "claudecode", "codex", "gemini-cli", "openai-with-random-suffix",
		"attacker-provider-2026-05-18-uuid", "azure-openai", "aws-bedrock", "ollama-local", "local",
		strings.Repeat("provider-", 20),
	}
	for _, input := range providerInputs {
		want := NormalizeGenAIProviderLabel(input)
		if got, valid := provider.Normalize(input); !valid || got != want {
			t.Errorf("provider Normalize(%q) = %q/%v, legacy=%q", input, got, valid, want)
		}
	}
	modelInputs := []string{
		"", "   ", "unknown", "some-future-model-9000", strings.Repeat("a", 200),
		"gpt-5", "gpt-5-mini-2026-04-18", "gpt-4o-mini-2024-07-18", "gpt-4-turbo", "gpt-3.5-turbo",
		"o1", "o3-mini", "claude-4-sonnet", "claude-3-7-sonnet-20250219", "claude-sonnet-4-5",
		"claude-opus-4-5-20250514", "claude-haiku-3-5", "gemini-2.0-flash", "gemini-1.5-pro-002",
		"gemini-experimental", "llama-4-maverick", "llama-3.1-405b", "mistral-large", "deepseek-r1",
		"qwen-2.5-32b", "grok-3-beta", "command-r-plus-2025-04", "phi-3.5", "phi-4-mini",
		"GPT-5", "Claude-Opus-4-5", "anthropic:claude-3-7-sonnet", "claude-3:vllm-pinned",
	}
	for _, input := range modelInputs {
		want := NormalizeModelLabel(input)
		if got, valid := model.Normalize(input); !valid || got != want {
			t.Errorf("model Normalize(%q) = %q/%v, legacy=%q", input, got, valid, want)
		}
	}
}
