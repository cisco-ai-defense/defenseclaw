// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// GAP-2393: `setup llm --provider custom --instance-name <n>` saves
// provider "custom"; the bound instance's base_provider_type is the
// family, so the judge starts on it instead of "unsupported provider type".
func TestGAP2393CustomProviderUsesTheBoundInstanceFamily(t *testing.T) {
	registry := &configs.ProvidersConfig{Providers: []configs.Provider{{
		Name:             "acme-bedrock-prod",
		BaseProviderType: "bedrock",
		Bedrock:          &configs.ProviderBedrock{Region: "us-east-1", AuthMode: "instance_role", InferenceProfile: "us."},
	}}}
	llm := config.LLMConfig{
		Provider:     "custom",
		Model:        "anthropic.claude-haiku-4-5-20251001-v1:0",
		InstanceName: "acme-bedrock-prod",
	}

	p, err := NewProviderForLLMConfig(&llm, registry)
	if err != nil {
		t.Fatalf("NewProviderForLLMConfig(provider custom): %v", err)
	}
	bp, ok := p.(*bifrostProvider)
	if !ok {
		t.Fatalf("expected *bifrostProvider, got %T", p)
	}
	if bp.providerKey != schemas.Bedrock {
		t.Fatalf("providerKey = %q, want bedrock from the instance", bp.providerKey)
	}
	if bp.bedrock == nil || bp.bedrock.Region != "us-east-1" {
		t.Fatalf("bedrock sub-block not taken from the instance: %+v", bp.bedrock)
	}
	if bp.model != "us.anthropic.claude-haiku-4-5-20251001-v1:0" {
		t.Fatalf("model = %q, want the instance's inference profile applied", bp.model)
	}

	// The judge starts with no API key: a Bedrock instance uses the AWS chain.
	judge, reason := newLLMJudgeWithReason(&config.JudgeConfig{Enabled: true}, llm, "", nil, registry)
	if judge == nil || reason != "" {
		t.Fatalf("judge=%v reason=%q, want a running judge on the custom instance", judge, reason)
	}
	if !llmJudgeAllowsEmptyAPIKey(llm, registry) {
		t.Fatal("a custom provider bound to a Bedrock instance must not need an API key")
	}

	// An explicit family on the role still wins over the instance.
	explicit := llm
	explicit.Provider = "openai"
	explicit.APIKey = "k"
	p, err = NewProviderForLLMConfig(&explicit, registry)
	if err != nil {
		t.Fatalf("explicit provider: %v", err)
	}
	if got := p.(*bifrostProvider).providerKey; got != schemas.OpenAI {
		t.Fatalf("explicit role provider lost to the instance: %q", got)
	}
}

func TestGAP2393CustomProviderWithoutAnInstanceNamesTheFix(t *testing.T) {
	_, err := NewProviderForLLMConfig(&config.LLMConfig{Provider: "custom", Model: "heavy", APIKey: "k", InstanceName: "missing"}, &configs.ProvidersConfig{})
	if err == nil || !strings.Contains(err.Error(), "instance_name") {
		t.Fatalf("err = %v, want a message naming instance_name", err)
	}
}
