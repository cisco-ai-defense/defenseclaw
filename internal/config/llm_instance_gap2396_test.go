// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// GAP-2396: `setup llm --provider custom --instance-name <n>` saves provider
// "custom"; every Go caller of ResolveLLM (the watcher and hook scanners
// too) must see the bound llm_providers.custom instance's family and
// sub-blocks, not "custom".
func TestGAP2396ResolveLLMAppliesTheBoundCustomInstance(t *testing.T) {
	c := &Config{
		LLM: LLMConfig{Provider: "custom", InstanceName: "Acme-Bedrock-Prod", Model: "anthropic.claude-haiku-4-5-20251001-v1:0"},
		LLMProviders: LLMProvidersConfig{Custom: []LLMCustomProvider{
			{Name: "acme-bedrock-prod", BaseProviderType: "Bedrock",
				Bedrock: &BedrockKeyConfig{Region: "us-east-1", AuthMode: "instance_role", InferenceProfile: "us."}},
			{Name: "acme-gw", BaseProviderType: "openai", BaseURL: "https://llm.acme.example/v1"},
		}},
	}
	for _, path := range []string{"", "scanners.skill", "scanners.mcp", "scanners.plugin", "guardrail.judge"} {
		got := c.ResolveLLM(path)
		if got.Provider != "bedrock" {
			t.Fatalf("%q: provider = %q, want bedrock from the instance", path, got.Provider)
		}
		if got.Bedrock == nil || got.Bedrock.Region != "us-east-1" || got.Bedrock.AuthMode != "instance_role" || got.Bedrock.InferenceProfile != "us." {
			t.Fatalf("%q: bedrock sub-block not taken from the instance: %+v", path, got.Bedrock)
		}
	}
	if c.LLMProviders.Custom[0].Bedrock == c.ResolveLLM("").Bedrock {
		t.Fatal("the resolved role must not alias the instance's sub-block")
	}

	// A role-level instance binding, base_url from the instance.
	c.Scanners.SkillScanner.LLM = LLMConfig{InstanceName: "acme-gw", Model: "gpt-5"}
	got := c.ResolveLLM("scanners.skill")
	if got.Provider != "openai" || got.BaseURL != "https://llm.acme.example/v1" {
		t.Fatalf("role instance: provider=%q base_url=%q", got.Provider, got.BaseURL)
	}

	// Explicit role values win over the instance.
	c.Scanners.SkillScanner.LLM = LLMConfig{Provider: "anthropic", BaseURL: "https://proxy.example", Model: "claude"}
	got = c.ResolveLLM("scanners.skill")
	if got.Provider != "anthropic" || got.BaseURL != "https://proxy.example" {
		t.Fatalf("explicit role lost to the instance: provider=%q base_url=%q", got.Provider, got.BaseURL)
	}
	c.LLM.Bedrock = &BedrockKeyConfig{Region: "eu-west-1"}
	if got := c.ResolveLLM(""); got.Bedrock.Region != "eu-west-1" {
		t.Fatalf("explicit bedrock sub-block lost to the instance: %+v", got.Bedrock)
	}

	// An instance_name that names no entry is left as is.
	c.LLM = LLMConfig{Provider: "custom", InstanceName: "missing", Model: "m"}
	if got := c.ResolveLLM(""); got.Provider != "custom" || got.Bedrock != nil {
		t.Fatalf("unmatched instance changed the role: %+v", got)
	}
}
