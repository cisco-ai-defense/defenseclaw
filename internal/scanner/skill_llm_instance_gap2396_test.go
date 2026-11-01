// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2396: the watcher's skill scan of a role bound to a keyless Bedrock
// llm_providers.custom instance (provider "custom") runs the LLM analyzer
// with the instance's family, region and inference profile.
func TestGAP2396SkillScannerJudgesWithTheCustomBedrockInstance(t *testing.T) {
	root := &config.Config{
		LLM: config.LLMConfig{Provider: "custom", InstanceName: "acme-bedrock-prod", Model: "anthropic.claude-haiku-4-5-20251001-v1:0"},
		LLMProviders: config.LLMProvidersConfig{Custom: []config.LLMCustomProvider{{
			Name: "acme-bedrock-prod", BaseProviderType: "bedrock",
			Bedrock: &config.BedrockKeyConfig{Region: "us-east-1", AuthMode: "instance_role", InferenceProfile: "us."},
		}}},
	}
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{UseLLM: true}, root.ResolveLLM("scanners.skill"), config.CiscoAIDefenseConfig{})
	args := strings.Join(ss.buildArgs("/tmp/skill", "quiet"), " ")
	if !strings.Contains(args, "--use-llm") {
		t.Fatalf("LLM analyzer skipped for the custom Bedrock instance: %s", args)
	}
	env := strings.Join(ss.scanEnv(), "\n")
	for _, want := range []string{"SKILL_SCANNER_LLM_MODEL=bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", "AWS_REGION=us-east-1"} {
		if !strings.Contains(env, want) {
			t.Fatalf("scanner env missing %s", want)
		}
	}
	if strings.Contains(env, "custom/") {
		t.Fatal("scanner env still routes custom/<model>")
	}

	plugin := &PluginScanner{LLM: root.ResolveLLM("scanners.plugin")}
	if got := liteLLMModel(plugin.LLM); got != "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0" {
		t.Fatalf("plugin judge model = %q", got)
	}
}

func TestGAP2396BedrockInferenceProfileOnlyWhereTheGatewayAppliesIt(t *testing.T) {
	b := &config.BedrockKeyConfig{InferenceProfile: "us."}
	cases := []struct {
		llm  config.LLMConfig
		want string
	}{
		{config.LLMConfig{Provider: "bedrock", Model: "anthropic.claude-haiku-4-5-20251001-v1:0", Bedrock: b}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Model: "bedrock/anthropic.claude-haiku-4-5-20251001-v1:0", Bedrock: b}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Provider: "bedrock", Model: "us.anthropic.claude-haiku-4-5-20251001-v1:0", Bedrock: b}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Provider: "bedrock", Model: "anthropic.claude-haiku-4-5-20251001-v1:0"}, "bedrock/anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Provider: "bedrock", Model: "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/x", Bedrock: b}, "arn:aws:bedrock:us-east-1:111122223333:application-inference-profile/x"},
		{config.LLMConfig{Provider: "openai", Model: "gpt-5", Bedrock: b}, "openai/gpt-5"},
	}
	for _, tc := range cases {
		if got := liteLLMModel(tc.llm); got != tc.want {
			t.Fatalf("liteLLMModel(%+v) = %q, want %q", tc.llm, got, tc.want)
		}
	}
}
