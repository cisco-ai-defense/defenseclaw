// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// GAP-0172: a managed config whose llm.model is a nickname or no model id
// at all was applied without a word, and every judge call then fell back.
// The lifecycle names the bad id and the expected form; real ids, prefixed
// models of other providers and custom-provider instances stay silent.
func TestLLMModelIDProblemNamesTheBadModelID(t *testing.T) {
	for _, tc := range []struct {
		name string
		llm  LLMConfig
		want []string
	}{
		{"nickname", LLMConfig{Model: "luna"}, []string{`llm.model "luna" names no provider`, "short name of us.openai.gpt-5.6-luna", "provider/model"}},
		{"not a model", LLMConfig{Model: "not-a-model"}, []string{`llm.model "not-a-model"`, "falls back to the rules"}},
		{"bedrock provider short name", LLMConfig{Model: "haiku-4.5", Provider: "bedrock"}, []string{"is not an Amazon Bedrock model id", "us.anthropic.claude-haiku-4-5-20251001-v1:0"}},
		{"bedrock prefix nonsense", LLMConfig{Model: "bedrock/sonnet-latest"}, []string{`"bedrock/sonnet-latest" is not an Amazon Bedrock model id`}},
	} {
		got := tc.llm.ModelIDProblem("llm.model")
		for _, want := range tc.want {
			if !strings.Contains(got, want) {
				t.Fatalf("%s: %q does not contain %q", tc.name, got, want)
			}
		}
	}
	for name, llm := range map[string]LLMConfig{
		"empty":                {},
		"bedrock id":           {Model: "us.openai.gpt-5.6-luna"},
		"prefixed bedrock id":  {Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		"amazon-bedrock id":    {Model: "amazon-bedrock/anthropic.claude-haiku-4-5-20251001-v1:0"},
		"bedrock arn":          {Model: "arn:aws:bedrock:us-east-1:000000000000:inference-profile/x", Provider: "bedrock"},
		"prefixed bedrock arn": {Model: "bedrock/arn:aws:bedrock:us-east-1:000000000000:inference-profile/x"},
		"bedrock alias":        {Model: "judge", Provider: "bedrock", Bedrock: &BedrockKeyConfig{DeploymentAliases: map[string]string{"judge": "x"}}},
		"anthropic prefixed":   {Model: "anthropic/claude-sonnet-5-5"},
		"unprefixed claude":    {Model: "claude-haiku-4-5"},
		"unprefixed gemini":    {Model: "gemini-2.5-pro"},
		"unprefixed openai":    {Model: "gpt-4o"},
		"openai o-series":      {Model: "o4-mini"},
		"other provider":       {Model: "mymodel", Provider: "ollama"},
		"ollama prefixed":      {Model: "ollama/llama3"},
		"custom instance":      {Model: "luna", InstanceName: "corp"},
	} {
		if got := llm.ModelIDProblem("llm.model"); got != "" {
			t.Fatalf("%s: unexpected warning %q", name, got)
		}
	}
}
