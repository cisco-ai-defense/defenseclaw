// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/configs"
)

func TestLLMJudgeAllowsEmptyAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		llm       config.LLMConfig
		providers *configs.ProvidersConfig
		want      bool
	}{
		{
			name: "local Ollama",
			llm:  config.LLMConfig{Model: "ollama/gemma4:12b-mlx"},
			want: true,
		},
		{
			name: "direct Bedrock model",
			llm:  config.LLMConfig{Model: "bedrock/google.gemma-3-12b-it"},
			want: true,
		},
		{
			name: "explicit Bedrock provider",
			llm: config.LLMConfig{
				Provider: "bedrock",
				Model:    "google.gemma-3-12b-it",
			},
			want: true,
		},
		{
			name: "Bedrock overlay instance",
			llm: config.LLMConfig{
				Model:        "judge-instance/google.gemma-3-12b-it",
				InstanceName: "judge-instance",
			},
			providers: &configs.ProvidersConfig{Providers: []configs.Provider{{
				Name:             "judge-instance",
				BaseProviderType: "bedrock",
			}}},
			want: true,
		},
		{
			name: "hosted OpenAI still requires a key",
			llm:  config.LLMConfig{Model: "openai/gpt-5"},
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := llmJudgeAllowsEmptyAPIKey(test.llm, test.providers); got != test.want {
				t.Fatalf("llmJudgeAllowsEmptyAPIKey() = %t, want %t", got, test.want)
			}
		})
	}
}
