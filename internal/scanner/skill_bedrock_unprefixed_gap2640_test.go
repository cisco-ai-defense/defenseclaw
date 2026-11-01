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

package scanner

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2640: an admin llm.model without the bedrock/ prefix reached the
// scanners unprefixed, so LiteLLM did not sign for Bedrock ("Authentication
// failed") and the MCP analyzer did not allow the Bedrock host.
func TestLiteLLMModelUnprefixedBedrockID(t *testing.T) {
	cases := []struct {
		llm  config.LLMConfig
		want string
	}{
		{config.LLMConfig{Model: "us.anthropic.claude-haiku-4-5-20251001-v1:0"}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Model: "us.openai.gpt-5.6-luna"}, "bedrock/us.openai.gpt-5.6-luna"},
		{config.LLMConfig{Model: "anthropic.claude-haiku-4-5-20251001-v1:0", Bedrock: &config.BedrockKeyConfig{InferenceProfile: "us."}}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		{config.LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"}, "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"},
		// Hard negatives: other providers' ids stay as written.
		{config.LLMConfig{Model: "gpt-4o"}, "gpt-4o"},
		{config.LLMConfig{Model: "claude-haiku-4-5"}, "claude-haiku-4-5"},
		{config.LLMConfig{Model: "claude-haiku-4-5", Provider: "anthropic"}, "anthropic/claude-haiku-4-5"},
		{config.LLMConfig{Model: "llama3.1:8b", Provider: "ollama"}, "ollama/llama3.1:8b"},
	}
	for _, c := range cases {
		if got := liteLLMModel(c.llm); got != c.want {
			t.Errorf("liteLLMModel(%q) = %q, want %q", c.llm.Model, got, c.want)
		}
	}
	if p := (config.LLMConfig{Model: "us.anthropic.claude-haiku-4-5-20251001-v1:0"}).ProviderPrefix(); p != "bedrock" {
		t.Errorf("ProviderPrefix = %q, want bedrock", p)
	}
	if p := (config.LLMConfig{Model: "gpt-4o"}).ProviderPrefix(); p != "" {
		t.Errorf("ProviderPrefix(gpt-4o) = %q, want empty", p)
	}
}
