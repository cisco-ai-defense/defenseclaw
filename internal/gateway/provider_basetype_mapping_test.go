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

import "testing"

// cliBaseProviderTypes mirrors _ALLOWED_BASE_PROVIDER_TYPES in
// cli/defenseclaw/commands/cmd_setup_provider.py — the base_provider_type
// values the `defenseclaw setup provider add` wizard offers operators.
// This is the WS2 regression net: every shape the CLI lets an operator
// configure MUST resolve to a Bifrost provider, otherwise the custom
// provider silently fails at gateway resolution (the exact misroute the
// custom-provider validation pass exists to surface).
var cliBaseProviderTypes = []string{
	"openai",
	"anthropic",
	"bedrock",
	"azure",
	"vertex_ai",
	"gemini",
	"gemini-openai",
	"groq",
	"mistral",
	"cohere",
	"deepseek",
	"xai",
	"fireworks_ai",
	"perplexity",
	"huggingface",
	"replicate",
	"openrouter",
	"together_ai",
	"cerebras",
	"ollama",
	"vllm",
	"lm_studio",
}

func TestEveryCLIBaseProviderTypeMapsToBifrost(t *testing.T) {
	for _, base := range cliBaseProviderTypes {
		if _, err := mapProviderKey(base); err != nil {
			t.Errorf("CLI base_provider_type %q does not map to a Bifrost provider (mapProviderKey error: %v); "+
				"the setup wizard offers it but the gateway would fail to resolve it", base, err)
		}
	}
}
