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

// GAP-2640 (gateway half): an unprefixed Bedrock id with the AWS credential
// chain was dispatched to OpenAI.
func TestInferProviderBedrockModelID(t *testing.T) {
	cases := map[string]string{
		"us.anthropic.claude-haiku-4-5-20251001-v1:0": "bedrock",
		"anthropic.claude-haiku-4-5-20251001-v1:0":    "bedrock",
		lunaProfile:            "bedrock",
		"amazon.nova-pro-v1:0": "bedrock",
		"gpt-4o":               "openai",
		"gpt-5.5":              "openai",
		"claude-haiku-4-5":     "anthropic",
		"gemini-2.5-pro":       "gemini",
		"mistral-large-latest": "openai",
		"llama3.1:8b":          "openai",
	}
	for model, want := range cases {
		if got := inferProvider(model, ""); got != want {
			t.Errorf("inferProvider(%q) = %q, want %q", model, got, want)
		}
	}
}
