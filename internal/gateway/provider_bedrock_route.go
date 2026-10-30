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
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

// bedrockOpenAIProfilePattern matches an OpenAI-family model behind a Bedrock
// cross-region inference profile ("us.openai.gpt-5.6-luna").
var bedrockOpenAIProfilePattern = regexp.MustCompile(`^(?:us|eu|apac|jp|au|ca|global|us-gov)\.openai\.[a-z0-9]`)

// isBedrockOpenAIProfileID reports whether model is an OpenAI-family model
// named through a Bedrock cross-region inference profile.
func isBedrockOpenAIProfileID(model string) bool {
	return bedrockOpenAIProfilePattern.MatchString(strings.ToLower(strings.TrimSpace(model)))
}

// bedrockConverseFamily is the alias model_family that keeps an OpenAI-family
// inference profile on the Bedrock Converse API (GAP-2639).
//
// Bifrost sends every OpenAI-family Bedrock model ("gpt-*") to the Bedrock
// Mantle endpoint (bedrock-mantle.<region>.api.aws). That broke the hook
// judge on GPT-5.6 Luna in two ways: Mantle serves the model only as
// "openai.gpt-5.6-luna" and answers 404 for the "us." profile id the
// configuration names, and Bifrost's Mantle client refuses to dial a private
// address, so on a network whose Bedrock interface endpoints resolve to
// private addresses every call failed with "Bedrock returned 502: failed to
// execute HTTP request to provider API". Converse on bedrock-runtime serves
// the profile id, signs with the "bedrock" service like every other Bedrock
// model, and is the route the scanners (LiteLLM) and the agents already use.
//
// Bifrost routes by the family of the resolved key alias, so an identity
// alias with a non-OpenAI family selects Converse. Gemma is used because the
// Bedrock provider has no Gemma-specific branch: the request is shaped as a
// plain Converse call. TestBedrockOpenAIProfileUsesConverse pins this choice
// so a Bifrost upgrade that changes it fails a test, not the judge.
const bedrockConverseFamily = schemas.ModelFamilyGemma

// withBedrockConverseRoute returns aliases with every OpenAI-family inference
// profile target routed to Converse, adding an identity alias for model when
// no alias names it. Aliases that already set a family are kept as written.
func withBedrockConverseRoute(aliases schemas.KeyAliases, model string) schemas.KeyAliases {
	for from, ac := range aliases {
		if ac.ModelFamily == nil && isBedrockOpenAIProfileID(ac.ModelID) {
			family := bedrockConverseFamily
			ac.ModelFamily = &family
			aliases[from] = ac
		}
	}
	model = strings.TrimSpace(model)
	if !isBedrockOpenAIProfileID(model) || aliasMapContains(aliases, model) {
		return aliases
	}
	if aliases == nil {
		aliases = make(schemas.KeyAliases, 1)
	}
	family := bedrockConverseFamily
	aliases[model] = schemas.AliasConfig{ModelID: model, ModelFamily: &family}
	return aliases
}

// bedrockConverseAliasID gives the tenant cache key a per-model identity when
// withBedrockConverseRoute adds an identity alias for model, so a client
// built for one model is never reused for another one without that alias.
func bedrockConverseAliasID(providerKey schemas.ModelProvider, model string) string {
	model = strings.TrimSpace(model)
	if providerKey != schemas.Bedrock || !isBedrockOpenAIProfileID(model) {
		return ""
	}
	sum := sha256.Sum256([]byte(model))
	return "bedrock-converse-model:sha256:" + hex.EncodeToString(sum[:8])
}

// openAIReasoningModelPattern matches the OpenAI reasoning models (GPT-5 and
// the o-series) under any provider prefix or Bedrock profile:
// "openai/gpt-5.5", "bedrock/us.openai.gpt-5.6-luna", "o3-mini".
var openAIReasoningModelPattern = regexp.MustCompile(`(?:^|[/.])(?:gpt-5|o[1-9](?:-|$))`)

// modelRefusesTemperature reports whether model accepts only its default
// sampling temperature. OpenAI's reasoning models answer 400 to any other
// value ("Unsupported value: 'temperature' does not support 0"), and Bedrock
// Converse refuses the field for them outright ("This model doesn't support
// the temperature field"), so the judge leaves it out for these models
// (GAP-2639). The Python side drops it the same way (litellm.drop_params).
func modelRefusesTemperature(model string) bool {
	return openAIReasoningModelPattern.MatchString(strings.ToLower(strings.TrimSpace(model)))
}
