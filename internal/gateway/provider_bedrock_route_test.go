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
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/maximhq/bifrost/core/schemas"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const lunaProfile = "us.openai.gpt-5.6-luna"

// routesToMantle answers what Bifrost's Bedrock provider asks before a chat
// call: an OpenAI-family model (after key alias resolution) goes to Mantle.
func routesToMantle(acc *tenantAccount, model string) bool {
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	if ac := acc.keys[0].Aliases.ResolveConfig(model); ac != nil {
		ctx.SetValue(schemas.BifrostContextKeyResolvedAlias, &schemas.ResolvedAlias{Key: model, Config: ac})
		model = ac.ModelID
	}
	return schemas.IsOpenAIModelFamily(ctx, model)
}

// GAP-2639: the hook judge on GPT-5.6 Luna went to Bedrock Mantle (404 for
// the us. profile id, 502 where the endpoint resolves to a private address).
func TestBedrockOpenAIProfileUsesConverse(t *testing.T) {
	bedrock := &config.BedrockKeyConfig{Region: "us-east-1", AuthMode: "instance_role"}
	acc := newTenantAccount(schemas.Bedrock, "", "k", "", lunaProfile, tlsOverrides{}, bedrock, nil, nil, nil)
	if routesToMantle(acc, lunaProfile) {
		t.Fatalf("%s still routes to Bedrock Mantle; want Converse", lunaProfile)
	}
	if err := acc.keys[0].Aliases.Validate(schemas.Bedrock); err != nil {
		t.Fatalf("aliases do not validate: %v", err)
	}
	if got := acc.keys[0].Aliases.Resolve(lunaProfile); got != lunaProfile {
		t.Fatalf("wire model = %q, want %q", got, lunaProfile)
	}

	// Without a bedrock sub-block (api_key auth) the route is the same.
	acc = newTenantAccount(schemas.Bedrock, "ABSKx", "k", "", lunaProfile, tlsOverrides{}, nil, nil, nil, nil)
	if routesToMantle(acc, lunaProfile) {
		t.Fatal("api_key Bedrock tenant still routes Luna to Mantle")
	}

	// A deployment alias whose target is the profile id is routed too.
	bedrock = &config.BedrockKeyConfig{Region: "us-east-1", DeploymentAliases: map[string]string{"judge": lunaProfile}}
	acc = newTenantAccount(schemas.Bedrock, "", "k", "", "judge", tlsOverrides{}, bedrock, nil, nil, nil)
	if routesToMantle(acc, "judge") {
		t.Fatal("deployment alias to the Luna profile still routes to Mantle")
	}

	// Hard negatives: Claude stays on Converse with no extra alias, the bare
	// Mantle-only id keeps Bifrost's Mantle route, other providers are untouched.
	const haiku = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
	acc = newTenantAccount(schemas.Bedrock, "", "k", "", haiku, tlsOverrides{}, &config.BedrockKeyConfig{Region: "us-east-1"}, nil, nil, nil)
	if len(acc.keys[0].Aliases) != 0 || routesToMantle(acc, haiku) {
		t.Fatalf("Claude profile got aliases %v", acc.keys[0].Aliases)
	}
	acc = newTenantAccount(schemas.Bedrock, "", "k", "", "openai.gpt-5.6-luna", tlsOverrides{}, &config.BedrockKeyConfig{Region: "us-east-1"}, nil, nil, nil)
	if !routesToMantle(acc, "openai.gpt-5.6-luna") {
		t.Fatal("bare openai.* id must keep the Mantle route (Converse refuses it on demand)")
	}
	acc = newTenantAccount(schemas.OpenAI, "sk-x", "k", "", "gpt-5.5", tlsOverrides{}, nil, nil, nil, nil)
	if len(acc.keys[0].Aliases) != 0 {
		t.Fatalf("OpenAI tenant got aliases %v", acc.keys[0].Aliases)
	}
}

func TestBedrockConverseAliasIDIsPerModel(t *testing.T) {
	a := bedrockConverseAliasID(schemas.Bedrock, lunaProfile)
	if a == "" || a == bedrockConverseAliasID(schemas.Bedrock, "eu.openai.gpt-5.6-luna") {
		t.Fatalf("alias ids not distinct per model: %q", a)
	}
	for _, c := range []struct {
		p schemas.ModelProvider
		m string
	}{{schemas.OpenAI, lunaProfile}, {schemas.Bedrock, "us.anthropic.claude-haiku-4-5-20251001-v1:0"}, {schemas.Bedrock, "openai.gpt-5.6-luna"}} {
		if got := bedrockConverseAliasID(c.p, c.m); got != "" {
			t.Errorf("bedrockConverseAliasID(%s, %s) = %q, want empty", c.p, c.m, got)
		}
	}
}

func TestJudgeChatRequestLeavesOutRefusedTemperature(t *testing.T) {
	for model, wantTemp := range map[string]bool{
		"bedrock/" + lunaProfile: false,
		"openai/gpt-5.5":         false,
		"openai/o3-mini":         false,
		"bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0": true,
		"openai/gpt-4o":                   true,
		"ollama/qwen3:8b":                 true,
		"bedrock/openai.gpt-oss-120b-1:0": true,
	} {
		j := &LLMJudge{cfg: &config.JudgeConfig{}, model: model, providerName: strings.SplitN(model, "/", 2)[0]}
		req := j.judgeChatRequest([]ChatMessage{{Role: "user", Content: "x"}}, 64, "injection")
		if got := req.Temperature != nil; got != wantTemp {
			t.Errorf("%s: temperature set = %v, want %v", model, got, wantTemp)
		}
		if wantTemp && *req.Temperature != 0 {
			t.Errorf("%s: temperature = %v, want 0", model, *req.Temperature)
		}
	}
}

// TestBifrostE2E_LiveBedrockLunaJudge sends the judge's own request shape to
// GPT-5.6 Luna on Bedrock. It needs a Bedrock API key in
// BIFROST_API_KEY and is skipped otherwise.
func TestBifrostE2E_LiveBedrockLunaJudge(t *testing.T) {
	key := os.Getenv("BIFROST_API_KEY")
	if key == "" {
		t.Skip("BIFROST_API_KEY not set: skipping live Bedrock Luna judge test")
	}
	llm := &config.LLMConfig{Model: "bedrock/" + lunaProfile, APIKey: key, Bedrock: &config.BedrockKeyConfig{Region: "us-east-1"}}
	p, err := NewProviderForLLMConfig(llm, nil)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	j := &LLMJudge{cfg: &config.JudgeConfig{}, model: llm.Model, providerName: "bedrock", provider: p}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req := j.judgeChatRequest([]ChatMessage{
		{Role: "system", Content: "You classify a tool call for prompt injection. Answer with the schema."},
		{Role: "user", Content: "Tool call: run `echo hello`."},
	}, 512, "tool_injection")
	resp, err := p.ChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("Luna judge call failed: %v", err)
	}
	if len(resp.Choices) == 0 || resp.Choices[0].Message == nil {
		t.Fatalf("empty response: %+v", resp)
	}
	t.Logf("Luna judge answered: %.200s", resp.Choices[0].Message.Content)
}
