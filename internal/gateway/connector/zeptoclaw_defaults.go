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

package connector

// ZCProviderEntry describes how to reach an upstream LLM provider.
type ZCProviderEntry struct {
	UpstreamURL string
	AuthHeader  string
	AuthScheme  string
}

// defaultModelPrefixes maps model name prefixes to provider names.
// Used to infer the provider when no explicit X-ZC-Provider header is present.
var defaultModelPrefixes = []struct {
	prefix   string
	provider string
}{
	{"claude-", "anthropic"},
	{"gpt-", "openai"},
	{"o1-", "openai"},
	{"o3-", "openai"},
	{"o4-", "openai"},
	{"chatgpt-", "openai"},
	{"gemini-", "gemini"},
	{"command-", "cohere"},
	{"mistral-", "mistral"},
	{"llama-", "meta"},
	{"deepseek-", "deepseek"},
}

// InferProviderFromModel maps a model name to a provider name by checking
// for well-known prefixes. Returns "" if no match is found.
//
// Also handles "provider/model" format (e.g. "anthropic/claude-sonnet-4-20250514")
// where the provider is explicit before the slash.
func InferProviderFromModel(model string) string {
	// Check for explicit "provider/model" format.
	if idx := findSlash(model); idx >= 0 {
		return model[:idx]
	}

	for _, entry := range defaultModelPrefixes {
		if len(model) >= len(entry.prefix) && model[:len(entry.prefix)] == entry.prefix {
			return entry.provider
		}
	}
	return ""
}

// findSlash returns the index of the first '/' in s, or -1.
func findSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

// ZeptoClawDefaultProviders maps provider names to their default upstream
// URLs, auth headers, and auth schemes. Mirrored from ZeptoClaw's
// PROVIDER_REGISTRY in src/providers/registry.rs.
var ZeptoClawDefaultProviders = map[string]ZCProviderEntry{
	"openai":     {UpstreamURL: "https://api.openai.com/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"anthropic":  {UpstreamURL: "https://api.anthropic.com/v1", AuthHeader: "x-api-key", AuthScheme: ""},
	"openrouter": {UpstreamURL: "https://openrouter.ai/api/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"groq":       {UpstreamURL: "https://api.groq.com/openai/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"gemini":     {UpstreamURL: "https://generativelanguage.googleapis.com/v1beta/openai", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"ollama":     {UpstreamURL: "http://localhost:11434/v1", AuthHeader: "", AuthScheme: ""},
	"nvidia":     {UpstreamURL: "https://integrate.api.nvidia.com/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"deepseek":   {UpstreamURL: "https://api.deepseek.com/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"kimi":       {UpstreamURL: "https://api.moonshot.cn/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"azure":      {UpstreamURL: "", AuthHeader: "api-key", AuthScheme: ""},
	"bedrock":    {UpstreamURL: "", AuthHeader: "", AuthScheme: ""},
	"vllm":       {UpstreamURL: "http://localhost:8000/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"zhipu":      {UpstreamURL: "https://open.bigmodel.cn/api/paas/v4", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"xai":        {UpstreamURL: "https://api.x.ai/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"novita":     {UpstreamURL: "https://api.novita.ai/v3/openai", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"qianfan":    {UpstreamURL: "https://aip.baidubce.com/rpc/2.0", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"cohere":     {UpstreamURL: "https://api.cohere.com/v2", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"mistral":    {UpstreamURL: "https://api.mistral.ai/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
	"meta":       {UpstreamURL: "https://api.llama.com/v1", AuthHeader: "Authorization", AuthScheme: "Bearer"},
}
