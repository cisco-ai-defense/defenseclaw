// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// ParseBody reads the usage out of one complete non-stream response body.
// It never fails: a body without a usage block, or one that is not JSON,
// yields an empty Usage (absent counts, not zeros).
func ParseBody(f APIFamily, body []byte) Usage {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != 0x7b {
		return Usage{}
	}
	var u Usage
	if len(body) > maxFullDecodeBytes && f != FamilyOllama && f != FamilyOther {
		// A huge body is not decoded whole: its usage object comes last.
		u = usageFromTail(f, body[len(body)-maxTailBytes:])
		if u.Has != 0 {
			u.Source = SourceProvider
		}
		u.seal()
		return u
	}
	switch f {
	case FamilyMessages, FamilyInvoke:
		u = parseAnthropicDoc(body)
	case FamilyChat:
		u = parseChatDoc(body)
	case FamilyResponses:
		u = parseResponsesDoc(body)
	case FamilyConverse:
		u = parseConverseDoc(body)
	case FamilyGemini:
		u = parseGeminiDoc(body)
	case FamilyOllama:
		u = parseOllamaDoc(body)
	default:
		return Usage{}
	}
	if u.Has != 0 {
		u.Source = SourceProvider
	}
	u.seal()
	return u
}

// ParseBedrockHeaders reads the token counts Bedrock InvokeModel puts in its
// response headers. It is the fallback for the invoke family, whose body
// format belongs to the model.
func ParseBedrockHeaders(h http.Header) Usage {
	var u Usage
	if h == nil {
		return u
	}
	in := headerCount(h.Get("X-Amzn-Bedrock-Input-Token-Count"))
	out := headerCount(h.Get("X-Amzn-Bedrock-Output-Token-Count"))
	u.set(HasInput, &u.Input, in)
	u.set(HasOutput, &u.Output, out)
	if u.Has != 0 {
		u.Source = SourceHeader
	}
	return u
}

func headerCount(s string) optInt {
	if s == "" {
		return optInt{}
	}
	var o optInt
	_ = o.UnmarshalJSON([]byte(s))
	return o
}

// ---- Anthropic Messages -------------------------------------------------

type anthropicUsage struct {
	ServiceTier   string `json:"service_tier"`
	CacheCreation *struct {
		Ephemeral1h optInt `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	ServerToolUse *struct {
		WebSearch optInt `json:"web_search_requests"`
		WebFetch  optInt `json:"web_fetch_requests"`
	} `json:"server_tool_use"`
	InputTokens         optInt `json:"input_tokens"`
	OutputTokens        optInt `json:"output_tokens"`
	CacheCreationTokens optInt `json:"cache_creation_input_tokens"`
	CacheReadTokens     optInt `json:"cache_read_input_tokens"`
}

// apply folds an Anthropic usage block into u. Anthropic reports uncached
// input only, so Input is the sum of the three input counters.
func (a anthropicUsage) apply(u *Usage) {
	if a.InputTokens.ok || a.CacheCreationTokens.ok || a.CacheReadTokens.ok {
		total := addOpt(addOpt(a.InputTokens, a.CacheCreationTokens), a.CacheReadTokens)
		u.set(HasInput, &u.Input, total)
		u.set(HasCacheRead, &u.CacheRead, a.CacheReadTokens)
		u.set(HasCacheCreation, &u.CacheCreation, a.CacheCreationTokens)
	}
	u.set(HasOutput, &u.Output, a.OutputTokens)
	a.markPartial(u)
}

func (a anthropicUsage) markPartial(u *Usage) {
	switch {
	case a.ServiceTier != "" && a.ServiceTier != "standard":
		u.Partial = "service_tier:" + a.ServiceTier
	case a.CacheCreation != nil && a.CacheCreation.Ephemeral1h.ok && a.CacheCreation.Ephemeral1h.v > 0:
		u.Partial = "cache_ttl_1h"
	case a.ServerToolUse != nil && (a.ServerToolUse.WebSearch.v > 0 || a.ServerToolUse.WebFetch.v > 0):
		u.Partial = "server_tools"
	}
}

func parseAnthropicDoc(body []byte) Usage {
	var doc struct {
		Model string          `json:"model"`
		Usage *anthropicUsage `json:"usage"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	if doc.Usage != nil {
		doc.Usage.apply(&u)
	}
	u.ResponseModel = doc.Model
	return u
}

// ---- OpenAI Chat Completions --------------------------------------------

type chatUsage struct {
	PromptTokens     optInt `json:"prompt_tokens"`
	CompletionTokens optInt `json:"completion_tokens"`
	PromptDetails    *struct {
		CachedTokens optInt `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionDetails *struct {
		ReasoningTokens optInt `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func (c chatUsage) apply(u *Usage) {
	u.set(HasInput, &u.Input, c.PromptTokens)
	u.set(HasOutput, &u.Output, c.CompletionTokens)
	if c.PromptDetails != nil {
		u.set(HasCacheRead, &u.CacheRead, c.PromptDetails.CachedTokens)
	}
	if c.CompletionDetails != nil {
		u.set(HasReasoning, &u.Reasoning, c.CompletionDetails.ReasoningTokens)
	}
}

func parseChatDoc(body []byte) Usage {
	var doc struct {
		Model       string     `json:"model"`
		ServiceTier string     `json:"service_tier"`
		Usage       *chatUsage `json:"usage"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	if doc.Usage != nil {
		doc.Usage.apply(&u)
	}
	u.ResponseModel = doc.Model
	openAITierPartial(&u, doc.ServiceTier)
	return u
}

// ---- OpenAI Responses ---------------------------------------------------

type responsesUsage struct {
	InputTokens  optInt `json:"input_tokens"`
	OutputTokens optInt `json:"output_tokens"`
	InputDetails *struct {
		CachedTokens optInt `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	OutputDetails *struct {
		ReasoningTokens optInt `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func (r responsesUsage) apply(u *Usage) {
	u.set(HasInput, &u.Input, r.InputTokens)
	u.set(HasOutput, &u.Output, r.OutputTokens)
	if r.InputDetails != nil {
		u.set(HasCacheRead, &u.CacheRead, r.InputDetails.CachedTokens)
	}
	if r.OutputDetails != nil {
		u.set(HasReasoning, &u.Reasoning, r.OutputDetails.ReasoningTokens)
	}
}

func parseResponsesDoc(body []byte) Usage {
	var doc struct {
		Model       string          `json:"model"`
		ServiceTier string          `json:"service_tier"`
		Usage       *responsesUsage `json:"usage"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	if doc.Usage != nil {
		doc.Usage.apply(&u)
	}
	u.ResponseModel = doc.Model
	openAITierPartial(&u, doc.ServiceTier)
	return u
}

// ---- Bedrock Converse ---------------------------------------------------

type converseUsage struct {
	InputTokens      optInt `json:"inputTokens"`
	OutputTokens     optInt `json:"outputTokens"`
	CacheReadTokens  optInt `json:"cacheReadInputTokens"`
	CacheWriteTokens optInt `json:"cacheWriteInputTokens"`
}

// apply: Converse inputTokens excludes the cache counters, so Input is the sum.
func (c converseUsage) apply(u *Usage) {
	if c.InputTokens.ok || c.CacheReadTokens.ok || c.CacheWriteTokens.ok {
		total := addOpt(addOpt(c.InputTokens, c.CacheReadTokens), c.CacheWriteTokens)
		u.set(HasInput, &u.Input, total)
		u.set(HasCacheRead, &u.CacheRead, c.CacheReadTokens)
		u.set(HasCacheCreation, &u.CacheCreation, c.CacheWriteTokens)
	}
	u.set(HasOutput, &u.Output, c.OutputTokens)
}

func parseConverseDoc(body []byte) Usage {
	var doc struct {
		Usage *converseUsage `json:"usage"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	if doc.Usage != nil {
		doc.Usage.apply(&u)
	}
	return u
}

// ---- Gemini -------------------------------------------------------------

type geminiUsage struct {
	ToolUsePrompt    optInt `json:"toolUsePromptTokenCount"`
	PromptTokens     optInt `json:"promptTokenCount"`
	CandidatesTokens optInt `json:"candidatesTokenCount"`
	CachedTokens     optInt `json:"cachedContentTokenCount"`
	ThoughtsTokens   optInt `json:"thoughtsTokenCount"`
}

// apply: promptTokenCount already includes cachedContentTokenCount;
// candidatesTokenCount excludes thoughts, which are billed as output.
func (g geminiUsage) apply(u *Usage) {
	// toolUsePromptTokenCount is billed as input but is not part of promptTokenCount.
	if g.PromptTokens.ok || g.ToolUsePrompt.ok {
		u.set(HasInput, &u.Input, addOpt(g.PromptTokens, g.ToolUsePrompt))
	}
	u.set(HasCacheRead, &u.CacheRead, g.CachedTokens)
	if g.PromptTokens.ok && g.PromptTokens.v > geminiLongContext {
		u.Partial = "long_context"
	}
	if g.CandidatesTokens.ok || g.ThoughtsTokens.ok {
		u.set(HasOutput, &u.Output, addOpt(g.CandidatesTokens, g.ThoughtsTokens))
	}
	u.set(HasReasoning, &u.Reasoning, g.ThoughtsTokens)
}

func parseGeminiDoc(body []byte) Usage {
	var doc struct {
		ModelVersion  string       `json:"modelVersion"`
		UsageMetadata *geminiUsage `json:"usageMetadata"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	if doc.UsageMetadata != nil {
		doc.UsageMetadata.apply(&u)
	}
	u.ResponseModel = doc.ModelVersion
	return u
}

// ---- Ollama native ------------------------------------------------------

func parseOllamaDoc(body []byte) Usage {
	var doc struct {
		Model           string `json:"model"`
		PromptEvalCount optInt `json:"prompt_eval_count"`
		EvalCount       optInt `json:"eval_count"`
	}
	_ = json.Unmarshal(body, &doc)
	var u Usage
	u.set(HasInput, &u.Input, doc.PromptEvalCount)
	u.set(HasOutput, &u.Output, doc.EvalCount)
	u.ResponseModel = doc.Model
	return u
}

// geminiLongContext is the prompt size above which Gemini Pro models bill a
// higher tier the flat price table does not model.
const geminiLongContext = 200_000

func openAITierPartial(u *Usage, tier string) {
	switch tier {
	case "flex", "priority", "scale":
		u.Partial = "service_tier:" + tier
	}
}

// maxFullDecodeBytes is the body size above which ParseBody reads only the
// tail of the body.
const maxFullDecodeBytes = 256 << 10
