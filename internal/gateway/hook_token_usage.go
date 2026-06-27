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
	"math"
	"strconv"
	"strings"
)

// hookTokenUsage is the result of inspecting a hook payload for
// LLM token-count fields. The struct is zero-valued when no usable
// counts were found; RecordHookTokenUsage already short-circuits on
// non-positive counts so callers can pass the zero struct as-is.
type hookTokenUsage struct {
	Model            string
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
}

type hookReportedCost struct {
	USD        float64
	Present    bool
	Cumulative bool
}

// extractHookPayloadReportedCost returns only an explicit upstream-reported
// USD amount. It deliberately does not apply model price tables: dashboards
// must distinguish an absent cost from a real reported zero.
func extractHookPayloadReportedCost(payload map[string]interface{}) hookReportedCost {
	if len(payload) == 0 {
		return hookReportedCost{}
	}
	candidates := []map[string]interface{}{payload}
	for _, key := range []string{"usage", "Usage", "cost", "billing", "result", "response"} {
		if nested := objectAt(payload, key); nested != nil {
			candidates = append(candidates, nested)
		}
	}
	for _, candidate := range candidates {
		if value, ok := firstFloat64Present(candidate,
			"total_cost_usd", "totalCostUsd", "totalCostUSD",
			"session_cost_usd", "sessionCostUsd", "sessionCostUSD",
			"usage.total_cost_usd",
		); ok && value >= 0 && !math.IsInf(value, 0) && !math.IsNaN(value) {
			return hookReportedCost{USD: value, Present: true, Cumulative: true}
		}
		if value, ok := firstFloat64Present(candidate,
			"cost_usd", "costUsd", "costUSD",
			"usage.cost_usd",
		); ok && value >= 0 && !math.IsInf(value, 0) && !math.IsNaN(value) {
			return hookReportedCost{USD: value, Present: true}
		}
	}
	return hookReportedCost{}
}

func firstFloat64Present(payload map[string]interface{}, keys ...string) (float64, bool) {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		switch value := raw.(type) {
		case float64:
			return value, true
		case float32:
			return float64(value), true
		case int:
			return float64(value), true
		case int64:
			return float64(value), true
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

// extractHookPayloadTokenUsage walks an agent-hook payload looking
// for common LLM token-count fields. Agents do not include token
// usage on every hook event; the extractor returns zero values for
// payloads that carry none, which the downstream RecordHookTokenUsage
// silently ignores.
//
// The field-name list intentionally mirrors extractOTLPLogTokenUsage
// in otel_ingest.go so the hook and OTLP surfaces converge on the
// same dashboard once both call sites exist:
//
//   - prompt-side aliases:  input_token_count, prompt_tokens,
//     gen_ai.usage.prompt_tokens, usage.prompt_tokens, …
//   - completion-side aliases: output_tokens, completion_tokens,
//     gen_ai.usage.completion_tokens, …
//   - total: total_tokens, gen_ai.usage.total_tokens, …
//
// The function also resolves the model name from the same priority
// chain extractOTLPLogTokenUsage uses (gen_ai.response.model →
// gen_ai.request.model → model). When all model fields are absent
// the caller's "unknown" fallback in RecordHookTokenUsage applies.
func extractHookPayloadTokenUsage(payload map[string]interface{}) hookTokenUsage {
	if len(payload) == 0 {
		return hookTokenUsage{}
	}
	var out hookTokenUsage

	// First, scan the top-level payload for a usage block. Many
	// CLI agent hooks attach a "usage" sibling alongside response
	// data; CL/CD style agents nest it under tool_response.usage.
	candidates := []map[string]interface{}{payload}
	for _, key := range []string{
		"usage", "Usage",
		"token_usage", "tokenUsage",
		"tool_response", "toolResponse",
		"tool_result", "toolResult",
		"result", "response",
		"last_assistant_message", "lastAssistantMessage",
		"completion", "Completion",
	} {
		if sub := objectAt(payload, key); sub != nil {
			candidates = append(candidates, sub)
			if nested := objectAt(sub, "usage"); nested != nil {
				candidates = append(candidates, nested)
			}
			if nested := objectAt(sub, "token_usage"); nested != nil {
				candidates = append(candidates, nested)
			}
		}
	}

	for _, src := range candidates {
		if out.PromptTokens == 0 {
			out.PromptTokens = firstInt64(src,
				"prompt_tokens", "promptTokens",
				"input_tokens", "inputTokens",
				"input_token_count", "prompt_token_count",
				"gen_ai.usage.prompt_tokens",
				"gen_ai.usage.input_tokens",
				"usage.prompt_tokens",
				"usage.input_tokens",
			)
		}
		if out.CompletionTokens == 0 {
			out.CompletionTokens = firstInt64(src,
				"completion_tokens", "completionTokens",
				"output_tokens", "outputTokens",
				"output_token_count", "completion_token_count",
				"gen_ai.usage.completion_tokens",
				"gen_ai.usage.output_tokens",
				"usage.completion_tokens",
				"usage.output_tokens",
			)
		}
		if out.TotalTokens == 0 {
			out.TotalTokens = firstInt64(src,
				"total_tokens", "totalTokens",
				"total_token_count",
				"gen_ai.usage.total_tokens",
				"usage.total_tokens",
			)
		}
		if out.Model == "" {
			out.Model = firstHookTokenString(src,
				"gen_ai.response.model",
				"gen_ai.request.model",
				"response.model",
				"request.model",
				"model",
				"model_id",
				"modelId",
			)
		}
	}

	// Derive total from prompt+completion if the agent did not
	// emit a pre-summed counter. Some Codex / Anthropic events
	// only report the two halves.
	if out.TotalTokens == 0 && (out.PromptTokens > 0 || out.CompletionTokens > 0) {
		out.TotalTokens = out.PromptTokens + out.CompletionTokens
	}
	return out
}

// firstInt64 returns the first numeric value found under the given
// keys, coercing JSON-decoded float64s and string-encoded numbers
// into int64. Returns 0 when no key carries a usable value.
func firstInt64(payload map[string]interface{}, keys ...string) int64 {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		switch v := raw.(type) {
		case float64:
			if v > 0 {
				return int64(v)
			}
		case int64:
			if v > 0 {
				return v
			}
		case int:
			if v > 0 {
				return int64(v)
			}
		case json_Number:
			if n, err := v.Int64(); err == nil && n > 0 {
				return n
			}
		case string:
			s := strings.TrimSpace(v)
			if s == "" {
				continue
			}
			// Parse small unsigned integers without bringing
			// strconv into the hot path. Use a tight loop so a
			// stray prefix/suffix (e.g. "1.0k") yields 0 instead
			// of a misleading large number.
			n, ok := parseIntStrict(s)
			if ok && n > 0 {
				return n
			}
		}
	}
	return 0
}

// firstHookTokenString returns the first string value under the
// given keys. Used to resolve the model name for label-attribution.
func firstHookTokenString(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// json_Number is a re-export of json.Number that we accept in
// firstInt64. We avoid a direct import of encoding/json here so this
// helper stays cheap to test without round-tripping through the
// decoder; callers that already have a json.Number can pass it
// through with a type assertion.
type json_Number = interface {
	Int64() (int64, error)
}

// parseIntStrict parses a non-negative integer from s, requiring
// every byte to be ASCII 0-9. Any other byte (sign, decimal point,
// scientific notation) returns false so the caller falls back to 0.
func parseIntStrict(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		if n > (1<<62-int64(c-'0'))/10 {
			// Overflow guard: anything past 9e17 is not a real
			// token count; treat as parse failure.
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}
