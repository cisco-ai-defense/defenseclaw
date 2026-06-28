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
	"testing"
)

func TestExtractHookPayloadTokenUsage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   map[string]interface{}
		want hookTokenUsage
	}{
		{
			name: "top-level openai usage",
			in: map[string]interface{}{
				"usage": map[string]interface{}{
					"prompt_tokens":     float64(100),
					"completion_tokens": float64(50),
					"total_tokens":      float64(150),
				},
				"model": "gpt-4o-mini",
			},
			want: hookTokenUsage{
				Model:            "gpt-4o-mini",
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
			},
		},
		{
			name: "anthropic style nested response.usage",
			in: map[string]interface{}{
				"tool_response": map[string]interface{}{
					"model": "claude-sonnet-4",
					"usage": map[string]interface{}{
						"input_tokens":  float64(200),
						"output_tokens": float64(80),
					},
				},
			},
			want: hookTokenUsage{
				Model:            "claude-sonnet-4",
				PromptTokens:     200,
				CompletionTokens: 80,
				TotalTokens:      280, // derived
			},
		},
		{
			name: "gen_ai semantic conventions",
			in: map[string]interface{}{
				"gen_ai.response.model":          "claude-opus-4",
				"gen_ai.usage.prompt_tokens":     float64(10),
				"gen_ai.usage.completion_tokens": float64(20),
				"gen_ai.usage.total_tokens":      float64(30),
			},
			want: hookTokenUsage{
				Model:            "claude-opus-4",
				PromptTokens:     10,
				CompletionTokens: 20,
				TotalTokens:      30,
			},
		},
		{
			name: "string-encoded counts",
			in: map[string]interface{}{
				"usage": map[string]interface{}{
					"prompt_tokens":     "42",
					"completion_tokens": "7",
				},
				"model_id": "gpt-4-turbo",
			},
			want: hookTokenUsage{
				Model:            "gpt-4-turbo",
				PromptTokens:     42,
				CompletionTokens: 7,
				TotalTokens:      49,
			},
		},
		{
			name: "no usage data returns zero",
			in: map[string]interface{}{
				"hook_event_name": "PreToolUse",
				"tool_name":       "Bash",
			},
			want: hookTokenUsage{},
		},
		{
			name: "non-numeric strings ignored",
			in: map[string]interface{}{
				"usage": map[string]interface{}{
					"prompt_tokens":     "not a number",
					"completion_tokens": "1.5", // strict parse rejects decimals
				},
			},
			want: hookTokenUsage{},
		},
		{
			name: "negative values ignored",
			in: map[string]interface{}{
				"usage": map[string]interface{}{
					"prompt_tokens":     float64(-1),
					"completion_tokens": float64(0),
				},
			},
			want: hookTokenUsage{},
		},
		{
			name: "empty payload",
			in:   nil,
			want: hookTokenUsage{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractHookPayloadTokenUsage(tc.in)
			if got != tc.want {
				t.Errorf("extractHookPayloadTokenUsage:\n  got  = %+v\n  want = %+v", got, tc.want)
			}
		})
	}
}

func TestParseIntStrict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		want   int64
		wantOk bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{"42", 42, true},
		{"123456789", 123456789, true},
		{"-1", 0, false},
		{"1.5", 0, false},
		{"1e3", 0, false},
		{"abc", 0, false},
		{"1abc", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseIntStrict(tc.in)
		if got != tc.want || ok != tc.wantOk {
			t.Errorf("parseIntStrict(%q) = (%d, %v); want (%d, %v)", tc.in, got, ok, tc.want, tc.wantOk)
		}
	}
}

func TestExtractHookPayloadReportedCost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		payload map[string]interface{}
		want    hookReportedCost
	}{
		{"top-level", map[string]interface{}{"total_cost_usd": 1.25}, hookReportedCost{USD: 1.25, Present: true, Cumulative: true}},
		{"nested usage string", map[string]interface{}{"usage": map[string]interface{}{"cost_usd": "0.0042"}}, hookReportedCost{USD: 0.0042, Present: true}},
		{"nested result usage", map[string]interface{}{"result": map[string]interface{}{"usage": map[string]interface{}{"total_cost_usd": "0.007"}}}, hookReportedCost{USD: 0.007, Present: true, Cumulative: true}},
		{"literal dotted usage key", map[string]interface{}{"usage.total_cost_usd": "0.008"}, hookReportedCost{USD: 0.008, Present: true, Cumulative: true}},
		{"reported zero is present", map[string]interface{}{"sessionCostUsd": 0}, hookReportedCost{USD: 0, Present: true, Cumulative: true}},
		{"generic cost is not assumed USD", map[string]interface{}{"cost": 99}, hookReportedCost{}},
		{"missing", map[string]interface{}{"model": "gpt-5"}, hookReportedCost{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractHookPayloadReportedCost(tc.payload); got != tc.want {
				t.Fatalf("extractHookPayloadReportedCost() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
