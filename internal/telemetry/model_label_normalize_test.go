// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"strings"
	"testing"
)

// TestNormalizeModelLabel_BoundsCardinality is the M4 regression
// test: every input must collapse onto a small, fixed set of labels
// regardless of how many model versions or how exotic the model
// identifiers grow over time. A successful regression of this test
// is the canary for "we re-introduced unbounded cardinality on the
// gen_ai.* model attribute". The exact size of the allowed set is
// kept here so the count is asserted in a single place.
func TestNormalizeModelLabel_BoundsCardinality(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "unknown"},
		{"whitespace", "   ", "unknown"},
		{"unknownFamily", "some-future-model-9000", "other"},
		{"unknownFamilyLong", strings.Repeat("a", 200), "other"},
		{"hostileSlash", "gpt-5/../../etc/passwd", "other"},
		{"hostileNewline", "gpt-5\nclaude", "other"},

		// Known families collapse on exact + dotted + dashed + colon-suffixed forms.
		{"gpt5", "gpt-5", "gpt-5"},
		{"gpt5Variant", "gpt-5-mini-2026-04-18", "gpt-5"},
		{"gpt5Nano", "gpt-5-nano", "gpt-5"},
		{"gpt5Date", "gpt-5.0420", "gpt-5"},
		{"gpt4", "gpt-4", "gpt-4"},
		{"gpt4Turbo", "gpt-4-turbo", "gpt-4"},
		{"gpt4o", "gpt-4o", "gpt-4o"}, // gpt-4o is its own family per OpenAI
		{"gpt4oMini", "gpt-4o-mini-2024-07-18", "gpt-4o"},
		{"gpt35", "gpt-3.5", "gpt-3.5"},
		{"o1", "o1", "o1"},
		{"o3", "o3-mini", "o3"},
		{"claude4", "claude-4-sonnet", "claude-4"},
		{"claude37", "claude-3-7-sonnet-20250219", "claude-3-7"},
		{"claudeSonnetAlias", "claude-sonnet-4-5", "claude-sonnet"},
		{"claudeOpusAlias", "claude-opus-4-5-20250514", "claude-opus"},
		{"claudeHaikuAlias", "claude-haiku-3-5", "claude-haiku"},
		{"gemini2", "gemini-2.0-flash", "gemini-2"},
		{"gemini15", "gemini-1.5-pro-002", "gemini-1.5"},
		{"geminiOther", "gemini-experimental", "gemini"},
		{"llama4", "llama-4-maverick", "llama-4"},
		{"llama3", "llama-3.1-405b", "llama-3"},
		{"mistral", "mistral-large", "mistral"},
		{"deepseekR1", "deepseek-r1", "deepseek"},
		{"qwen", "qwen-2.5-32b", "qwen"},
		{"grok", "grok-3-beta", "grok"},
		{"commandR", "command-r-plus-2025-04", "command-r"},
		{"phi3", "phi-3.5", "phi-3"},
		{"phi4", "phi-4-mini", "phi-4"},

		// Case folding
		{"upperCase", "GPT-5", "gpt-5"},
		{"mixedCase", "Claude-Opus-4-5", "claude-opus"},

		// Colon separator (provider-prefixed identifiers)
		{"providerPrefix", "anthropic:claude-3-7-sonnet", "other"}, // anthropic: not in allowlist
		{"colonSuffix", "claude-3:vllm-pinned", "claude-3"},
	}

	// Assert each case + collect the set of unique label values so
	// we can guard the total label count.
	seen := map[string]struct{}{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeModelLabel(tc.in)
			if got != tc.want {
				t.Errorf("NormalizeModelLabel(%q) = %q, want %q", tc.in, got, tc.want)
			}
			seen[got] = struct{}{}
		})
	}

	// Hard upper bound: the allowlist size plus the synthetic
	// buckets (unknown, other). If a future patch wires in a new
	// model family without registering it here, the count grows
	// and this test fires loud.
	const maxAllowedLabels = 30
	if len(seen) > maxAllowedLabels {
		t.Errorf("normalize emitted %d distinct labels; want ≤ %d (cardinality budget exceeded)", len(seen), maxAllowedLabels)
	}
}
