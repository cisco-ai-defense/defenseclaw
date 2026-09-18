// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"strings"
)

// inspectableTextMaxDepth bounds the JSON walk. ACP content blocks nest a few
// levels at most (params.prompt[].text, params.update.content.text); anything
// deeper is either an unknown extension or an attempt to bury content below
// the recursion the scanner is willing to follow, and both are already
// size-bounded by MaxFrameBytes / MaxTurnEvaluationBytes upstream.
const inspectableTextMaxDepth = 64

// InspectableText renders the human-readable strings carried by an ACP frame
// as newline-separated lines, for the guardrail content scanners.
//
// The guard must NOT hand the raw JSON-RPC envelope to those scanners. Content
// rules are written against prose and anchor on prose boundaries — start of
// line, sentence punctuation, list markers. Inside a marshalled frame the very
// same sentence is preceded by `"` (the opening quote of the JSON string), so
// whether a rule fires depends on whether its author happened to include a
// quote in the boundary alternation. That is luck, not policy: a stale or
// stricter rule pack silently stops matching prompts it was written to catch,
// with no error anywhere. Putting every string on its own line restores the
// start-of-line boundary those rules were authored against.
//
// Every string value is collected, not just the ones under keys this build
// knows ("text", "content", ...). An unrecognized or newly added ACP content
// shape must fail toward inspection, never away from it.
//
// Returns "" when the payload carries no strings, so callers can fall back to
// the raw frame rather than scanning nothing.
func InspectableText(payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}
	var b strings.Builder
	collectInspectableText(decoded, 0, &b)
	return strings.TrimRight(b.String(), "\n")
}

func collectInspectableText(node any, depth int, b *strings.Builder) {
	if depth > inspectableTextMaxDepth {
		return
	}
	switch value := node.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return
		}
		b.WriteString(value)
		b.WriteByte('\n')
	case []any:
		for _, item := range value {
			collectInspectableText(item, depth+1, b)
		}
	case map[string]any:
		// Deterministic order: a verdict reason must not depend on Go's
		// randomized map iteration, and neither must a rule whose pattern
		// spans two adjacent content blocks.
		for _, key := range sortedKeys(value) {
			collectInspectableText(value[key], depth+1, b)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	// Small maps; insertion sort keeps this allocation-free versus sort.Strings.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
