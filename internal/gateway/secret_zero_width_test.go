// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// spliceZeroWidth puts sep after every n-th rune of s.
func spliceZeroWidth(s, sep string, n int) string {
	var b strings.Builder
	i := 0
	for _, r := range s {
		b.WriteRune(r)
		i++
		if i%n == 0 {
			b.WriteString(sep)
		}
	}
	return b.String()
}

// TestSecretRulesSeeThroughZeroWidthSeparators: a secret rule fixture
// (rules_test.go) with invisible characters spliced through it is still found
// by its rule on the hook path (prompt and tool result) and in a model
// response (whole and mid-stream). The proxy's removed secret regexes had a
// zero-width fallback; the rule pack now has it on every surface
// (rel-1-0-10:GAP-0210).
func TestSecretRulesSeeThroughZeroWidthSeparators(t *testing.T) {
	api := &APIServer{scannerCfg: &config.Config{}}
	insp := NewGuardrailInspector("local", nil, nil)
	insp.SetDetectionStrategy("regex_only", "", "", "", false)
	ctx := context.Background()
	for _, fx := range secretRuleTruePositives() {
		if strings.Contains(fx.input, "-----BEGIN") {
			continue // a PEM block is validated line by line (secretshape); not this property
		}
		for _, sep := range []string{"\u200b", "\u200d\u2060", "\u00ad"} {
			text := spliceZeroWidth(fx.input, sep, 7)
			hook := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "prompt"))
			result := api.inspectMessageContent(ctx, claudeCodeContentInspectRequest(text, "tool_result"))
			whole := insp.Inspect(ctx, "completion", text, nil, "model", "observe")
			mid := insp.InspectMidStream(ctx, "completion", text, []ChatMessage{{Role: "assistant", Content: text}}, "model", "observe")
			for name, findings := range map[string][]string{
				"hook prompt": hook.Findings, "hook tool result": result.Findings,
				"completion": whole.Findings, "mid-stream": mid.Findings,
			} {
				found := false
				for _, f := range findings {
					found = found || strings.HasPrefix(f, fx.wantID+":")
				}
				if !found {
					t.Errorf("%s with %q every 7 runes: %s findings %v, want %s", fx.name, sep, name, findings, fx.wantID)
				}
			}
		}
	}
}
