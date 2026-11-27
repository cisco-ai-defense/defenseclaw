// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"testing"
)

// TestGAP2207NilCompilerKeepsTheLiteralTombstoneDead: with no compiler (a
// generation whose compile failed, the legacy view) the expression text
// "false", the pack tombstone, still reads dead, as at the parent; any other
// expression reads live, since nothing can fold it. Red at a1e04558ad: every
// expression read live with no compiler, so the tombstone lent its severity.
func TestGAP2207NilCompilerKeepsTheLiteralTombstoneDead(t *testing.T) {
	curl := regexp.MustCompile(`(?i)\bcurl\b`)
	for _, tc := range []struct {
		expression string
		want       bool
	}{
		{"false", false},
		{"  false\n", false},
		{"false && true", true},
		{gap2207LiveExpression, true},
	} {
		rule := PatternRule{ID: "CMD-PIPE-CURL", Severity: "HIGH", Expression: tc.expression, Pattern: curl, ToolCallOnly: true}
		if got := effectRuleLive(rule, nil); got != tc.want {
			t.Errorf("effectRuleLive(%q, nil) = %t, want %t", tc.expression, got, tc.want)
		}
		want := ""
		if tc.want {
			want = "HIGH"
		}
		index := indexEffectRuleSeverity([]ruleCategory{{Rules: []PatternRule{rule}}}, nil)
		if got := index["CMD-PIPE-CURL"]; got != want {
			t.Errorf("indexEffectRuleSeverity(%q, nil) = %q, want %q", tc.expression, got, want)
		}
	}
}
