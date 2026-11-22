// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1070. The shell lane trigger word of the PATH-ETC-SHADOW
// rule was tested on the raw text, so a quote- or backslash-split file name
// after a cd (cat sh'ad'ow) never reached the parse: allow, where the
// unquoted spelling and the split spelling with an absolute path get the rule.
func TestGAP1070SplitShadowNameAfterCdIsJudgedLikeItsPlainSpelling(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		plain, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand("cd /etc && cat shadow"))
		for _, command := range []string{
			"cd /etc && cat sh'ad'ow", "cd /etc && cat sh\"ad\"ow", "cd /etc && cat sha\\dow", "cd /etc && cat s''hadow",
		} {
			got, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			if boundedParse(got) < boundedParse(plain) {
				t.Errorf("%s %q: action=%s, plain spelling is %s; findings=%v", tier.name, strings.TrimSpace(command), got, plain, findings)
			}
		}
	}
}
