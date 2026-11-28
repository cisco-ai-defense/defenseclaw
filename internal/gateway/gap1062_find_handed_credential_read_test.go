// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP1062FindHandedCredentialReadIsItsStatementAlone: find FILE -exec
// cat {} \\; (or +, or cp {} DEST) hands the credential file to the same read
// as cat FILE, so the hook answers it with the same action, severity and rule
// ids in every tier (rel-1-0-10:GAP-1062: the find-handed readings once
// reported a lower severity than the read itself). The severity of the read
// itself is the semantic owner's (PATH-GIT-CREDS owns PATH-NETRC), the same
// for both spellings.
func TestGAP1062FindHandedCredentialReadIsItsStatementAlone(t *testing.T) {
	env := boundedLaneEnv(t)
	rows := []struct{ find, direct string }{
		{"find ~/.netrc -exec cat {} \\;", "cat ~/.netrc"},
		{"find ~/.aws/credentials -exec cat {} \\;", "cat ~/.aws/credentials"},
		{"find ~/.aws/credentials -exec cat {} +", "cat ~/.aws/credentials"},
		{"find ~/.aws/credentials -exec cp {} /tmp/staged \\;", "cp ~/.aws/credentials /tmp/staged"},
		{"find ~/.kube/config -exec cat {} +", "cat ~/.kube/config"},
		{"find ~/.git-credentials -exec cat {} \\;", "cat ~/.git-credentials"},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(command string) claudeCodeHookResponse {
			base := context.Background()
			ctx := withShareBodyStrict(base, func() bool { return api.shareBodyStrictTier(base, "claudecode") })
			input := map[string]any{"command": command}
			body := mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap1062", "cwd": env.cwd,
				"tool_name": "Bash", "tool_input": input})
			if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok {
				ctx = context.WithValue(ctx, resolvedWritesContextKey{}, targets)
			}
			return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap1062", CWD: env.cwd, ToolName: "Bash", ToolInput: input,
			})
		}
		for _, row := range rows {
			direct, found := decide(row.direct), decide(row.find)
			if direct.Severity == "" || direct.Severity == "NONE" || len(direct.RuleIDs) == 0 {
				t.Errorf("%s: the direct read %q has no finding (%s %v), the oracle proves nothing", tier.name, row.direct, direct.Severity, direct.RuleIDs)
			}
			if found.Action != direct.Action || found.Severity != direct.Severity || !slices.Equal(found.RuleIDs, direct.RuleIDs) {
				t.Errorf("%s: %q is %s %s %v, its statement alone %q is %s %s %v", tier.name,
					row.find, found.Action, found.Severity, found.RuleIDs, row.direct, direct.Action, direct.Severity, direct.RuleIDs)
			}
		}
	}
}
