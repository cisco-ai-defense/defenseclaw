// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A script body on a share that the hook call budget kept unread is judged by
// the policy tier. When proven assignments meet, the derived configuration
// keeps the base (default) pack, so the tier is taken per member: a strict
// member that blocks keeps its block (the final action of a meet is the
// strongest member action), a strict member that only observes does not
// raise one, and a meet of default members alerts as one default profile does
// (rel-1-0-6:GAP-0482, review 9).
func TestShareBodyUnreadIsJudgedByTheStrongestEnforcingMember(t *testing.T) {
	stubProfileSources(t)
	root := guardrailPoliciesRoot(t)
	profile := func(pack, mode string) config.GuardrailProfile {
		return config.GuardrailProfile{Mode: mode, BlockAt: "MEDIUM", RulePackDir: filepath.Join(root, pack)}
	}
	for _, row := range []struct {
		name          string
		first, second config.GuardrailProfile
		command, want string
	}{
		{"default-only", profile("default", "action"), profile("default", "action"), "source safe.sh", "alert"},
		{"strict-only", profile("strict", "action"), profile("strict", "action"), "source safe.sh", "block"},
		{"default-and-strict-ordinary", profile("default", "action"), profile("strict", "action"), "source safe.sh", "block"},
		{"strict-and-default-ordinary", profile("strict", "action"), profile("default", "action"), "source safe.sh", "block"},
		{"default-and-strict-protected-writer", profile("default", "action"), profile("strict", "action"), "source writer.sh", "block"},
		{"default-and-strict-observer-ordinary", profile("default", "action"), profile("strict", "observe"), "source safe.sh", "alert"},
	} {
		t.Run(row.name, func(t *testing.T) {
			profiles := map[string]config.GuardrailProfile{"a-first": row.first, "b-second": row.second}
			set, raw := meetOfTwoAssignments(t, "action", profiles, "a-first", "b-second", "claudecode")
			ctx := withGuardrailProfile(withProfilePath(raw, profilePathHook), set, "claudecode")
			if resolvedGuardrailProfileFrom(ctx) == nil {
				t.Fatal("fixture selected no profile")
			}
			home, live, dead := shareBudgetFixture(t, 3, 700*time.Millisecond)
			api := &APIServer{}
			var action string
			runtime := hookProfileRuntime{Evaluate: func(_ *APIServer, evalCtx context.Context, _ agentHookRequest, _ []byte, _ map[string]interface{}) agentHookResponse {
				for _, dir := range dead {
					_, _ = hookpaths.Lstat(filepath.Join(dir, "notes.txt"))
				}
				findings := dispatchTrustedAction(evalCtx, trustedActionRequest{
					Input:     actionfacts.Input{Tool: "Bash", Command: row.command, CWD: live, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
					Connector: "claudecode", ProtectedHomeHook: true, EnforcementCapable: true,
				})
				if !hookpaths.ShareBodyUnread() {
					t.Error("fixture did not leave the script body unread")
				}
				action = api.buildVerdict(evalCtx, findings, "tool_call", false).Action
				return agentHookResponse{Action: action}
			}}
			api.safeEvaluateHook(ctx, "claudecode", agentHookRequest{}, nil, nil, runtime)
			if action != row.want {
				t.Errorf("unread script %q: verdict %s, want %s", row.command, action, row.want)
			}
		})
	}
}
