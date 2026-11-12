// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway cannot open the user home, so a script body the hook
// client left unread (its path passes more links than the system opens, or
// the share wait ran out) reaches it only as client evidence. It is judged as
// the gateway judges a body its own read left unread: the strict tier blocks
// as for a call past the evaluation limit, the default and permissive tiers
// allow the ordinary script with the alert. A protected file the command
// names is blocked in every tier whatever the evidence says
// (rel-1-0-9:GAP-0950, managed macOS and Linux).
func TestManagedGatewayJudgesAScriptBodyTheHookClientLeftUnread(t *testing.T) {
	home, _ := r104ReviewHome(t)
	// The managed gateway has no view of this folder: it reads nothing in it.
	cwd := filepath.Join(home, "unreadable-by-the-gateway", "hop001")
	type outcome struct{ strict, def string }
	for _, tc := range []struct {
		name     string
		command  string
		evidence map[string]string
		want     outcome
		alert    bool
	}{
		{"ordinary body read by the client", "source safe.sh", map[string]string{}, outcome{"allow", "allow"}, false},
		{"ordinary body past the link bound", "source safe.sh", map[string]string{hookpaths.ShareBodyUnreadKey: "links"}, outcome{"block", "alert"}, true},
		{"writer body past the link bound", "source writer.sh", map[string]string{hookpaths.ShareBodyUnreadKey: "links"}, outcome{"block", "alert"}, true},
		{"dot form past the link bound", ". ./writer.sh", map[string]string{hookpaths.ShareBodyUnreadKey: "links"}, outcome{"block", "alert"}, true},
		{"ordinary body cut by the share budget", "source safe.sh", map[string]string{hookpaths.ShareBodyUnreadKey: "budget"}, outcome{"block", "alert"}, true},
		{"both causes", "source safe.sh", map[string]string{hookpaths.ShareBodyUnreadKey: "budget,links"}, outcome{"block", "alert"}, true},
		{"protected file named directly stays blocked", "echo marker >> ~/.ssh/authorized_keys", map[string]string{hookpaths.ShareBodyUnreadKey: "links"}, outcome{"block", "block"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, strict := range []bool{true, false} {
				end := hookpaths.HookCall()
				evidence := map[string]string{hookpaths.CWDKey: cwd}
				for key, value := range tc.evidence {
					evidence[key] = value
				}
				request := trustedActionRequest{
					Input:     actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
					Connector: "claudecode", ProtectedHomeHook: true, EnforcementCapable: true,
					ResolvedWriteTargets: evidence,
				}
				ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
				findings := dispatchTrustedAction(ctx, request)
				want := tc.want.def
				if strict {
					want = tc.want.strict
				}
				if got := buildVerdict(findings, "tool_call").Action; got != want {
					t.Errorf("strict=%v %q: %s, want %s (findings %v)", strict, tc.command, got, want, findings)
				}
				alert := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == shareBodyUnreadRuleID })
				if !strict && alert != tc.alert {
					t.Errorf("default tier %q: alert %v, want %v", tc.command, alert, tc.alert)
				}
				end()
			}
		})
	}
}
