// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A sourced script whose folder is reached through more links than the share
// walk follows (40) is a body the call could not read. It is judged as a
// body the share budget kept unread is: the strict tier blocks, the default
// tier allows with the alert. A chain within the bound reads the script, and
// the script that writes a protected file through a link is blocked in both
// tiers (rel-1-0-9:GAP-0621).
func TestSourcedScriptBehindTooManyLinksIsJudgedByTheTier(t *testing.T) {
	for _, tc := range []struct {
		name          string
		links         int
		script        string
		strict        string
		def           string
		defHasAlert   bool
		strictHasRule string
	}{
		{"writer within the bound", 40, "writer.sh", "block", "block", false, ""},
		{"ordinary within the bound", 40, "safe.sh", "allow", "allow", false, ""},
		{"writer beyond the bound", 41, "writer.sh", "block", "alert", true, "ACTION-COMPOUND-LIMIT"},
		{"ordinary beyond the bound", 41, "safe.sh", "block", "alert", true, "ACTION-COMPOUND-LIMIT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, live := r104ReviewHome(t)
			for name, body := range map[string]string{
				"writer.sh": "echo marker >> alias\n",
				"safe.sh":   "echo ordinary > report.txt\n",
			} {
				if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			restore := hookpaths.OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
			t.Cleanup(restore)
			cwd := gatewayLinkChain(t, tc.links, live)
			for _, strict := range []bool{true, false} {
				func() {
					defer hookpaths.HookCall()()
					request := trustedActionRequest{
						Input:     actionfacts.Input{Tool: "Bash", Command: "source " + tc.script, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
						Connector: "claudecode", ProtectedHomeHook: true, EnforcementCapable: true,
					}
					ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
					findings := dispatchTrustedAction(ctx, request)
					got, want := buildVerdict(findings, "tool_call").Action, tc.def
					if strict {
						want = tc.strict
					}
					if got != want {
						t.Errorf("strict=%v source %s behind %d links: %s, want %s (findings %v)", strict, tc.script, tc.links, got, want, findings)
					}
					alert := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == shareBodyUnreadRuleID })
					if !strict && alert != tc.defHasAlert {
						t.Errorf("default tier alert for %d links: %v, want %v", tc.links, alert, tc.defHasAlert)
					}
					if strict && tc.strictHasRule != "" && !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == tc.strictHasRule }) {
						t.Errorf("strict tier: no %s finding behind %d links: %v", tc.strictHasRule, tc.links, findings)
					}
				}()
			}
		})
	}
}

// gatewayLinkChain makes n links, the first named by the returned path, each
// pointing at the next and the last at target. The links are made from the
// last to the first so each target exists when its link is made: Windows
// makes a link to a folder a folder link only if the folder is there, and a
// file link to a folder cannot be opened as one, so a chain made from the
// first to the last is a chain no read can go through. A chain that does not
// open fails the test, never skips it.
func gatewayLinkChain(t *testing.T, n int, target string) string {
	t.Helper()
	dir := t.TempDir()
	name := func(i int) string { return filepath.Join(dir, fmt.Sprintf("hop%03d", i)) }
	for i := n; i >= 1; i-- {
		to := target
		if i < n {
			to = name(i + 1)
		}
		if err := os.Symlink(to, name(i)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(name(1), "safe.sh")); err != nil {
		t.Fatalf("a chain of %d links to %s does not open: %v", n, target, err)
	}
	return name(1)
}
