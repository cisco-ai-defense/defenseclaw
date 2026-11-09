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

// A script named by a path from a working folder without links, through a
// chain of folder links to a folder below it, is the script the system
// opens up to the links it opens (40 on Linux, 32 on macOS, 63 on Windows).
// Within the bound its body is read and a write it makes to a protected file
// through a link is blocked in both tiers, as for the same script named from
// inside the chain; past the bound it is an unread body judged by the tier;
// an ordinary script stays allowed within the bound (rel-1-0-9:GAP-0950,
// UB26-03).
func TestScriptNamedThroughLinksOutsideTheWorkingFolderIsReadOrUnread(t *testing.T) {
	limit := hookpaths.SystemLinkLimit()
	// One more link is the one from the working folder to the chain.
	for _, links := range []int{1, 8, 9, limit - 2, limit - 1, limit, limit + 1, limit + 24} {
		for _, script := range []string{"writer_direct.sh", "safe.sh"} {
			t.Run(fmt.Sprintf("%s behind %d links", script, links+1), func(t *testing.T) {
				home, cwd := r104ReviewHome(t)
				live := filepath.Join(cwd, "live")
				if err := os.Mkdir(live, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(live, "alias")); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{
					"writer_direct.sh": "echo marker >> " + filepath.Join(live, "alias") + "\n",
					"safe.sh":          "echo ordinary > report.txt\n",
				} {
					if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				restore := hookpaths.OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
				t.Cleanup(restore)
				if err := os.Symlink(gatewayLinkChain(t, links, live), filepath.Join(cwd, "c")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				read := links+1 <= limit
				for _, strict := range []bool{true, false} {
					func() {
						defer hookpaths.HookCall()()
						request := trustedActionRequest{
							Input:     actionfacts.Input{Tool: "Bash", Command: "source c/" + script, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
							Connector: "claudecode", EnforcementCapable: true,
						}
						ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
						findings := dispatchTrustedAction(ctx, request)
						want := "allow"
						switch {
						case !read && strict:
							want = "block"
						case !read:
							want = "alert"
						case script == "writer_direct.sh":
							want = "block"
						}
						if got := buildVerdict(findings, "tool_call").Action; got != want {
							t.Errorf("strict=%v source c/%s behind %d links: %s, want %s (findings %v)", strict, script, links+1, got, want, findings)
						}
						alert := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == shareBodyUnreadRuleID })
						if !strict && alert == read {
							t.Errorf("default tier: unread-body alert %v behind %d links (limit %d)", alert, links+1, limit)
						}
					}()
				}
			})
		}
	}
}
