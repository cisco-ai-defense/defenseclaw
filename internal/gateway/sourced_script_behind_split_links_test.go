// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A working folder named by its links is read as the system reads the name:
// a process that reached the folder through some links and then changed
// into a link of it holds a folder whose spelling counts all of them, and
// one absolute open of that spelling fails once they pass the system limit.
// A sourced script behind such a spelling is a body the call could not read.
// It is judged by the tier like a body past the share walk bound (the strict
// tier blocks, the default tier allows with the alert), never allowed with
// no finding. A spelling within the limit reads the script, and the script
// that writes a protected file is blocked in both tiers
// (rel-1-0-9:GAP-0950, GAP-0935).
func TestSourcedScriptBehindLinksSplitAcrossTheWorkingFolderIsJudgedByTheTier(t *testing.T) {
	limit := hookpaths.ShareWalkLinkLimit()
	splits := []int{0, 1, 2, limit - 2, limit - 1, limit, limit + 1}
	slices.Sort(splits)
	splits = slices.Compact(splits)
	for _, folderLinks := range splits {
		total := folderLinks + 1
		for _, script := range []string{"writer.sh", "safe.sh"} {
			t.Run(fmt.Sprintf("%s behind %d folder links and the last link", script, folderLinks), func(t *testing.T) {
				home, live := r104ReviewHome(t)
				for name, body := range map[string]string{
					"writer.sh": "echo marker >> alias\n",
					"safe.sh":   "echo ordinary > report.txt\n",
				} {
					if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				cwd := splitLinkWorkingFolder(t, folderLinks, live)
				wantStrict, wantDefault, alert := "allow", "allow", false
				switch {
				case total > limit:
					wantStrict, wantDefault, alert = "block", "alert", true
				case script == "writer.sh":
					wantStrict, wantDefault = "block", "block"
				}
				for _, strict := range []bool{true, false} {
					func() {
						defer hookpaths.HookCall()()
						request := trustedActionRequest{
							Input:     actionfacts.Input{Tool: "Bash", Command: "source " + script, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
							Connector: "claudecode", ProtectedHomeHook: true, EnforcementCapable: true,
						}
						ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
						findings := dispatchTrustedAction(ctx, request)
						want := wantDefault
						if strict {
							want = wantStrict
						}
						if got := buildVerdict(findings, "tool_call").Action; got != want {
							t.Errorf("strict=%v source %s behind %d links: %s, want %s (findings %v)", strict, script, total, got, want, findings)
						}
						hasAlert := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == shareBodyUnreadRuleID })
						if !strict && hasAlert != alert {
							t.Errorf("default tier alert behind %d links: %v, want %v", total, hasAlert, alert)
						}
						if strict && total > limit && !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "ACTION-COMPOUND-LIMIT" }) {
							t.Errorf("strict tier: no evaluation-limit finding behind %d links: %v", total, findings)
						}
					}()
				}
			})
		}
	}
}

// splitLinkWorkingFolder returns the spelling of target that a process holds
// after it reached a middle folder through n links and then changed into the
// link "next" of that folder: n links on the way to the folder and one more
// to target, each link made after the folder it points at exists.
func splitLinkWorkingFolder(t *testing.T, n int, target string) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		var err error
		if dir, err = filepath.EvalSymlinks(dir); err != nil {
			t.Fatal(err)
		}
		if target, err = filepath.EvalSymlinks(target); err != nil {
			t.Fatal(err)
		}
	}
	middle := filepath.Join(dir, "middle")
	if err := os.Mkdir(middle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(middle, "next")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	entry := middle
	for i := n; i >= 1; i-- {
		link := filepath.Join(dir, fmt.Sprintf("hop%03d", i))
		if err := os.Symlink(entry, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		entry = link
	}
	return filepath.Join(entry, "next")
}
