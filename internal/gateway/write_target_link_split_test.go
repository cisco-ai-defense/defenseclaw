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

// A process whose working folder is reached through up to the links the
// system opens opens a name in it with a limit of its own. A call that
// writes through a two-link name from such a folder is judged by where the
// links end, at every split of the limit between the folder and the name:
// an ordinary file is allowed in both tiers, a protected file is blocked in
// both, whether the name is typed, sourced from a script, or held in a
// known value (rel-1-0-9:GAP-0935).
func TestWriteThroughANameFromAFolderBehindManyLinksIsJudgedByTheFileItReaches(t *testing.T) {
	limit := hookpaths.SystemLinkLimit()
	counts := []int{0, 1, 2, limit - 4, limit - 3, limit - 2, limit - 1, limit}
	slices.Sort(counts)
	counts = slices.Compact(counts)
	for _, folderLinks := range counts {
		if folderLinks < 0 {
			continue
		}
		t.Run(fmt.Sprintf("folder behind %d links", folderLinks), func(t *testing.T) {
			home, live := r104ReviewHome(t)
			protected := filepath.Join(home, ".ssh", "authorized_keys")
			ordinary := filepath.Join(live, "report.txt")
			if err := os.WriteFile(ordinary, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			scripts := map[string]string{
				"safe.sh":   "echo ordinary >> ordinary1\n",
				"writer.sh": "echo marker >> protected1\n",
			}
			for name, body := range scripts {
				if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Made from the last link to the first so each target exists
			// when its link is made.
			for name, target := range map[string]string{"ordinary2": ordinary, "protected2": protected} {
				if err := os.Symlink(target, filepath.Join(live, name)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			for name, target := range map[string]string{"ordinary1": "ordinary2", "protected1": "protected2"} {
				if err := os.Symlink(filepath.Join(live, target), filepath.Join(live, name)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			cwd := live
			if folderLinks > 0 {
				cwd = gatewayLinkChain(t, folderLinks, live)
			}
			// The premise: a process stands in the folder and opens the
			// two-link name from it.
			t.Chdir(cwd)
			for _, name := range []string{"ordinary1", "protected1"} {
				if _, err := os.Stat(name); err != nil {
					t.Fatalf("the system does not open %s from a folder behind %d links: %v", name, folderLinks, err)
				}
			}
			restore := hookpaths.OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
			t.Cleanup(restore)
			for _, row := range []struct {
				name, command string
				blocked       bool
			}{
				{"ordinary typed", "echo ordinary >> ordinary1", false},
				{"ordinary known value", `f=ordinary1; echo ordinary >> "$f"`, false},
				{"ordinary sourced", "source safe.sh", false},
				{"protected typed", "echo marker >> protected1", true},
				{"protected known value", `f=protected1; echo marker >> "$f"`, true},
				{"protected sourced", "source writer.sh", true},
			} {
				for _, strict := range []bool{false, true} {
					func() {
						defer hookpaths.HookCall()()
						request := trustedActionRequest{
							Input:     actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
							Connector: "claudecode", ProtectedHomeHook: true, EnforcementCapable: true,
						}
						ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
						findings := dispatchTrustedAction(ctx, request)
						got := buildVerdict(findings, "tool_call").Action
						if want := map[bool]string{true: "block", false: "allow"}[row.blocked]; got != want {
							t.Errorf("%s, strict=%v, folder behind %d links: %s, want %s (findings %v)", row.name, strict, folderLinks, got, want, findings)
						}
					}()
				}
			}
		})
	}
}
