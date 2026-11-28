// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGAP1865AliasReadKeepsThePlainSpellingCell (DET111 GAP-2025): a read
// or write through a session link alias (GAP-1865: the link made by one
// call, used by a later call of the same session) is graded as the plain
// spelling of the member it names, on the Claude Code and Codex hook routes
// in the five tiers. A project link to ~/.npmrc or ~/.kube/config is a
// plain dev workflow: showing it gets the cell cat of the member gets, and
// a count through it is never above grep -c of the member. A write through
// it keeps the T23 restricted cell, never below the plain write (DET111
// ruling on GAP-2114/GAP-2121); with the link also on disk the effect
// reader resolves it and the write is the plain write, as at T23. The cross-call
// alias of ~/.ssh/id_rsa keeps the cell of cat ~/.ssh/id_rsa. At
// ac8b361121 every alias use was the restricted credentials tier, so the
// npmrc and kubeconfig rows were CRITICAL (a block in strict) where the
// plain read is a MEDIUM alert.
func TestGAP1865AliasReadKeepsThePlainSpellingCell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	for _, f := range []string{".npmrc", ".kube/config", ".ssh/id_rsa", "proj/scratch/keep"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	rows := []struct {
		link, alias, member string
		uses                []string // %s is the alias, then the member
		exact               bool
		write               bool // at least the plain write, and the T23 restricted CRITICAL
	}{
		{"ln -sf ~/.npmrc ~/proj/.npmrc", "~/proj/.npmrc", "~/.npmrc",
			[]string{"cat %s", "head -n 3 %s"}, true, false},
		{"ln -sf ~/.npmrc ~/proj/.npmrc", "~/proj/.npmrc", "~/.npmrc",
			[]string{"echo registry=x >> %s", "printf x > %s"}, false, true},
		{"ln -sf ~/.npmrc ~/proj/.npmrc", "~/proj/.npmrc", "~/.npmrc",
			[]string{"grep -c registry %s"}, false, false},
		{"ln -sf ~/.kube/config ~/proj/kubeconfig", "~/proj/kubeconfig", "~/.kube/config",
			[]string{"cat %s"}, true, false},
		{"ln -sf ~/.kube/config ~/proj/kubeconfig", "~/proj/kubeconfig", "~/.kube/config",
			[]string{"grep -c server %s"}, false, false},
		{"ln -sf ~/.ssh/id_rsa ./scratch/see", "./scratch/see", "~/.ssh/id_rsa",
			[]string{"cat %s"}, true, false},
	}
	expand := func(p string) string {
		if rest, ok := strings.CutPrefix(p, "~/"); ok {
			return filepath.Join(home, rest)
		}
		return filepath.Join(cwd, p)
	}
	for _, tier := range boundedTestTiers {
		for _, route := range gap2025Routes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for n, row := range rows {
				for _, onDisk := range []bool{false, true} {
					session := fmt.Sprintf("gap2025-%s-%s-%d-%v", tier.name, route.connector, n, onDisk)
					_ = os.Remove(expand(row.alias))
					if got, _ := route.decide(t, api, session, cwd, row.link); got == "block" {
						t.Fatalf("%s %s %q: link blocked", tier.name, route.connector, row.link)
					}
					if onDisk {
						if err := os.Symlink(expand(row.member), expand(row.alias)); err != nil {
							t.Fatal(err)
						}
					}
					for _, use := range row.uses {
						plain, plainSev := route.decide(t, api, session+"-plain", cwd, fmt.Sprintf(use, row.member))
						got, sev := route.decide(t, api, session, cwd, fmt.Sprintf(use, row.alias))
						if row.write {
							// Only the memo alias is the T23 restricted tier: a link
							// on disk is resolved by the effect reader itself, and
							// the write is the plain write of the member, as at T23
							// (ac8b361121).
							if credentialFlowRank[got] < credentialFlowRank[plain] ||
								aliasSeverityRank[sev] < aliasSeverityRank[plainSev] ||
								!onDisk && sev != "CRITICAL" {
								t.Errorf("%s %s disk link %v %q: %s/%s, want at least the plain write %q %s/%s (and the T23 restricted CRITICAL without a disk link)",
									tier.name, route.connector, onDisk, fmt.Sprintf(use, row.alias), got, sev,
									fmt.Sprintf(use, row.member), plain, plainSev)
							}
							continue
						}
						if row.exact && (got != plain || sev != plainSev) ||
							credentialFlowRank[got] > credentialFlowRank[plain] ||
							got == plain && aliasSeverityRank[sev] > aliasSeverityRank[plainSev] {
							t.Errorf("%s %s disk link %v %q: %s/%s, want the plain spelling %q cell %s/%s",
								tier.name, route.connector, onDisk, fmt.Sprintf(use, row.alias), got, sev,
								fmt.Sprintf(use, row.member), plain, plainSev)
						}
					}
					_ = os.Remove(expand(row.alias))
				}
			}
		}
	}
}

var aliasSeverityRank = map[string]int{"": 0, "NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}

type gap2025Route struct {
	connector string
	decide    func(t *testing.T, api *APIServer, session, cwd, command string) (string, string)
}

// gap2025Routes are the two hook routes that carry a session id (the alias
// memo is per session).
func gap2025Routes() []gap2025Route {
	return []gap2025Route{
		{"claudecode", func(t *testing.T, api *APIServer, session, cwd, command string) (string, string) {
			resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: session, CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Severity
		}},
		{"codex", func(t *testing.T, api *APIServer, session, cwd, command string) (string, string) {
			resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", SessionID: session, ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Severity
		}},
	}
}
