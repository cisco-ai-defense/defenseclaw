// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A later redirection whose double-quoted target holds a backtick quote is
// split as a word is, so the launcher reader still reads the statement: the
// nested cmd /c launchers around the authorized_keys redirect fixture
// (overLimitWindowsRedirect) get the verdict of the same nesting without that
// redirection where both shells read the target alike, and past the launcher
// depth they are TRUNCATED at the depth cap whatever the target
// (rel-1-0-10:GAP-0969). A launcher behind time or nsenter, or behind a
// context-neutral wrapper chain the analysis reads whole, is read as the bare
// launcher is (rel-1-0-10:GAP-0970). 5 tiers, argv and string.
func TestGAP0969LaterRedirectTargetsKeepTheLauncherReadDefault(t *testing.T) {
	gap0969LauncherReader(t, 0)
}
func TestGAP0969LaterRedirectTargetsKeepTheLauncherReadPermissive(t *testing.T) {
	gap0969LauncherReader(t, 1)
}
func TestGAP0969LaterRedirectTargetsKeepTheLauncherReadStrict(t *testing.T) {
	gap0969LauncherReader(t, 2)
}
func TestGAP0969LaterRedirectTargetsKeepTheLauncherReadManaged(t *testing.T) {
	gap0969LauncherReader(t, 3)
}
func TestGAP0969LaterRedirectTargetsKeepTheLauncherReadManagedStrict(t *testing.T) {
	gap0969LauncherReader(t, 4)
}

func gap0969LauncherReader(t *testing.T, tierIndex int) {
	gap0589WindowsHost(t)
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	tier := boundedTestTiers[tierIndex]
	floor := bounded.Unknown(tier.tier)
	api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
	decide := func(command interface{}) (bounded.Action, bool, string) {
		resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		})
		return boundedParse(resp.Action), containsString(resp.RuleIDs, evaluationLimitRuleID), resp.Action
	}
	// GAP-0969: a later redirection with a backtick quote in its target,
	// after or before the fixture's own redirection.
	for _, extra := range []struct {
		id, before, after string
		keepsPlain        bool
	}{
		{"then-backtick-target", "", " 2> \"a`\"b\"", false},
		{"backtick-target-first", " 2> \"a`\"b\"", "", false},
		{"then-doubled-quote-target", "", ` 2> "a""b"`, true},
	} {
		for k := 1; k <= maxLauncherBodyDepth+1; k++ {
			pre := strings.Repeat("cmd /c ", k-1)
			plain := pre + overLimitWindowsRedirect
			spelled := pre + strings.Replace(overLimitWindowsRedirect, " >> ", extra.before+" >> ", 1) + extra.after
			for form, pair := range map[string][2]interface{}{
				"argv":   {[]interface{}{"cmd", "/c", plain}, []interface{}{"cmd", "/c", spelled}},
				"string": {"cmd /c " + plain, "cmd /c " + spelled},
			} {
				want, _, _ := decide(pair[0])
				got, limit, action := decide(pair[1])
				// A backtick is no escape to CMD, so inside the depth the CMD
				// reading of a backtick target is its own (rel-1-0-10:GAP-0974);
				// a doubled quote reads the same in both shells.
				if extra.keepsPlain && got < want {
					t.Errorf("%s/%s/depth %d %s: action %s, below the same nesting without the redirection (%s)", tier.name, extra.id, k, form, action, want)
				}
				if k > maxLauncherBodyDepth && (got < floor || !limit && got != bounded.Block) {
					t.Errorf("%s/%s/depth %d %s: action %s limit %t, want at least %s at the depth cap", tier.name, extra.id, k, form, action, limit, floor)
				}
			}
		}
	}
	// GAP-0970: a launcher behind every pass-through wrapper the analysis
	// unwraps, and behind a context-neutral chain of 5 and of more than 64
	// words, blocks the fixture in the argv form; an ordinary script stays
	// allowed.
	for _, chain := range []struct{ id, pre string }{
		{"time", "time"},
		{"time -p", "time -p"},
		{"nsenter -t 1 -m", "nsenter -t 1 -m"},
		{"time x5", strings.TrimSpace(strings.Repeat("time ", 5))},
		{"nice -n 5 x30", strings.TrimSpace(strings.Repeat("nice -n 5 ", 30))},
	} {
		for _, l := range []gap0711Launcher{gap0805Launchers[1], gap0805Launchers[3]} {
			for _, row := range []struct {
				id, body string
				want     bounded.Action
			}{
				{"redirect", overLimitWindowsRedirect, bounded.Block},
				{"benign-git", `git log --oneline -5`, bounded.Allow},
			} {
				words := strings.Fields(chain.pre)
				argv := make([]interface{}, 0, len(words)+3)
				for _, w := range words {
					argv = append(argv, w)
				}
				argv = append(argv, gap0805Argv(gap0805Wrapper{}, l, row.body)...)
				got, limit, action := decide(argv)
				if row.want == bounded.Block && got != bounded.Block {
					t.Errorf("%s/%s/%s/%s argv: action %s, want block", tier.name, chain.id, l.name, row.id, action)
				}
				if row.want == bounded.Allow && got != bounded.Allow && (!limit || got != floor) {
					t.Errorf("%s/%s/%s/%s argv: action %s, want allow (or the unknown tier at a cap)", tier.name, chain.id, l.name, row.id, action)
				}
			}
		}
	}
}
