// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shareBudgetFixture is the project directory of r104ReviewHome as a network
// share that answers after liveDelay, and count more directories as shares
// that never answer. A script on the answering share writes through an
// existing link there to the protected keys file; another writes a report.
func shareBudgetFixture(t *testing.T, count int, liveDelay time.Duration) (home, live string, dead []string) {
	t.Helper()
	home, live = r104ReviewHome(t)
	for name, body := range map[string]string{
		"writer.sh": "echo marker >> alias\n",
		"safe.sh":   "echo ordinary > report.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range count {
		dir := filepath.Join(home, fmt.Sprintf("dead-%d", i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		dead = append(dead, dir)
	}
	release := make(chan struct{})
	restore := hookpaths.OverrideNetworkSharesForTest(func(path string) string {
		for _, root := range append(append([]string{}, dead...), live) {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				return root
			}
		}
		return ""
	}, func(root string) {
		if root != live+string(filepath.Separator) {
			<-release
			return
		}
		time.Sleep(liveDelay)
	})
	t.Cleanup(func() {
		close(release)
		restore()
	})
	return home, live, dead
}

func shareBudgetVerdict(t *testing.T, home, live, command string, protectedHome, strict bool, dead []string) string {
	t.Helper()
	request := trustedActionRequest{
		Input:     actionfacts.Input{Tool: "Bash", Command: command, CWD: live, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
		Connector: "claudecode", ProtectedHomeHook: protectedHome, EnforcementCapable: true,
	}
	defer hookpaths.HookCall()()
	for _, dir := range dead {
		if _, err := hookpaths.Lstat(filepath.Join(dir, "notes.txt")); err == nil {
			t.Fatal("the share that does not answer answered")
		}
	}
	ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
	return buildVerdict(dispatchTrustedAction(ctx, request), "tool_call").Action
}

// rel-1-0-6:GAP-0482 (review 7, review 8): shares that do not answer spend
// the share budget of a hook call, and a script on an answering share asked
// after them is then unread. The strict tier judges it as a call past the
// evaluation limit, never as a script that writes nothing, whatever the
// number of shares before it. The default tier does not refuse it: the body
// is neither a named nor a known protected target, so the call is allowed
// with a visible alert. The protected-home cell is the managed hook.
func TestGAP0482ShareBudgetUnreadScriptIsJudgedByTheTier(t *testing.T) {
	for _, protectedHome := range []bool{false, true} {
		for _, count := range []int{2, 3, 4, 6} {
			t.Run(fmt.Sprintf("protected-home-%t/dead-%d", protectedHome, count), func(t *testing.T) {
				home, live, dead := shareBudgetFixture(t, count, 100*time.Millisecond)
				if got := shareBudgetVerdict(t, home, live, "source writer.sh", protectedHome, true, dead); got != "block" {
					t.Errorf("a script on the share after %d shares that do not answer, strict tier: verdict %s, want block", count, got)
				}
			})
		}
	}
}

// The benign twin of the false block of review 8: an ordinary script on a
// share that answers in 500 ms, asked after two shares that do not answer,
// is not refused in the default tier, in both spellings of the source word,
// and carries the visible alert. Only the strict tier refuses what it could
// not read.
func TestGAP0482ShareBudgetSlowOrdinaryScriptIsNotRefusedByDefault(t *testing.T) {
	for _, protectedHome := range []bool{false, true} {
		for _, command := range []string{"source safe.sh", ". safe.sh"} {
			t.Run(fmt.Sprintf("protected-home-%t/%s", protectedHome, command), func(t *testing.T) {
				// One fixture per tier: a share that has answered is
				// remembered, and a call that finds it answered reads it.
				for _, strict := range []bool{false, true} {
					home, live, dead := shareBudgetFixture(t, 2, 500*time.Millisecond)
					got := shareBudgetVerdict(t, home, live, command, protectedHome, strict, dead)
					if want := map[bool]string{false: "alert", true: "block"}[strict]; got != want {
						t.Errorf("an ordinary script on a share answering in 500 ms, strict %t: verdict %s, want %s", strict, got, want)
					}
				}
			})
		}
	}
}

// The protected controls of every tier: a command that names the protected
// link itself is blocked after any number of shares that do not answer, and
// a script that is read still blocks when it writes through the link. With
// the budget to spare the answering share is read and its ordinary script is
// allowed; a command that reads no script is allowed whatever the shares
// before it did.
func TestGAP0482ShareBudgetNamedLinkAndBenignTwins(t *testing.T) {
	for _, protectedHome := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("protected-home-%t/strict-%t/named-link", protectedHome, strict), func(t *testing.T) {
				home, live, dead := shareBudgetFixture(t, 3, 100*time.Millisecond)
				if got := shareBudgetVerdict(t, home, live, "echo marker >> alias", protectedHome, strict, dead); got != "block" {
					t.Errorf("a write through the named protected link after three shares that do not answer: verdict %s, want block", got)
				}
			})
			t.Run(fmt.Sprintf("protected-home-%t/strict-%t/read-script", protectedHome, strict), func(t *testing.T) {
				home, live, dead := shareBudgetFixture(t, 1, 100*time.Millisecond)
				if got := shareBudgetVerdict(t, home, live, "source writer.sh", protectedHome, strict, dead); got != "block" {
					t.Errorf("a read script that writes through the protected link: verdict %s, want block", got)
				}
				if got := shareBudgetVerdict(t, home, live, "source safe.sh", protectedHome, strict, dead); got != "allow" {
					t.Errorf("a read ordinary script: verdict %s, want allow", got)
				}
			})
			t.Run(fmt.Sprintf("protected-home-%t/strict-%t/no-script", protectedHome, strict), func(t *testing.T) {
				home, live, dead := shareBudgetFixture(t, 4, 100*time.Millisecond)
				if got := shareBudgetVerdict(t, home, live, "echo ordinary", protectedHome, strict, dead); got != "allow" {
					t.Errorf("a command that reads no script after four dead shares: verdict %s, want allow", got)
				}
			})
		}
	}
}

// The hook entry points carry the policy tier of the request to the
// dispatch: a strict rule pack marks the context strict, the default and
// permissive packs do not, so the tier test above runs on the cells the
// gateway builds.
func TestGAP0482HookCallMarksTheTierForTheDispatch(t *testing.T) {
	for _, row := range []struct {
		pack   string
		strict bool
	}{{"strict", true}, {"default", false}, {"permissive", false}} {
		t.Run(row.pack, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.RulePack = row.pack
			api := &APIServer{scannerCfg: cfg}
			var seen, called bool
			runtime := hookProfileRuntime{Evaluate: func(_ *APIServer, ctx context.Context, _ agentHookRequest, _ []byte, _ map[string]interface{}) agentHookResponse {
				seen, called = shareBodyStrictFrom(ctx), true
				return agentHookResponse{Action: "allow"}
			}}
			api.safeEvaluateHook(t.Context(), "claudecode", agentHookRequest{}, nil, nil, runtime)
			if !called || seen != row.strict {
				t.Errorf("pack %s: evaluate called %t, strict mark %t, want %t", row.pack, called, seen, row.strict)
			}
		})
	}
}
