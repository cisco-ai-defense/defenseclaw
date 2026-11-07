// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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

func shareBudgetVerdict(t *testing.T, home, live, command string, protectedHome bool, dead []string) string {
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
	return buildVerdict(dispatchTrustedAction(t.Context(), request), "tool_call").Action
}

// rel-1-0-6:GAP-0482 (review 7): shares that do not answer spend the share
// budget of a hook call, and a script on an answering share asked after them
// is then unread. It is judged as a call past the evaluation limit, never as
// a script that writes nothing, whatever the number of shares before it. A
// script that writes through a link to the protected keys file blocks as it
// does when it is read. The protected-home cell is the managed hook.
func TestGAP0482ShareBudgetNeverTurnsAnUnreadScriptIntoAnAllow(t *testing.T) {
	for _, protectedHome := range []bool{false, true} {
		for _, count := range []int{2, 3, 4, 6} {
			t.Run(fmt.Sprintf("protected-home-%t/dead-%d", protectedHome, count), func(t *testing.T) {
				home, live, dead := shareBudgetFixture(t, count, 100*time.Millisecond)
				if got := shareBudgetVerdict(t, home, live, "source writer.sh", protectedHome, dead); got != "block" {
					t.Errorf("a script on the share after %d shares that do not answer: verdict %s, want block", count, got)
				}
			})
		}
	}
}

// The benign twin: with the budget to spare the answering share is read and
// its ordinary script is allowed; a command that reads no script is allowed
// whatever the shares before it did.
func TestGAP0482ShareBudgetBenignTwinsStayAllowed(t *testing.T) {
	for _, protectedHome := range []bool{false, true} {
		t.Run(fmt.Sprintf("protected-home-%t", protectedHome), func(t *testing.T) {
			home, live, dead := shareBudgetFixture(t, 2, 100*time.Millisecond)
			if got := shareBudgetVerdict(t, home, live, "source safe.sh", protectedHome, dead); got != "allow" {
				t.Errorf("an ordinary script on the answering share: verdict %s, want allow", got)
			}
		})
		t.Run(fmt.Sprintf("protected-home-%t/no-script", protectedHome), func(t *testing.T) {
			home, live, dead := shareBudgetFixture(t, 4, 100*time.Millisecond)
			if got := shareBudgetVerdict(t, home, live, "echo ordinary", protectedHome, dead); got != "allow" {
				t.Errorf("a command that reads no script after four dead shares: verdict %s, want allow", got)
			}
		})
	}
}
