// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gap0641Payload(cwd, command string) []byte {
	return []byte(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":%q,"tool_input":{"command":%q}}`, cwd, command))
}

func TestGAP0641LateOutcomeFollowsTierAndNamedTarget(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	sp, ok := specFor("claudecode")
	if !ok {
		t.Fatal("Claude Code spec missing")
	}
	for _, row := range []struct {
		name, command, tier string
		managed, secure     bool
		wantMode            string
		wantBlocked         bool
	}{
		{"ordinary default", "echo ready", "open", false, false, "open", false},
		{"ordinary strict", "echo ready", "closed", false, false, "closed", true},
		{"ordinary managed", "echo ready", "open", true, false, "closed", true},
		{"direct named target", "cat ~/.ssh/authorized_keys", "open", false, false, "closed", true},
		{"known value named target", `f="$HOME/.ssh/authorized_keys"; cat "$f"`, "open", false, false, "closed", true},
		{"Secure Client unchanged", "echo ready", "open", false, true, "open", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			opts := Options{Connector: "claudecode", Event: "PreToolUse", Home: home,
				FailMode: row.tier, ManagedEnterprise: row.managed, SecureClient: row.secure,
				OutageFailModeNow: func() string { return row.tier },
				failurePayload:    gap0641Payload(cwd, row.command)}
			// The look runs once, apart from the pure policy (review 7).
			opts.lateOrdinaryOpen = lateOrdinaryLook(opts)
			mode, _, blocked := lateAnswerOutcome(opts, sp, row.tier)
			if mode != row.wantMode || blocked != row.wantBlocked {
				t.Fatalf("late mode=%q blocked=%v, want mode=%q blocked=%v", mode, blocked, row.wantMode, row.wantBlocked)
			}
		})
	}
}

func TestGAP0641OrdinaryTimeoutWarnsWhileNamedTargetStaysClosed(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, command string
		blocked       bool
	}{
		{"ordinary", "echo ready", false},
		{"ordinary env prefix", "FOO=bar echo ready", false},
		{"ordinary assignment then call", "FOO=bar; echo ready", false},
		{"ordinary colon list prefix", "LIST=a:b echo ready", false},
		{"named env prefix", "FOO=bar cat ~/.ssh/authorized_keys", true},
		{"named assigned value", "KEY=~/.ssh/authorized_keys echo ready", true},
		{"named colon list element", "LIST=a:~/.ssh/authorized_keys echo ready", true},
		{"home assignment", "HOME=/tmp cat .ssh/authorized_keys", true},
		{"named target", "cat ~/.ssh/authorized_keys", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(string(gap0641Payload(cwd, row.command)))
			})
			if got := nativeOutageBlocked(result); got != row.blocked {
				t.Fatalf("blocked=%v, want %v: code=%d stdout=%q stderr=%q", got, row.blocked, result.code, result.stdout, result.stderr)
			}
			if !row.blocked && !strings.Contains(result.stdout+result.stderr, "did not answer in time") {
				t.Fatalf("ordinary timeout did not warn: stdout=%q stderr=%q", result.stdout, result.stderr)
			}
		})
	}
}

// GAP-0641 review 7: a protected link reached through a process-relative
// /proc or /dev link is not ordinary; the hook cannot read that hop as the
// process that opens it does. An ordinary operand stays ordinary.
func TestGAP0641ProcessRelativeProtectedAliasIsNotOrdinary(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "project")
	state := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{cwd, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(state, "entry")
	if err := os.WriteFile(protected, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "notes"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	for _, command := range []string{"cat /proc/self/cwd/alias", "cat /proc/thread-self/cwd/alias",
		"cat /proc/self/root" + filepath.Join(cwd, "alias"), "cat /dev/fd/3"} {
		if ordinaryNoAnswerPayloadInHome(gap0641Payload(cwd, command), home) {
			t.Errorf("%q was accepted as an ordinary late call", command)
		}
	}
	if !ordinaryNoAnswerPayloadInHome(gap0641Payload(cwd, "cat notes"), home) {
		t.Error("an ordinary operand is no longer ordinary")
	}
}

// GAP-0641 review 7: the no-answer policy reads the tier and the payload
// only after the deadline is armed. A tier read that stalls past the
// deadline leaves the closed answer, as the stalled install look does; it
// does not hold the watchdog until the read returns and then allow.
func TestGAP0641StalledTierReadGivesTheClosedAnswer(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string {
			time.Sleep(1500 * time.Millisecond)
			return "open"
		}
		opts.Stdin = strings.NewReader(string(gap0641Payload(cwd, "echo ready")))
	})
	if !nativeOutageBlocked(result) {
		t.Fatalf("a stalled tier read was answered open: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}
