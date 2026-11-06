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
