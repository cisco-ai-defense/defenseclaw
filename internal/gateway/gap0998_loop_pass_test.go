// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0998GuestLoopPassRunsTheBodyAfterTheCd: in the copy-mode actor,
// a statement of a loop body that runs before a cd of the same body runs in
// the folder of that cd on the next pass, so an unread command there may
// call a function the first pass declared, in the folder the cd left. Such
// a loop gets the verdict and rules of the same write called after the cd
// (refers), while a loop a top-level break ends after one pass, and the
// benign loops, keep the laptop verdict (substrate-1 GAP-0998, SEC10-K rows
// K04 and K12).
func TestGAP0998GuestLoopPassRunsTheBodyAfterTheCd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	const body = "g() { echo m > config.yaml; }"
	refers := "for i in 1 2; do $CMD; " + body + "; done; cd ~/.defenseclaw && g"
	later := []string{
		"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; done",
		"until [ -f x ]; do $CMD; " + body + "; cd ~/.defenseclaw; done",
		"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; [ -f y ] && break; done",
		"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; [ -f y ] && continue; break; done",
	}
	laptop := []string{
		"until false; do $CMD; " + body + "; cd ~/.defenseclaw; break; done",
		"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break; done",
		"for i in 1 2; do " + body + "; $CMD; done; cd ~/.defenseclaw && ls",
		body + "; for i in 1 2; do $CMD; done; cd ~/.defenseclaw && ls",
		"h() { $CMD; }; for i in 1 2; do h; " + body + "; done; cd ~/.defenseclaw && ls",
		"for d in a b; do ls; cd src; done",
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, "claudecode", pack)
			home := filepath.Join(t.TempDir(), "home", "alice")
			for _, dir := range []string{"src", ".defenseclaw"} {
				if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = pack
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			binding := sandboxTestBinding("claudecode")
			actor := withProfilePath(withAuthenticatedHookConnector(sandboxauth.WithRequest(context.Background(), binding, nil), binding.Connector), profilePathHook)
			wa, wr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, refers)
			if wa == "allow" || !slices.Contains(wr, "tamper.detector_state_write") {
				t.Fatalf("reference %q: actor %s %v; want a state-write finding", refers, wa, wr)
			}
			for _, command := range later {
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, command)
				if ca != wa || !slices.Equal(cr, wr) {
					t.Errorf("%q: actor %s %v; want %s %v as for the call after the cd", command, ca, cr, wa, wr)
				}
			}
			for _, command := range laptop {
				la, lr := gap0304Verdict(t, api, context.Background(), home, command)
				ca, cr := gap0304Verdict(t, api, actor, sandboxauth.SandboxHome, command)
				if ca != la || !slices.Equal(cr, lr) || strings.Contains(command, "break") && la != "allow" {
					t.Errorf("%q: actor %s %v, laptop %s %v", command, ca, cr, la, lr)
				}
			}
		})
	}
}

// TestGAP0998GuestScriptCallsLoopOnce: a loop whose body has a top-level
// break runs it once, so no statement of it runs after the cd that follows
// it; a break that may not run, a continue or a function named break keeps
// the later pass (substrate-1 GAP-0998).
func TestGAP0998GuestScriptCallsLoopOnce(t *testing.T) {
	const body = "g() { echo m > config.yaml; }"
	for _, row := range []struct {
		command string
		after   bool
	}{
		{"until false; do $CMD; " + body + "; cd ~/.defenseclaw; break; done", false},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break 1; done", false},
		{"while read l; do $CMD; " + body + "; break; cd ~/.defenseclaw; done", false},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; [ -f y ] && break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break & done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break > x; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break $N; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; [ -f y ] && continue; break; done", true},
		{"break() { :; }; for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; break; done", true},
		{"for j in 1 2; do for i in 1; do $CMD; " + body + "; cd ~/.defenseclaw; break; done; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; builtin continue; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; command continue; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; command -p continue; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; builtin $C; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; 'continue'; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; $C; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; eval $C; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; source x; break; done", true},
		{"for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; n; break; done", false}, // a static call: the loop still runs once
		{"n() { continue; }; for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; n; break; done", true},
		{"n() { $C; }; for i in 1 2; do $CMD; " + body + "; cd ~/.defenseclaw; n; break; done", true},
	} {
		calls, _ := guestScriptCalls(row.command, "/home/alice")
		write, cd := -1, -1
		for _, call := range calls {
			switch {
			case strings.HasPrefix(call.text, "echo m"):
				write = call.at
			case strings.HasPrefix(call.text, "cd ~/.defenseclaw"):
				cd = call.start
			}
		}
		if write < 0 || cd < 0 {
			t.Fatalf("%q: no write or cd in %+v", row.command, calls)
		}
		if got := write > cd; got != row.after {
			t.Errorf("%q: write at %d, cd at %d: after = %v, want %v", row.command, write, cd, got, row.after)
		}
	}
}
