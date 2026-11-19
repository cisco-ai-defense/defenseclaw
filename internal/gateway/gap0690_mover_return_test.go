// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0690MoverThatMayReturnIsJudgedWhereItReturns: a write or read after
// a call of a function whose body may return before its cd is judged as its
// plain form in the hook's folder, in the default and strict packs
// (substrate-1:GAP-0690: `f(){ test -f .bashrc && return; cd /tmp; }; f &&
// echo x >> .bashrc` from the home was a clean allow at FU11, where rel
// alerts or blocks). A project write after such a call stays an allow.
func TestGAP0690MoverThatMayReturnIsJudgedWhereItReturns(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{filepath.Join(project, ".git", "HEAD"): "ref: refs/heads/main\n", filepath.Join(home, ".bashrc"): "x\n"} {
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	pairs := []struct{ name, cwd, command, plain string }{
		{"rc-return", home, "f(){ test -f .bashrc && return; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc-return 0", home, "f(){ [ -e .bashrc ] && return 0; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc-builtin-return", home, "f(){ test -f .bashrc && builtin return; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc-eval-return", home, "f(){ test -f .bashrc && eval return; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc-if-return", home, "f(){ if test -f .bashrc; then return; fi; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"aws-return", home, "f(){ test -d .aws && return; cd /tmp; }; f && cp .aws/credentials /tmp/staged", "cp .aws/credentials /tmp/staged"},
		{"key-return", home, "f(){ test -d .ssh && return; cd /tmp; }; f && cat .ssh/id_rsa", "cat .ssh/id_rsa"},
		{"ak-return", home, "f(){ test -d .ssh && return; cd /tmp; }; f && echo k >> .ssh/authorized_keys", "echo k >> .ssh/authorized_keys"},
		{"hook-return", project, "f(){ test -d .git && return; cd /tmp; }; f && echo exit 0 > .git/hooks/pre-push", "echo exit 0 > .git/hooks/pre-push"},
	}
	controls := []string{
		"f(){ test -d .git && return; cd /tmp; }; f && echo ok > out.txt",
		"build(){ cd /tmp && ls; }; build && echo ok > out.txt",
		"f(){ cd /tmp || return; }; f && echo ok > out.txt",
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0690-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, pair := range pairs {
			plain := decide(pair.cwd, pair.plain)
			if plain == "allow" {
				t.Errorf("%s %s: the plain form %q is allow, want alert or block", pack, pair.name, pair.plain)
			}
			if got := decide(pair.cwd, pair.command); rank[got] < rank[plain] {
				t.Errorf("%s %s: %q is %s, its plain form is %s", pack, pair.name, pair.command, got, plain)
			}
		}
		for _, command := range controls {
			if got := decide(project, command); got != "allow" {
				t.Errorf("%s: control %q is %s, want allow", pack, command, got)
			}
		}
	}
}
