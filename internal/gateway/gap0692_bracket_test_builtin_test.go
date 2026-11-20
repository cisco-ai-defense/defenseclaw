// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0692BracketTestInAFunctionKeepsTheProtectedWrite: a `[ ... ]` test
// in an action that defines a function is judged as its `test` spelling and
// never below the plain write, in the default and strict packs
// (substrate-1:GAP-0692: `f(){ [ -e .bashrc ]; }; f && echo x >> ~/.bashrc`
// was a clean allow at rel 740c0de8fd, FU11 and t6/fix-0690, while the
// `test -e` form alerts). Ordinary writes after such a call stay an allow.
func TestGAP0692BracketTestInAFunctionKeepsTheProtectedWrite(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{
		filepath.Join(project, ".git", "HEAD"):     "ref: refs/heads/main\n",
		filepath.Join(home, ".bashrc"):             "x\n",
		filepath.Join(home, ".aws", "credentials"): "[default]\n",
	} {
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	// testForm spells every bracket test of command with the test builtin.
	testForm := func(command string) string {
		command = strings.NewReplacer("[[ ", "test ", " ]]", "", "[ ", "test ", " ]", "").Replace(command)
		return command
	}
	rows := []struct{ name, command, plain string }{
		{"rc", "f(){ [ -e .bashrc ]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc tilde", "f(){ [ -e .bashrc ]; }; f && echo x >> ~/.bashrc", "echo x >> ~/.bashrc"},
		{"rc return", "f(){ [ -e .bashrc ] && return 0; cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc return tilde", "f(){ [ -e .bashrc ] && return 0; cd /tmp; }; f && echo x >> ~/.bashrc", "echo x >> ~/.bashrc"},
		{"zshrc and", "f(){ [ -e .bashrc ] && :; }; f && echo x >> .zshrc", "echo x >> .zshrc"},
		{"profile negated", "f(){ ! [ -e .bashrc ]; }; f && echo x >> .profile", "echo x >> .profile"},
		{"rc double bracket", "f(){ [[ -e .bashrc ]]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc nested", "f(){ g(){ [ -e .bashrc ]; }; g; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc command", "f(){ command [ -e .bashrc ]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc top level", "g(){ :; }; [ -e .bashrc ]; echo x >> .bashrc", "echo x >> .bashrc"},
		{"rc copy", "f(){ [ -f /tmp/x ]; }; f && cp /tmp/x .bashrc", "cp /tmp/x .bashrc"},
		{"aws copy", "f(){ [ -e .aws/credentials ]; }; f && cp .aws/credentials /tmp/staged", "cp .aws/credentials /tmp/staged"},
		{"hook write", "f(){ [ -d .git ]; }; f && echo exit 0 > .git/hooks/pre-push", "echo exit 0 > .git/hooks/pre-push"},
	}
	controls := []string{
		"f(){ [ -e .bashrc ]; }; f && echo x >> notes.txt",
		"f(){ [ -d .git ] && echo yes; }; f",
		"f(){ [ -d sub ] || mkdir sub; }; f && echo ok > sub/out.txt",
		"g(){ :; }; [ -n \"$HOME\" ] && echo ok > out.txt",
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0692-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, row := range rows {
			cwd := home
			if strings.Contains(row.plain, ".git/") {
				cwd = project
			}
			plain := decide(cwd, row.plain)
			if plain == "allow" {
				t.Errorf("%s %s: the plain form %q is allow, want alert or block", pack, row.name, row.plain)
			}
			twin := decide(cwd, testForm(row.command))
			got := decide(cwd, row.command)
			if rank[got] < rank[plain] || rank[got] < rank[twin] {
				t.Errorf("%s %s: %q is %s; its plain form is %s, its test form %q is %s", pack, row.name, row.command, got, plain, testForm(row.command), twin)
			}
		}
		for _, command := range controls {
			if got := decide(project, command); got != "allow" {
				t.Errorf("%s: control %q is %s, want allow", pack, command, got)
			}
		}
	}
}
