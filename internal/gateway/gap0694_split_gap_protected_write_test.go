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

// TestGAP0694SplitGapKeepsTheProtectedWrite: a call the per-command split
// cannot flatten (a parse gap: in an action that defines a function, a
// command whose name is not static, `"$@"`, `$r ~`, `$(echo return)`,
// `eval "$c"`, `$y`, `eval [ ... ]`) is never below its plain write when the
// call writes a protected file, in the default and strict packs
// (substrate-1:GAP-0694: `f(){ cd /tmp; "$@"; }; f cd && echo x >> .bashrc`
// from the home allowed at FU11 c8090b1056 and t6/fix-0690 6dee637f77, where
// rel 740c0de8fd alerts or blocks; GAP-0693 and GAP-0695: the same at rel).
// A mover that returns to a protected folder keeps its verdict, and the
// ordinary developer calls of the review (FIX-0690-RV O01-O16) and parse-gap
// calls that write project files stay an allow.
func TestGAP0694SplitGapKeepsTheProtectedWrite(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(project, "src"), filepath.Join(home, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{
		filepath.Join(project, ".git", "HEAD"):             "ref: refs/heads/main\n",
		filepath.Join(project, "go.mod"):                   "module x\n",
		filepath.Join(home, ".bashrc"):                     "x\n",
		filepath.Join(home, ".defenseclaw", "config.yaml"): "a: b\n",
	} {
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	rows := []struct{ name, command, plain string }{
		// GAP-0694 (FIX-0690-RV A05, A11, M1, M2, M4, A18).
		{"A05 var mover", "f(){ cd /tmp; $r ~; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"A05 tilde", "f(){ cd /tmp; $r ~; }; f && echo x >> ~/.bashrc", "echo x >> ~/.bashrc"},
		{"A11 subst return", "f(){ test -f .bashrc && $(echo return); cd /tmp; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"M1 args mover", "f(){ cd /tmp; \"$@\"; }; f cd && echo x >> .bashrc", "echo x >> .bashrc"},
		{"M2 semicolon", "f(){ cd /tmp; $r ~; }; f; echo x >> .bashrc", "echo x >> .bashrc"},
		{"M4 copy", "f(){ cd /tmp; $r ~; }; f && cp /tmp/x .bashrc", "cp /tmp/x .bashrc"},
		{"A18 eval mover", "f(){ cd /tmp; eval \"$c\"; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"zshrc args", "f(){ cd /tmp; \"$@\"; }; f cd && echo x >> .zshrc", "echo x >> .zshrc"},
		// GAP-0693 (FIX-0690-RV C01-C03).
		{"C01 var body", "f(){ $y; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"C02 var body uncalled", "f(){ $y; }; echo x >> .bashrc", "echo x >> .bashrc"},
		{"C03 var top level", "g(){ :; }; $y; echo x >> .bashrc", "echo x >> .bashrc"},
		// GAP-0695 (FIX-0690-RV B05).
		{"B05 eval bracket", "f(){ eval [ -e .bashrc ]; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		{"B05t eval test", "f(){ eval test -e .bashrc; }; f && echo x >> .bashrc", "echo x >> .bashrc"},
		// DefenseClaw state through a dynamic body (as G00).
		{"state args", "f(){ \"$@\"; }; f true && echo m > ~/.defenseclaw/config.yaml", "echo m > ~/.defenseclaw/config.yaml"},
	}
	// The returns of 041ba2d7f8 (FIX-0690-RV G01-G05): the plain form is G00.
	movers := []string{
		"cd ~/.defenseclaw && f(){ cd /x || return 0; }; f && echo m > config.yaml",
		"cd ~/.defenseclaw && f(){ cd /x || return; }; f && echo m > config.yaml",
		"cd ~/.defenseclaw && f(){ cd /x || return 1; }; f || echo m > config.yaml",
		"cd ~/.defenseclaw && f(){ cd /x || return 1; }; f; echo m > config.yaml",
		"cd ~/.defenseclaw && f(){ cd /x || return 1; }; f && echo m > config.yaml",
	}
	controls := []string{
		// FIX-0690-RV O01-O16.
		"die(){ echo \"$1\" >&2; exit 1; }; [ -f go.mod ] || die \"no go.mod\"; go build ./...",
		"f(){ [ -d node_modules ] || npm ci; }; f && npm test",
		"cleanup(){ [ -n \"$tmp\" ] && rm -rf \"$tmp\"; }; tmp=$(mktemp -d); trap cleanup EXIT; cp -r src \"$tmp\"/",
		"check(){ [ -z \"$(git status --porcelain)\" ]; }; check && git log -1",
		"f(){ [ -f \"$1\" ] && wc -l \"$1\"; }; f go.mod",
		"log(){ [ -n \"$V\" ] && echo \"$@\"; }; log hi; echo done > out.txt",
		"ensure(){ [ -d build ] || mkdir -p build; }; ensure && cd build && cmake ..",
		"f(){ [ -x ./configure ] && ./configure; }; f && make -j4",
		"retry(){ n=0; while [ $n -lt 3 ]; do \"$@\" && return 0; n=$((n+1)); sleep 1; done; return 1; }; retry go test ./...",
		"f(){ [ \"$1\" = a ] && return 0; cd src; }; f b && echo ok > out.txt",
		"f(){ test -d .git && return; cd /tmp; }; f && echo ok > out.txt",
		"usage(){ echo usage; }; [ $# -eq 0 ] && usage; ls -la",
		"f(){ [ -d .git ] && git status; }; f; rm -rf ./tmp-build",
		"f(){ [ -d ~/.cache/pip ] && du -sh ~/.cache/pip; }; f",
		"f(){ [ -d src ] && cd src; }; f && echo ok > notes.txt",
		"f(){ cd src || return 1; [ -f a.go ] && go vet .; }; f && echo ok > out.txt",
		// Parse-gap calls that write project files only.
		"f(){ \"$@\"; }; f make && echo ok > out.txt",
		"run(){ $CMD \"$@\"; }; run build > build.log 2>&1",
		"f(){ eval \"$c\"; }; f; echo done >> notes.txt",
		"q(){ \"$@\" >/dev/null 2>&1; }; q go version && cp go.mod /tmp/go.mod.bak",
		"retry(){ \"$@\" || \"$@\"; }; retry npm ci && echo ok > src/status.txt",
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0694-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, row := range rows {
			plain := decide(home, row.plain)
			if plain == "allow" {
				t.Errorf("%s %s: the plain form %q is allow, want alert or block", pack, row.name, row.plain)
			}
			if got := decide(home, row.command); rank[got] < rank[plain] {
				t.Errorf("%s %s: %q is %s; its plain form %q is %s", pack, row.name, row.command, got, row.plain, plain)
			}
		}
		plain := decide(home, "cd ~/.defenseclaw && echo m > config.yaml")
		for _, command := range movers {
			if got := decide(home, command); rank[got] < rank[plain] {
				t.Errorf("%s: %q is %s; its plain form is %s", pack, command, got, plain)
			}
		}
		for _, command := range controls {
			if got := decide(project, command); got != "allow" {
				t.Errorf("%s: control %q is %s, want allow", pack, command, got)
			}
		}
	}
}
