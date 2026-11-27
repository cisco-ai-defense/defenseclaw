// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0697RelativeHomeWriteIsItsHomeSpelling: a write, append or delete
// whose relative operand the call's folder resolves to a file in the caller's
// home is judged as the same command with the file spelled from the home, in
// the default and strict packs (substrate-1:GAP-0697: from the home,
// `cp /tmp/x .aws/credentials` and `echo x > .aws/credentials` allowed at rel
// 740c0de8fd, FU11 c8090b1056 and t6/fix-0690 8e3ec11b61, where
// `cp /tmp/x ~/.aws/credentials` blocks with PATH-AWS-CREDS). The text-pattern
// path rules (PATH-AWS-CREDS, PATH-KUBE, PATH-DOCKER, PATH-GIT-CREDS,
// PATH-NETRC, PATH-NPMRC, PATH-PYPIRC, PATH-GNUPG, PATH-AWS-CONFIG and the
// cloud credential files) read only a home spelling; the rules that read the
// path facts (SSH, shell profiles, DefenseClaw state, agent hook config) were
// already equal and stay so. The FIX-0690-GATES rows Z6 and Z6f (the same
// copy after a mover that may return in the home) are never below rel, and
// writes of ordinary files, or of the same names outside the home, stay as
// they were.
func TestGAP0697RelativeHomeWriteIsItsHomeSpelling(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	targets := []string{
		".aws/credentials", ".aws/config", ".kube/config", ".docker/config.json", ".git-credentials",
		".npmrc", ".pypirc", ".netrc", ".gnupg/gpg.conf", ".config/gh/hosts.yml",
		".ssh/authorized_keys", ".ssh/config", ".bashrc", ".zshrc", ".defenseclaw/config.yaml",
		".claude/settings.json",
	}
	for _, name := range append([]string{"proj/main.go", "proj/.aws/credentials", "notes.txt"}, targets...) {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	forms := []string{"cp /tmp/x %s", "echo x > %s", "echo x >> %s", "tee %s </tmp/x", "mv /tmp/x %s", "install /tmp/x %s", "rm %s"}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	type verdict struct {
		action string
		rules  string
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(cwd, command string) verdict {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0697-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = cwd
			got := callAgentHookForTest(t, handler, ev)
			rules := slices.Clone(got.RuleIDs)
			slices.Sort(rules)
			return verdict{got.Action, strings.Join(slices.Compact(rules), ",")}
		}
		// Each relative spelling from the home is its ~/ spelling.
		for _, target := range targets {
			for _, form := range forms {
				relative := strings.ReplaceAll(form, "%s", target)
				spelled := strings.ReplaceAll(form, "%s", "~/"+target)
				want := decide(home, spelled)
				if got := decide(home, relative); got != want {
					t.Errorf("%s: %q is %v; its home spelling %q is %v", pack, relative, got, spelled, want)
				}
			}
		}
		// The same file from another folder of the home, and after a cd.
		for _, row := range []struct{ cwd, command, spelled string }{
			{home, "cd .aws && cp /tmp/x credentials", "cd .aws && cp /tmp/x ~/.aws/credentials"},
			{home, "cd .aws; echo x > credentials", "cd .aws; echo x > ~/.aws/credentials"},
			{filepath.Join(home, ".aws"), "cp /tmp/x credentials", "cp /tmp/x ~/.aws/credentials"},
			{filepath.Join(home, ".aws"), "echo x >> ./credentials", "echo x >> ~/.aws/credentials"},
			{filepath.Join(home, "proj"), "echo x > ../.aws/credentials", "echo x > ~/.aws/credentials"},
			{filepath.Join(home, "proj"), "cd .. && cp /tmp/x .git-credentials", "cp /tmp/x ~/.git-credentials"},
			{home, "cp /tmp/x './.aws//credentials'", "cp /tmp/x ~/.aws/credentials"},
			{home, "dd if=/tmp/x of=.aws/credentials", "dd if=/tmp/x of=~/.aws/credentials"},
		} {
			want := decide(home, row.spelled)
			if want.action != "block" {
				t.Errorf("%s: the home spelling %q is %v, want block", pack, row.spelled, want)
			}
			if got := decide(row.cwd, row.command); got.action != want.action {
				t.Errorf("%s: %q in %s is %v; its home spelling %q is %v", pack, row.command, row.cwd, got, row.spelled, want)
			}
		}
		// FIX-0690-GATES Z6 and Z6f: the copy after a mover that may return
		// in the home is never below the same write spelled from the home
		// (rel alerts in default and blocks in strict, through the unresolved
		// mover folder; the copy from the home blocks).
		for _, row := range []struct{ command, plain string }{
			{"f(){ test -f .aws/credentials && return; cd /tmp; }; f && cp /tmp/x .aws/credentials", "cp /tmp/x ~/.aws/credentials"},
			{"f(){ [ -f .aws/credentials ] && return; cd /tmp; }; f && cp /tmp/x .aws/credentials", "cp /tmp/x ~/.aws/credentials"},
			{"f(){ test -f .npmrc && return; cd /tmp; }; f && echo x >> .npmrc", "echo x >> ~/.npmrc"},
		} {
			plain := decide(home, row.plain)
			if plain.action == "allow" {
				t.Errorf("%s: the home spelling %q is allow, want alert or block", pack, row.plain)
			}
			if got := decide(home, row.command); rank[got.action] < rank[plain.action] {
				t.Errorf("%s: %q is %v; the write from the home %q is %v", pack, row.command, got, row.plain, plain)
			}
		}
		// Ordinary files, and the same names outside the home, stay allowed.
		for _, row := range []struct{ cwd, command string }{
			{home, "cp /tmp/x proj/main.go"},
			{home, "echo x > notes.txt"},
			{home, "echo x >> notes.txt && rm notes.txt"},
			{home, "cp /tmp/x proj/.aws/credentials"},
			{home, "cd /tmp && cp /tmp/x .aws/credentials"},
			{home, "echo x > .aws/config"},
			{filepath.Join(home, "proj"), "echo x > .npmrc"},
			{filepath.Join(home, "proj"), "cp /tmp/x .aws/credentials"},
			{"/tmp", "cp /tmp/x .aws/credentials"},
			{"/tmp", "echo x > .git-credentials"},
		} {
			if got := decide(row.cwd, row.command); got.action != "allow" {
				t.Errorf("%s: control %q in %s is %v, want allow", pack, row.command, row.cwd, got)
			}
		}
	}
}

// TestRelativeHomeWritesAsTilde: the scan text spells a relative operand the
// call writes in the home as its ~/ path, and leaves every other word, a read,
// a write outside the home and a reading in a folder the command may not run
// in as written (substrate-1:GAP-0697).
func TestRelativeHomeWritesAsTilde(t *testing.T) {
	home := "/home/alice"
	for _, row := range []struct{ cwd, command, want string }{
		{home, "cp /tmp/x .aws/credentials", "cp /tmp/x ~/.aws/credentials"},
		{home, "echo .aws/credentials > .aws/credentials", "echo ~/.aws/credentials > ~/.aws/credentials"},
		// A quoted spelling is respelled whole: a quoted ~ is no home
		// (substrate-1:GAP-0700).
		{home, "cp /tmp/x '.aws/credentials'", "cp /tmp/x ~/.aws/credentials"},
		{home, `cp /tmp/x ".aws/credentials"`, "cp /tmp/x ~/.aws/credentials"},
		{home, `cp /tmp/x .aws/"credentials"`, "cp /tmp/x ~/.aws/credentials"},
		{home, `echo x > ".npmrc"`, "echo x > ~/.npmrc"},
		{home, `echo ".npmrc" > .npmrc`, "echo ~/.npmrc > ~/.npmrc"},
		{home, `cp /tmp/x ".aws/$f"`, `cp /tmp/x ".aws/$f"`},
		{home, "dd if=/tmp/x of=.npmrc", "dd if=/tmp/x of=~/.npmrc"},
		{home, "rm .netrc", "rm ~/.netrc"},
		{home + "/.aws", "tee credentials </tmp/x", "tee ~/.aws/credentials </tmp/x"},
		{home + "/proj", "echo x >> ../.git-credentials", "echo x >> ~/.git-credentials"},
		{home, "cp /tmp/credentials x/credentials.bak", "cp /tmp/credentials ~/x/credentials.bak"},
		// Reads, writes outside the home, and spelled operands are unchanged.
		{home, "cat .aws/credentials", "cat .aws/credentials"},
		{home, "cp .npmrc /tmp/npmrc", "cp .npmrc /tmp/npmrc"},
		{"/tmp", "cp /tmp/x .aws/credentials", "cp /tmp/x .aws/credentials"},
		{home, "cp /tmp/x ~/.aws/credentials", "cp /tmp/x ~/.aws/credentials"},
		{home, "echo x > /home/alice/.npmrc", "echo x > /home/alice/.npmrc"},
		// A partial call is left to the pass of each simple command.
		{home, "cd .aws && cp /tmp/x credentials", "cd .aws && cp /tmp/x credentials"},
	} {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: home})
		if got := relativeHomeWritesAsTilde(row.command, row.command, facts); got != row.want {
			t.Errorf("%q in %s: scan text %q, want %q", row.command, row.cwd, got, row.want)
		}
	}
}
