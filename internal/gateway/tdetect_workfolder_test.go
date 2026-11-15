// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCDFirstFormsGetTheVerdictOfTheOneStepForm is substrate-1:GAP-0327 widened
// by the 1.0.10 lead: every protected-write and protected-read rule judges its
// target AFTER the call's cd chain is resolved (actionfacts working_folder.go).
// For each target, the cd-first spellings (&&, ;, a subshell, an absolute cd, a
// two-step cd) must get the verdict the one-step spelling gets, in the five
// tiers, through the real Claude Code hook handler in a real project with a
// .git folder. The one-step verdict is the oracle (never hard-coded), plus the
// floor rows that pin what the oracle is: the git hook write, the shell
// profile, authorized_keys and the credential files are not allowed in strict.
type cdFirstTarget struct {
	name, dir, one, inner string
	// floor: one letter per tier (default, strict, permissive, managed,
	// managed-strict): S where the one-step form must not be a clean allow.
	floor string
}

// cdFirstTargets are the protected targets of the cd-first tests: the target,
// its folder, the one-step form and the form run in the folder.
var cdFirstTargets = []cdFirstTarget{
	{"git hook", ".git/hooks", "echo exit 0 > .git/hooks/pre-push", "echo exit 0 > pre-push", "ASAAS"},
	{"git hook post-checkout", ".git/hooks", "printf x > ./.git/hooks/post-checkout", "printf x > post-checkout", "ASAAS"},
	{"git config", ".git", "echo x >> .git/config", "echo x >> config", "ASAAS"},
	{"shell profile", "~", "echo x >> ~/.bashrc", "echo x >> .bashrc", "ASAAS"},
	{"authorized_keys", "~/.ssh", "echo k >> ~/.ssh/authorized_keys", "echo k >> authorized_keys", "ASAAS"},
	{"cron.d", "/etc/cron.d", "echo '* * * * * root /tmp/x' > /etc/cron.d/job", "echo '* * * * * root /tmp/x' > job", ""},
	{"systemd user unit", "~/.config/systemd/user", "echo x > ~/.config/systemd/user/evil.service", "echo x > evil.service", "ASAAS"},
	{"autostart", "~/.config/autostart", "echo x > ~/.config/autostart/a.desktop", "echo x > a.desktop", "ASAAS"},
	{"launch agent", "~/Library/LaunchAgents", "echo x > ~/Library/LaunchAgents/evil.plist", "echo x > evil.plist", "ASAAS"},
	{"defenseclaw state", "~/.defenseclaw", "echo x >> ~/.defenseclaw/config.yaml", "echo x >> config.yaml", "ASAAS"},
	{"defenseclaw hook", "~/.defenseclaw/hooks", "echo x > ~/.defenseclaw/hooks/h.sh", "echo x > h.sh", "ASAAS"},
	{"ssh key read", "~/.ssh", "cat ~/.ssh/id_rsa", "cat id_rsa", "ASAAS"},
	{"aws credentials read", "~/.aws", "cat ~/.aws/credentials", "cat credentials", "ASAAS"},
	{"aws credentials copy", "~/.aws", "cp ~/.aws/credentials /tmp/staged", "cp credentials /tmp/staged", "ASAAS"},
	{"kube config read", "~/.kube", "cat ~/.kube/config", "cat config", "ASAAS"},
	{"sudoers", "/etc", "echo x >> /etc/sudoers", "echo x >> sudoers", "ASAAS"},
	{"shadow read", "/etc", "cat /etc/shadow", "cat shadow", "ASAAS"},
}

func TestCDFirstFormsGetTheVerdictOfTheOneStepForm(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{
		filepath.Join(project, ".git", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"), filepath.Join(home, ".defenseclaw", "hooks"),
		filepath.Join(home, ".config", "systemd", "user"), filepath.Join(home, ".config", "autostart"),
		filepath.Join(home, "Library", "LaunchAgents"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	letter := map[string]string{"allow": "A", "alert": "L", "block": "B"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		verdict := func(command string) string {
			out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "td-wf-" + p.name, "cwd": project,
				"tool_name": "Bash", "tool_use_id": "tu-" + command, "tool_input": map[string]any{"command": command},
			})
			action, _ := out["action"].(string)
			return letter[action]
		}
		pi := 0
		for i, q := range gap0437Packs {
			if q.name == p.name {
				pi = i
			}
		}
		for _, tg := range cdFirstTargets {
			dir := strings.ReplaceAll(tg.dir, "~", home)
			if !strings.HasPrefix(dir, "/") {
				dir = project + "/" + dir
			}
			oracle := verdict(tg.one)
			if floor := tg.floor; floor != "" && floor[pi] == 'S' && oracle == "A" {
				t.Errorf("%s %s: the one-step form %q is a clean allow, want a finding", p.name, tg.name, tg.one)
			}
			forms := map[string]string{
				"and":       "cd " + tg.dir + " && " + tg.inner,
				"semicolon": "cd " + tg.dir + "; " + tg.inner,
				"subshell":  "(cd " + tg.dir + " && " + tg.inner + ")",
				"absolute":  "cd " + dir + " && " + tg.inner,
				"two steps": "cd " + tg.dir + " && cd . && " + tg.inner,
			}
			for name, command := range forms {
				if got := verdict(command); got != oracle {
					t.Errorf("%s %s (%s): %q is %s, the one-step form %q is %s", p.name, tg.name, name, command, got, tg.one, oracle)
				}
			}
		}
		// A link to /dev/null masks a unit (turns it off); it is no persistence.
		for _, command := range []string{
			"ln -sf /dev/null /etc/systemd/system/enforce-ci-config.timer", "cd /etc/systemd/system && ln -sf /dev/null static.path",
			"ln -sf /dev/null ~/.config/systemd/user/x.service",
		} {
			if got := verdict(command); got != "A" {
				t.Errorf("%s: masking link %q is %s, want allow", p.name, command, got)
			}
		}
		// Controls: a cd that leaves the protected folder, and a folder that is not the target's.
		for _, command := range []string{
			"cd src && echo ok > out.txt", "cd .git/hooks && cd /tmp && echo x > pre-push", "cd /tmp && echo x > .bashrc",
			"cd ~ && cd proj && echo x > .bashrc", "cd .git/hooks | cat; echo x > pre-push",
			"cd .git/hooks && echo x > pre-push.sample",
		} {
			if got := verdict(command); got == "B" {
				t.Errorf("%s control %q is blocked", p.name, command)
			}
		}
	}
}

// cdFirstFixture is the project of the cd-first tests: a home with the
// protected folders and a project with a .git folder.
func cdFirstFixture(t *testing.T) (home, project string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "home", "alice")
	project = filepath.Join(home, "proj")
	for _, dir := range []string{
		filepath.Join(project, ".git", "hooks"), filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
		filepath.Join(home, ".kube"), filepath.Join(home, ".defenseclaw", "hooks"),
		filepath.Join(home, ".config", "systemd", "user"), filepath.Join(home, ".config", "autostart"),
		filepath.Join(home, "Library", "LaunchAgents"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, project
}

var cdFirstRank = map[string]int{"A": 0, "L": 1, "B": 2}

// cdFirstVerdict is the verdict letter (A allow, L alert, B block) of a Bash
// call through the Claude Code hook handler.
func cdFirstVerdict(t *testing.T, a *APIServer, session, cwd, command string) string {
	t.Helper()
	out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
		"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": "tu-" + command, "tool_input": map[string]any{"command": command},
	})
	action, _ := out["action"].(string)
	return map[string]string{"allow": "A", "alert": "L", "block": "B"}[action]
}

// TestCDThatMayNotRunKeepsTheHookFolderReading is rel-1-0-10:GAP-0869: a cd
// that fails (a missing folder, a file) or may not run (behind false &&, ||,
// a test, in a group, in the background), before a ; or a newline, leaves
// the later statement in the hook's folder as well. With the hook in each
// target's folder, every such prefix in front of the in-folder form gets at
// least the verdict of the form alone, in the five tiers (the review's
// td327rev class A rows, built from the same target table).
func TestCDThatMayNotRunKeepsTheHookFolderReading(t *testing.T) {
	home, project := cdFirstFixture(t)
	prefixes := map[string]string{
		"nonexist":     "cd /nonexistent-td327; ",
		"nonexist-nl":  "cd /nonexistent-td327\n",
		"notadir":      "cd /dev/null; ",
		"nonexist-rel": "cd no-such-dir-td327; ",
		"cdpath-miss":  "CDPATH=/nonexistent-td327 cd zz-td327; ",
		"false-and":    "false && cd /tmp; ",
		"test-d":       "test -d /nonexistent-td327 && cd /nonexistent-td327; ",
		"brace-false":  "{ false && cd /tmp; }; ",
		"true-or":      "true || cd /tmp; ",
		"or-nonexist":  "cd /nonexistent-td327 || true; ",
		"background":   "cd /tmp & ",
		"if-false":     "if false; then cd /tmp; fi; ",
		"subshell":     "(cd /tmp); ",
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		for _, tg := range cdFirstTargets {
			dir := strings.ReplaceAll(tg.dir, "~", home)
			if !strings.HasPrefix(dir, "/") {
				dir = project + "/" + dir
			}
			oracle := cdFirstVerdict(t, a, "td-mnr-"+p.name, dir, tg.inner)
			for name, prefix := range prefixes {
				if got := cdFirstVerdict(t, a, "td-mnr-"+p.name, dir, prefix+tg.inner); cdFirstRank[got] < cdFirstRank[oracle] {
					t.Errorf("%s %s (%s): %q in the target folder is %s, the form alone is %s", p.name, tg.name, name, prefix+tg.inner, got, oracle)
				}
			}
		}
	}
}
