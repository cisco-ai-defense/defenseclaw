// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentHookConfigOwnedTargetSpellings pins that an installed DefenseClaw
// hook executable or bridge is protected by every spelling of the target the
// literal form is protected by (brace list, move onto itself with a suffix,
// folder removal, glob, find and rsync emptying, glob loop), and that the
// ordinary neighbours of those files stay allowed. A Git pathspec glob in
// another repository reaches only the registration files that repository has.
func TestAgentHookConfigOwnedTargetSpellings(t *testing.T) {
	h := newGAP0048Home(t)
	other := filepath.Join(h.ext, "other")
	for path, body := range map[string]string{
		filepath.Join(h.home, ".local", "bin", "defenseclaw-hook-user"): "#!/bin/sh\n",
		filepath.Join(h.home, ".local", "bin", "defenseclaw-hook-post"): "#!/bin/sh\n",
		filepath.Join(h.home, ".local", "bin", "other-tool"):            "#!/bin/sh\n",
		filepath.Join(other, ".git", "HEAD"):                            "ref: refs/heads/main\n",
		filepath.Join(other, "a.json"):                                  "{}\n",
		filepath.Join(h.ext, "empty", "keep"):                           "",
		filepath.Join(h.home, ".defenseclaw", "hooks", "codex-hook.sh"): "#!/bin/sh\n",
		filepath.Join(h.project, "notes.txt.bak"):                       "x\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if strings.Contains(path, "/.local/bin/") {
			mode = 0o755
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	empty := filepath.Join(h.ext, "empty") + "/"
	type row struct {
		name, command string
		block         bool
	}
	rows := []row{
		{"brace list removes both hooks", `rm ~/.local/bin/defenseclaw-hook-{user,post}`, true},
		{"brace move aside of one hook", `mv ~/.local/bin/defenseclaw-hook-user{,.bak}`, true},
		{"brace move aside of bridge folder", `mv ~/.config/opencode/plugins{,.bak}`, true},
		{"glob loop removes hooks", `for f in ~/.local/bin/defenseclaw-hook-*; do rm -f "$f"; done`, true},
		{"folder holding hooks removed", `rm -rf ~/.local/bin`, true},
		{"glob empties bridge folder", `rm -rf ~/.config/opencode/plugins/*`, true},
		{"find deletes bridge folder", `find ~/.config/opencode/plugins -delete`, true},
		{"rsync empties bridge folder", `rsync -a --delete ` + empty + ` ~/.config/opencode/plugins/`, true},
		{"install over hook script", `install -m755 /bin/true ~/.defenseclaw/hooks/codex-hook.sh`, true},
		{"dd over hook executable", `printf x | dd of=~/.local/bin/defenseclaw-hook-post`, true},
		{"folder holding hook scripts moved", `mv ~/.defenseclaw /tmp/aside-dir`, true},
		{"install of another tool", `install -m755 build/tool ~/.local/bin/other-tool`, false},
		{"dd to a scratch file", `dd if=/dev/zero of=/tmp/scratch-file bs=1 count=1`, false},
		{"literal removal", `rm ~/.local/bin/defenseclaw-hook-user`, true},
		{"other tool removal", `rm ~/.local/bin/other-tool`, false},
		{"brace backup of notes", `cp notes.txt{,.orig}`, false},
		{"brace move of notes", `mv notes.txt{,.moved}`, false},
		{"unrelated cache removal", `rm -rf ~/.cache/tool`, false},
		{"brace list of other tools", `rm ~/.local/bin/other-{tool,thing}`, false},
		{"git glob checkout in a repo without registration files", `cd ` + other + ` && git checkout HEAD -- "*.json"`, false},
		{"glob loop re-modes hooks", `for f in ~/.local/bin/defenseclaw-hook-*; do chmod 000 "$f"; done`, true},
		{"one-item loop re-modes a hook", `for f in ~/.local/bin/defenseclaw-hook-user; do chmod 000 "$f"; done`, true},
		{"glob loop overwrites hooks", `for f in ~/.local/bin/defenseclaw-hook-*; do echo x > "$f"; done`, true},
		{"glob loop truncates hooks", `for f in ~/.local/bin/defenseclaw-hook-*; do : > "$f"; done`, true},
		{"loop re-modes other tools", `for f in ~/.local/bin/other-*; do chmod 755 "$f"; done`, false},
		{"loop overwrites other tools", `for f in ~/.local/bin/other-*; do echo x > "$f"; done`, false},
		{"install of another tool into the bin folder", `install -m755 build/tool ~/.local/bin/`, false},
		{"install of another tool into the bin folder without slash", `install -m755 build/tool ~/.local/bin`, false},
		{"install of another tool with a target folder", `install -t ~/.local/bin build/tool`, false},
		{"install of a hook-named file into the bin folder", `install -m755 build/defenseclaw-hook-user ~/.local/bin/`, true},
		{"perl with a module option reads a hook", `perl -MFile::Spec -e 'print while <>' ~/.local/bin/defenseclaw-hook-user`, false},
		{"perl include option reads a hook", `perl -Ilib/inc -ne 'print' ~/.local/bin/defenseclaw-hook-user`, false},
		{"perl in place edit of a hook", `perl -pi -e 's/a/b/' ~/.local/bin/defenseclaw-hook-user`, true},
		{"perl in place edit with a backup suffix", `perl -pi.bak -e 's/a/b/' ~/.local/bin/defenseclaw-hook-user`, true},
		{"perl in place option before the code option", `perl -i -pe 's/a/b/' ~/.local/bin/defenseclaw-hook-user`, true},
	}
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.name
	}
	forEachHookConfigCell(t, "claudecode", hookConfigBalancedAndStrictManaged, names, func(t *testing.T, judge hookConfigJudge, cell hookConfigCell, i int) {
		r := rows[i]
		want := "allow"
		// The state tree is outside the agent hook config rule: a managed
		// install keeps it with its file permissions, a per-user one with the
		// state rules.
		if r.block && (!cell.managed || r.name != "install over hook script" && r.name != "folder holding hook scripts moved") {
			want = "block"
		}
		got := judge(h.project, cell.managed, "Bash", map[string]any{"command": r.command})
		if action := hookConfigAction(got); action != want {
			t.Errorf("%s: got %s, want %s: %s", r.command, action, want, strings.TrimSpace(got))
		}
	})
}

// TestAgentHookConfigGitWorktreeFromEnvironment pins that GIT_WORK_TREE and
// GIT_DIR before git name the worktree the way --work-tree does.
func TestAgentHookConfigGitWorktreeFromEnvironment(t *testing.T) {
	h := newGAP0048Home(t)
	other := filepath.Join(h.ext, "other")
	if err := os.MkdirAll(filepath.Join(other, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	guard := newAgentHookConfigGuard(h.ext, h.home)
	for _, tc := range []struct {
		name string
		argv []string
		want bool
	}{
		{"work tree holds a registration file", []string{"GIT_WORK_TREE=" + h.project, "git", "reset", "--hard"}, true},
		{"git dir of that tree", []string{"GIT_DIR=" + filepath.Join(h.project, ".git"), "git", "reset", "--hard"}, true},
		{"work tree without one", []string{"GIT_WORK_TREE=" + other, "git", "reset", "--hard"}, false},
		{"no repository at all", []string{"git", "reset", "--hard"}, false},
	} {
		if got := agentHookConfigGitTarget(tc.argv, guard) != ""; got != tc.want {
			t.Errorf("%s: reached %v, want %v", tc.name, got, tc.want)
		}
	}
}
