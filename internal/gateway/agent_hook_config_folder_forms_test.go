// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAgentHookConfigFolderAndRepositoryShellForms pins the shell verdicts for
// calls that reach an agents config folder or rewrite a repositorys
// registration files without naming them: a folder removal, move, extraction
// or find deletion is possible (an alert in the balanced default, a block
// under strict), the DefenseClaw bridge file named literally or through a
// folder change is blocked, and ordinary history cleanup, backups and Git
// work that leaves the registration files alone stay allowed.
func TestAgentHookConfigFolderAndRepositoryShellForms(t *testing.T) {
	h := newGAP0048Home(t)
	if err := os.MkdirAll(filepath.Join(h.project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.ToSlash(filepath.Join(h.ext, "x.tar"))
	rows := []hookConfigShellRow{
		{"cursor folder removed", `rm -rf ~/.cursor`, "possible"},
		{"codex folder moved in a nested shell", `bash -c "mv ~/.codex /tmp/codex-old"`, "possible"},
		{"find deletes in the claude folder", `find ~/.claude -name settings.json -delete`, "possible"},
		{"archive extracted into the claude folder", `tar -xf ` + archive + ` -C ~/.claude`, "possible"},
		{"claude settings made unreadable", `chmod 000 ~/.claude/settings.json`, "possible"},
		{"git am", `git am fix.mbox`, "possible"},
		{"git cherry-pick", `git cherry-pick abc1234`, "possible"},
		{"git merge", `git merge feature`, "possible"},
		{"git pull with a pager option", `git --no-pager pull`, "possible"},
		{"git revert from another folder", `git -C . revert HEAD`, "possible"},
		{"bridge file removed", `rm ~/.config/opencode/plugins/defenseclaw.js`, "block"},
		{"bridge file removed after a folder change", `cd ~/.config/opencode/plugins && rm defenseclaw.js`, "block"},
		{"bridge file removed in a nested shell", `dash -lxc 'rm ~/.config/opencode/plugins/defenseclaw.js'`, "block"},
		{"history of the claude folder removed", `rm -rf ~/.claude/projects/old-proj`, "allow"},
		{"todo glob of the claude folder removed", `rm -f ~/.claude/todos/*.json`, "allow"},
		{"claude folder copied out", `cp -r ~/.claude /tmp/claude-copy`, "allow"},
		{"claude settings copied to a backup", `cp ~/.claude/settings.json ~/settings.backup.json`, "allow"},
		{"claude settings backed up beside them", `cp .claude/settings.json .claude/settings.json.bak`, "allow"},
		{"claude settings filtered to a scratch file", `jq '.model="opus"' ~/.claude/settings.json > /tmp/s.json`, "allow"},
		{"project command file written", `mkdir -p .claude/commands && echo x > .claude/commands/review.md`, "allow"},
		{"git branch created", `git checkout -b feature-x`, "allow"},
		{"git status and log", `git status && git log -3 --oneline`, "allow"},
		{"git stash push", `git stash`, "allow"},
	}
	// A managed install leaves the agent config folders to the vendor lock, so
	// these rows run in the balanced default and the strict pack per-user.
	checkHookConfigShellRowsIn(t, h, []hookConfigCell{{"default", false}, {"strict", false}}, rows)
}
