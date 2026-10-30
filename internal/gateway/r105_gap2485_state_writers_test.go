// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2485 (pod check25): option forms that write a named state file or
// directory, and git subcommands that rewrite a work tree on the state (or
// drop the untracked files of the home work tree that holds the state root),
// block with tamper.detector_state_write in every mode. Project, dotfiles
// and read forms stay allowed and quiet.
func TestR105GAP2485StateWriteOptionFormsAndGitWorkTreeWriters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	for _, dir := range []string{filepath.Join(home, "proj2"), filepath.Join(home, ".local", "bin"), filepath.Join(home, "dotfiles")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"install -t hooks", "install -t ~/.defenseclaw/hooks /tmp/claude-code-hook.sh", true, ""},
		{"install --target-directory= hooks", "install --target-directory=~/.defenseclaw/hooks /tmp/claude-code-hook.sh", true, ""},
		{"install --target-directory hooks abs", "install -m 0755 --target-directory " + home + "/.defenseclaw/hooks /tmp/claude-code-hook.sh", true, ""},
		{"install -t root config name", "install -t ~/.defenseclaw /tmp/x/config.yaml", true, ""},
		{"sort -o config", "sort -o ~/.defenseclaw/config.yaml /tmp/x", true, ""},
		{"sort -o attached abs", "sort -u -o" + home + "/.defenseclaw/config.yaml /tmp/x", true, ""},
		{"sort --output= config", "sort --output=" + home + "/.defenseclaw/config.yaml /tmp/x", true, ""},
		{"git work-tree stash -u", "git --work-tree ~/.defenseclaw stash -u", true, ""},
		{"git work-tree stash push --all", "git --work-tree ~/.defenseclaw stash push --all", true, ""},
		{"git work-tree checkout -f", "git --work-tree ~/.defenseclaw checkout -f -- .", true, ""},
		{"git -C hooks reset --hard", "git -C ~/.defenseclaw/hooks reset --hard", true, ""},
		{"git work-tree= restore", "git --work-tree=" + home + "/.defenseclaw restore .", true, ""},
		{"git home work tree clean", "git --work-tree ~ clean -fdx", true, ""},
		{"git -C home clean", "git -C ~ clean -fdx", true, ""},
		{"git home stash -u", "git --git-dir=~/dotfiles --work-tree=~ stash -u", true, ""},
		// Allowed and quiet.
		{"install -t local bin", "install -t ~/.local/bin /tmp/tool", false, ""},
		{"install file to local bin", "install -m 0755 /tmp/tool ~/.local/bin/tool", false, ""},
		{"sort -o project", "sort -o ~/proj2/out.txt /tmp/x", false, ""},
		{"sort state read", "sort ~/.defenseclaw/config.yaml", false, ""},
		{"dotfiles status", "git --git-dir=~/dotfiles --work-tree=~ status", false, ""},
		{"dotfiles add", "git --git-dir=~/dotfiles --work-tree=~ add .vimrc", false, ""},
		{"dotfiles checkout file", "git --git-dir=~/dotfiles --work-tree=~ checkout -- .vimrc", false, ""},
		{"dotfiles stash", "git --git-dir=~/dotfiles --work-tree=~ stash", false, ""},
		{"project reset hard", "git -C ~/proj2 reset --hard", false, ""},
		{"project stash -u", "git -C ~/proj2 stash -u", false, ""},
		{"project clean", "git -C ~/proj2 clean -fdx", false, ""},
		{"state work tree status", "git --work-tree ~/.defenseclaw status --short", false, ""},
		{"state work tree diff", "git -C ~/.defenseclaw diff", false, ""},
		{"home clean dry run", "git -C ~ clean -fdxn", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
