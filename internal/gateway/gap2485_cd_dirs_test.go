// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2485 pod check26: a session whose cwd is the home judges each command
// in the directory it runs in after an earlier cd/pushd/popd, and a home
// work tree counts above the state root only when the call names it (-C,
// --work-tree). Project work after a cd, and git in a home or /tmp the
// command does not prove is a work tree, stay allowed and quiet; a cd into
// the state still writes the state.
func TestR105GAP2485CommandDirectoryAfterCd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, _ := r105StateFixture(t)
	for _, dir := range []string{"proj2", "bin", ".local/share/x"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"cd hooks sort -o relative", "cd ~/.defenseclaw/hooks && sort -o a.txt /tmp/x", true, ""},
		{"cd state install -t hooks", "cd ~/.defenseclaw && install -t hooks /tmp/claude-code-hook.sh", true, ""},
		{"cd state rm glob", "cd ~/.defenseclaw && rm -rf hook*", true, ""},
		{"cd state git stash -u", "cd ~/.defenseclaw && git stash -u", true, ""},
		{"pushd hooks reset hard", "pushd ~/.defenseclaw/hooks && git reset --hard && popd", true, ""},
		{"cd project then -C home clean", "cd ~/proj2 && git -C ~ clean -fdx", true, ""},
		{"named home clean", "git -C ~ clean -fdx", true, ""},
		{"named home work tree stash -u", "git --git-dir=~/.dotfiles --work-tree=~ stash -u", true, ""},
		// Allowed and quiet (check26 probe rows P1-P30 but P22).
		{"P1", "cd ~/proj2 && git clean -fdx", false, ""},
		{"P2", "cd ~/proj2 && git stash -u", false, ""},
		{"P3", "cd proj2 && git stash -u", false, ""},
		{"P4", "git -C proj2 clean -fdx", false, ""},
		{"P5", "cd \"$REPO\" && git clean -fdx", false, ""},
		{"P6", "cd $REPO && git stash -u", false, ""},
		{"P7", "(cd ~/proj2 && git clean -fd)", false, ""},
		{"P8", "pushd ~/proj2 && git stash -u && popd", false, ""},
		{"P9", "git stash -u", false, ""},
		{"P10", "git clean -fdx", false, ""},
		{"P11", "for d in ~/proj2; do git -C \"$d\" clean -fdx; done", false, ""},
		{"P12", "git -C \"$REPO\" stash -u", false, ""},
		{"P13", "cd ~/proj2; git checkout -- .", false, ""},
		{"P14", "git -C ~ stash list", false, ""},
		{"P15", "git -C ~ checkout main", false, ""},
		{"P16", "sort -o out.txt in.txt", false, ""},
		{"P17", "install -t ~/bin a b", false, ""},
		{"P18", "sort -k2 -t: -o /tmp/o.txt /tmp/in.txt", false, ""},
		{"P19", "install -Dt ~/.local/share/x a", false, ""},
		{"P20", "git -c core.quotepath=off -C ~/proj2 restore .", false, ""},
		{"P21", "git --git-dir=$HOME/.dotfiles --work-tree=$HOME checkout -f", false, ""},
		{"P23", "git stash -u && git pull && git stash pop", false, ""},
		{"P24", "cd ~/proj2 && git reset --hard && git clean -fd", false, ""},
		{"P25", "git -C $REPO_DIR clean -fdx $EXTRA", false, ""},
		{"P26", "rm -rf $TMPDIR/build $X", false, ""},
		{"P27", "rm -rf ./node_modules $EXTRA", false, ""},
		{"P28", "sort -o \"$OUT\" in.txt", false, ""},
		{"P29", "install -t \"$DEST\" a", false, ""},
		{"P30", "cd /tmp && git clean -fdx", false, ""},
		{"cd state read", "cd ~/.defenseclaw && sort config.yaml", false, ""},
		{"cd state then project rm", "cd ~/.defenseclaw && cd ~/proj2 && rm -rf hook*", false, ""},
		{"cd state log cleanup", "cd ~/.defenseclaw && rm -f logs/*.log", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, home, rows, true)
	}
}
