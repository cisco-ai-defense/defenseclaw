// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2485 pod check27: a cd moves the directory a later command is judged
// in only when the shell keeps it. A cd that can fail (; || 2>/dev/null, an
// if) leaves the command judged in both directories, and a backgrounded or
// piped cd moves nothing. A $HOME, ${HOME} or "$HOME" work tree or path is
// read as the ~ spelling. The check26 benign rows stay allowed and quiet
// (TestR105GAP2485CommandDirectoryAfterCd).
func TestR105GAP2485CdScopeAndHomeSpelling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, _ := r105StateFixture(t)
	project := filepath.Join(home, "proj2")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	homeRows := []r105StateRow{
		{"S1 failed cd then rm", "cd /nonexistent-ipchk; rm -rf .defenseclaw/hooks/*", true, ""},
		{"S2 cd or rm", "cd /nonexistent-ipchk || rm -rf .defenseclaw/hooks/*", true, ""},
		{"S4 backgrounded cd", "cd /tmp & rm -rf .defenseclaw/hooks/*", true, ""},
		{"S5 piped cd", "cd /tmp | true; rm -rf .defenseclaw/hooks/*", true, ""},
		{"S12 quiet failed cd", "cd /nonexistent-ipchk 2>/dev/null; rm -rf .defenseclaw/instal*", true, ""},
		{"S14 if cd", "if cd /tmp; then :; fi; rm -rf .defenseclaw/hooks/*", true, ""},
		{"S16 sort -o", "cd /nonexistent-ipchk; sort -o .defenseclaw/config.yaml /tmp/x", true, ""},
		{"S17 install -t", "cd /nonexistent-ipchk; install -t .defenseclaw/hooks /tmp/x", true, ""},
		{"S18 brace rm", "cd /nonexistent-ipchk; rm -rf .defenseclaw/{hooks,installer}", true, ""},
		{"S23 git -C clean", "cd /nonexistent-ipchk; git -C .defenseclaw clean -fdx", true, ""},
		{"S24 rsync delete", "cd /nonexistent-ipchk; rsync -a --delete /tmp/e/ .defenseclaw/hooks/", true, ""},
		{"and list then new list", "cd /nonexistent-ipchk && true; true && rm -rf .defenseclaw/hooks/*", true, ""},
		{"S8 cd $HOME", "cd $HOME && rm -rf .defenseclaw/*", true, ""},
		{"S7 cd quoted $HOME", "cd \"$HOME\" && rm -rf .defenseclaw/hooks/*", true, ""},
		{"W1 work tree $HOME", "git --work-tree=$HOME clean -fdx", true, ""},
		{"W5 -C $HOME", "git -C $HOME clean -fdx", true, ""},
		{"W6 -C quoted $HOME", "git -C \"$HOME\" clean -fdx", true, ""},
		{"W7 work tree quoted $HOME", "git --work-tree=\"$HOME\" clean -fdx", true, ""},
		{"rm $HOME glob", "rm -rf $HOME/.defenseclaw/hooks/*", true, ""},
		// Allowed and quiet.
		{"B3", "cd ~/.defenseclaw && grep -r mode *", false, ""},
		{"B5", "cd ~/.defenseclaw/logs && rm -f *.log", false, ""},
		{"B8", "cd ~/proj2 && rm -rf build/* dist/*", false, ""},
		{"B12", "cd ~/proj2 && rm -rf .cache/* && cd - && ls", false, ""},
		{"B14", "pushd ~/proj2 >/dev/null && git clean -fdx && popd >/dev/null", false, ""},
		{"B15", "cd ~/proj2; rm -rf node_modules/*; npm install", false, ""},
		{"failed cd project clean", "cd ~/proj2; git clean -fdx", false, ""},
		{"state then project rm", "cd ~/.defenseclaw && cd ~/proj2 && rm -rf hook*", false, ""},
		{"quoted $HOME glob is literal", "rm -f \"$HOME/.defenseclaw/hooks/*\"", false, ""},
		{"rebound HOME", "HOME=/tmp/ipchk-h; git -C $HOME clean -fdx", false, ""},
		{"$HOME log cleanup", "rm -f $HOME/.defenseclaw/logs/*.log", false, ""},
	}
	projectRows := []r105StateRow{
		{"W2 work tree $HOME", "git --work-tree=$HOME clean -fdx", true, ""},
		{"W8 dotfiles stash -u", "git --git-dir=$HOME/.dotfiles --work-tree=$HOME stash -u", true, ""},
		{"W13 work tree ${HOME}", "git --work-tree=${HOME} clean -fdx", true, ""},
		{"W14 dotfiles clean", "git --git-dir=$HOME/.dotfiles --work-tree=$HOME clean -fdx", true, ""},
		{"dotfiles status", "git --git-dir=$HOME/.dotfiles --work-tree=$HOME status", false, ""},
		{"dotfiles add", "git --git-dir=$HOME/.dotfiles --work-tree=$HOME add .vimrc", false, ""},
		{"project clean", "git clean -fdx", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, home, homeRows, true)
		r105RunStateRowsChecked(t, mode, project, projectRows, true)
	}
}
