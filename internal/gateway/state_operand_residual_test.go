// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2047 (pod check16 rows): the operands the shell or the program hands
// over in another form reach the active state as well: a here-string fed
// to xargs, a project symlink to the state root, a $HOME or ${HOME} glob
// and a double-quoted $HOME path, an rsync or a `cp -r X/.` into the root,
// and a git clean of the -C directory. Each removes or replaces protected
// state, so it blocks in every mode, both connectors. Reads, copies out,
// log cleanup and the same commands on project paths stay quiet.
func TestR105GAP2047ResidualStateOperands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(cwd, "dclink")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"build", "proj2", "backup"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"xargs here-string installer", "xargs rm -rf <<< ~/.defenseclaw/installer", true, "classifier seam GAP-2047: actionfacts parses POSIX sh, where <<< is a syntax error, so an xargs here-string gives no facts (needs the bash here-string grammar)"},
		{"xargs here-string config", "xargs rm -f <<< ~/.defenseclaw/config.yaml", true, "classifier seam GAP-2047: actionfacts parses POSIX sh, where <<< is a syntax error, so an xargs here-string gives no facts (needs the bash here-string grammar)"},
		{"xargs here-string quoted $HOME hooks", `xargs rm -rf <<< "$HOME/.defenseclaw/hooks"`, true, "classifier seam GAP-2047: actionfacts parses POSIX sh, where <<< is a syntax error, so an xargs here-string gives no facts (needs the bash here-string grammar)"},
		{"symlinked root trailing slash", "rm -rf dclink/", true, ""},
		{"symlinked root tree", "rm -rf dclink/installer", true, ""},
		{"symlinked root config", "rm -f dclink/config.yaml", true, ""},
		{"quoted $HOME tree", `rm -rf "$HOME/.defenseclaw/installer"`, true, ""},
		{"quoted ${HOME} tree", `rm -rf "${HOME}/.defenseclaw/hooks"`, true, ""},
		{"quoted $HOME then path", `rm -rf "$HOME"/.defenseclaw/hooks`, true, ""},
		{"quoted $HOME move config", `mv "$HOME/.defenseclaw/config.yaml" /tmp/c`, true, ""},
		{"$HOME root glob", "rm -rf $HOME/.defenseclaw/*", true, ""},
		{"${HOME} hooks glob", "rm -rf ${HOME}/.defenseclaw/hooks/*", true, ""},
		{"${HOME} prefix glob", "rm -rf ${HOME}/.defenseclaw/instal*", true, ""},
		{"rsync contents into root", "rsync -a /tmp/x/ ~/.defenseclaw/", true, ""},
		{"rsync config into root", "rsync -a /tmp/x/config.yaml ~/.defenseclaw/", true, ""},
		{"rsync hooks dir into root", "rsync -a /tmp/hooks ~/.defenseclaw/", true, ""},
		{"cp dot into root", "cp -r /tmp/x/. ~/.defenseclaw/", true, ""},
		{"cp -a dot into root", "cp -a /tmp/x/. ~/.defenseclaw", true, ""},
		{"git -C root clean", "git -C ~/.defenseclaw clean -fdx", true, ""},
		{"git -C hooks clean", "git -C ~/.defenseclaw/hooks clean -fd", true, ""},
		{"git -C home clean state", "git -C ~ clean -fdx .defenseclaw", true, ""},
		// Allowed and quiet.
		{"xargs here-string project", "xargs rm -f <<< build/a.o", false, "classifier seam GAP-2047: actionfacts parses POSIX sh, where <<< is a syntax error, so an xargs here-string gives no facts (needs the bash here-string grammar)"},
		{"xargs here-string read", "xargs cat <<< ~/.defenseclaw/config.yaml", false, "classifier seam GAP-2047: actionfacts parses POSIX sh, where <<< is a syntax error, so an xargs here-string gives no facts (needs the bash here-string grammar)"},
		{"symlinked root link only", "rm -f dclink", false, ""},
		{"symlinked root list", "ls -la dclink/", false, ""},
		{"symlinked root log cleanup", "rm -f dclink/logs/gateway.log", false, ""},
		{"quoted $HOME cache", `rm -rf "$HOME/.cache/pip"`, false, ""},
		{"quoted $HOME read", `cat "$HOME/.defenseclaw/config.yaml"`, false, ""},
		{"$HOME cache glob", "rm -rf $HOME/.cache/*", false, ""},
		{"$HOME log glob", "rm -f $HOME/.defenseclaw/logs/*.log", false, ""},
		{"rsync into backup", "rsync -a /tmp/x/ backup/", false, ""},
		{"rsync state out", "rsync -a ~/.defenseclaw/ backup/dc/", false, ""},
		{"rsync logs dir into root", "rsync -a /tmp/logs ~/.defenseclaw/", false, ""},
		{"cp dot into project", "cp -r /tmp/x/. proj2/", false, ""},
		{"cp state dot out", "cp -r ~/.defenseclaw/. /tmp/dcbak/", false, ""},
		{"git -C project clean", "git -C proj2 clean -fdx", false, ""},
		{"git -C state status", "git -C ~/.defenseclaw status", false, ""},
		{"git -C state clean dry run", "git -C ~/.defenseclaw clean -n -d", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// pod check17 P3 (regression of c5089e423b): the value word of an rsync
// option that takes one (`--exclude cache/`) is not a source that lands in
// the root, and --delay-updates is not a delete option. The rows that
// really write the state keep blocking.
func TestR105Check17RsyncOptionValuesAreNotSources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"rsync exclude value into root", "rsync -a --exclude cache/ ~/proj/out ~/.defenseclaw/", false, ""},
		{"rsync quoted exclude value into root", "rsync -a --exclude 'cache/' out ~/.defenseclaw/", false, ""},
		{"rsync include filter values into root", "rsync -a --include logs/ --filter '- tmp/' out ~/.defenseclaw/", false, ""},
		{"rsync link-dest value into root", "rsync -a --link-dest /tmp/prev/ out ~/.defenseclaw/", false, ""},
		{"rsync -e value into root", "rsync -a -e ssh out ~/.defenseclaw/", false, ""},
		{"rsync delay-updates into root", "rsync -a --delay-updates out ~/.defenseclaw/", false, ""},
		{"rsync exclude then contents into root", "rsync -a --exclude cache/ /tmp/x/ ~/.defenseclaw/", true, ""},
		{"rsync exclude then config into root", "rsync -a --exclude cache/ /tmp/x/config.yaml ~/.defenseclaw/", true, ""},
		{"rsync delete-after into root", "rsync -a --delete-after out ~/.defenseclaw/", true, ""},
		{"rsync exclude= then contents into root", "rsync -a --exclude=cache/ /tmp/x/ ~/.defenseclaw/", true, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// pod check17 GAP-2047 rows (b) and (d): a pattern or a dir/. copy through
// a project link to the state root, and a git clean of a --work-tree,
// remove or replace protected state like their ~/.defenseclaw spellings.
func TestR105Check17LinkGlobsAndGitWorkTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(cwd, "dclink")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"build", "proj2"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(home, ".defenseclaw")
	rows := []r105StateRow{
		{"glob through link root", "rm -rf dclink/*", true, ""},
		{"glob through dot link hooks", "rm -rf ./dclink/hooks/*", true, ""},
		{"prefix glob through link", "rm -rf dclink/instal*", true, ""},
		{"brace through link", "rm -rf dclink/{installer,hooks}", true, ""},
		{"cp dot into link", "cp -a /tmp/x/. dclink/", true, ""},
		{"git work-tree option clean", "git --work-tree " + state + " clean -fdx", true, ""},
		{"git work-tree= clean", "git --git-dir=/tmp/g.git --work-tree=" + state + " clean -fdx", true, ""},
		{"git -C home work-tree clean", "git -C " + home + " --work-tree .defenseclaw clean -fd", true, ""},
		// Allowed and quiet.
		{"log glob through link", "rm -f dclink/logs/*", false, ""},
		{"list glob through link", "ls dclink/*", false, ""},
		{"project glob", "rm -rf build/*", false, ""},
		{"git work-tree project clean", "git --work-tree proj2 clean -fdx", false, ""},
		{"git work-tree state dry run", "git --work-tree " + state + " clean -n -d", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// pod check18 (regressions of d46bd27b42 and d9e567b34a, and GAP-2047 row
// c): a short rsync option with an attached value (`-T/tmp/te`,
// `-aT/tmp/te`, `-essh-te`) does not take the next word, a relative
// --work-tree is resolved after every -C, and a double-quoted $HOME prefix
// before an unquoted pattern names the state like ~ does. Each removes or replaces protected state, so
// it blocks in every mode, both connectors; the same forms on project paths
// stay quiet.
func TestR105Check18AttachedRsyncValuesWorkTreeAfterCAndQuotedHomeGlobs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	for _, dir := range []string{"out", "proj2", "backup"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"rsync attached -T into hooks", "rsync -a -T/tmp/te /tmp/x/ ~/.defenseclaw/hooks/", true, ""},
		{"rsync clustered -aT into root", "rsync -aT/tmp/te /tmp/x/ ~/.defenseclaw/", true, ""},
		{"rsync attached -e into hooks", "rsync -a -essh-te /tmp/x/ ~/.defenseclaw/hooks/", true, ""},
		{"rsync clustered -ae then value word into root", "rsync -ae ssh /tmp/x/ ~/.defenseclaw/", true, ""},
		{"git relative work-tree before -C", "git --work-tree=. -C ~/.defenseclaw clean -fdx", true, ""},
		{"git git-dir and relative work-tree before -C", "git --git-dir=/tmp/g/.git --work-tree=. -C ~/.defenseclaw clean -fdx", true, ""},
		{"git work-tree word before -C", "git --work-tree hooks -C ~/.defenseclaw clean -fdx", true, ""},
		{"quoted $HOME prefix glob root", `rm -rf "$HOME/.defenseclaw/"*`, true, ""},
		{"quoted $HOME then glob root", `rm -rf "$HOME"/.defenseclaw/*`, true, ""},
		{"quoted ${HOME} prefix glob hooks", `rm -rf "${HOME}/.defenseclaw/hooks/"*`, true, ""},
		// Allowed and quiet.
		{"rsync attached -T into backup", "rsync -a -T/tmp/te /tmp/x/ backup/", false, ""},
		{"rsync attached -e dir into root", "rsync -a -essh out ~/.defenseclaw/", false, ""},
		{"git relative work-tree project", "git --work-tree=. -C proj2 clean -fdx", false, ""},
		{"quoted $HOME cache glob", `rm -rf "$HOME/.cache/"*`, false, ""},
		{"quoted $HOME log glob", `rm -f "$HOME/.defenseclaw/logs/"*.log`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
