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
