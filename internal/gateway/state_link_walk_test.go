// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2047 (T10 subset e, rows L5 and L11): with dclink -> ~/.defenseclaw
// in the project, the kernel follows the link before a `..` after it, so
// `rm -rf dclink/../.defenseclaw/*` removes the state root's entries while
// its lexical spelling is the project's own .defenseclaw; and git enters a
// -C or --work-tree directory (or one a cd moved the shell to) through the
// link, so `git -C dclink clean -fdx` cleans the state. Each blocks in every
// mode, both connectors. The same spellings on project paths, reads, a dry
// run and log cleanup stay quiet, as do the T10 rows R12/R13 (rsync of a
// directory named x into the root adds ~/.defenseclaw/x and touches no
// protected name, the pod check17 rule) and R16 (git cleans the /tmp/wt
// work tree, not the -C directory; real git removes only /tmp/wt entries).
func TestR105GAP2047LinkWalkDotDotAndGitDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(cwd, "dclink")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"build", "out", "proj2/build"} {
		if err := os.MkdirAll(filepath.Join(cwd, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"L5 glob after link dot-dot", "rm -rf dclink/../.defenseclaw/*", true, ""},
		{"link dot-dot hooks", "rm -rf dclink/../.defenseclaw/hooks", true, ""},
		{"dot link dot-dot installer", "rm -rf ./dclink/../.defenseclaw/installer", true, ""},
		{"link dot-dot config", "rm -f dclink/../.defenseclaw/config.yaml", true, ""},
		{"link dot-dot brace", "rm -rf dclink/../.defenseclaw/{installer,hooks}", true, ""},
		{"mv out of link dot-dot", "mv dclink/../.defenseclaw/hooks /tmp/oldhooks", true, ""},
		{"L11 git -C link clean", "git -C dclink clean -fdx", true, ""},
		{"git -C link slash clean", "git -C dclink/ clean -fd", true, ""},
		{"git --work-tree= link clean", "git --work-tree=dclink clean -fdx", true, ""},
		{"git --work-tree link clean", "git --work-tree dclink clean -fdx", true, ""},
		{"cd link then git clean", "cd dclink && git clean -fdx", true, ""},
		{"cd link hooks then rm glob", "cd dclink/hooks; rm -rf *", true, ""},
		{"project dot-dot build", "rm -rf dclink/../proj2/build", false, ""},
		{"project dot-dot glob", "rm -rf build/../out/*", false, ""},
		{"list link parent", "ls dclink/../", false, ""},
		{"git -C link status", "git -C dclink status", false, ""},
		{"git -C link clean dry run", "git -C dclink clean -n -d", false, ""},
		{"link log cleanup", "rm -f dclink/logs/gateway.log", false, ""},
		{"cd project then git clean", "cd proj2 && git clean -fdx", false, ""},
		{"R12 rsync dir into root", "rsync -a --remove-sent-files /tmp/x ~/.defenseclaw/", false, ""},
		{"R13 rsync delay-updates dir into root", "rsync -a --delay-updates /tmp/x ~/.defenseclaw/", false, ""},
		{"R16 git work tree outside state", "git -C ~/.defenseclaw --work-tree=/tmp/wt clean -fdx", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
