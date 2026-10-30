// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2577 (managed Windows, T10p C05): the GAP-2047 link-walk rows and the
// GAP-0052 static xargs rows, sent as Git Bash commands from a Windows
// project with a directory link to the state, allowed with no finding while
// they block on Linux and macOS. The same rows on project paths stay quiet.
func TestR105GAP2577WindowsGitBashLinkWalkAndXargs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Git Bash drive home and a Windows directory link are Windows forms")
	}
	home, cwd := r105StateFixture(t)
	t.Setenv("USERPROFILE", home)
	state := filepath.Join(home, ".defenseclaw")
	for link, target := range map[string]string{"dclink": state, "hooklink": filepath.Join(state, "hooks")} {
		full := filepath.Join(cwd, link)
		if err := os.Symlink(target, full); err != nil {
			// A junction needs no symlink privilege.
			if out, err := exec.Command("cmd", "/c", "mklink", "/J", full, target).CombinedOutput(); err != nil {
				t.Fatalf("link %s: %v %s", link, err, out)
			}
		}
	}
	for _, dir := range []string{"build", "out", "proj2/build"} {
		if err := os.MkdirAll(filepath.Join(cwd, filepath.FromSlash(dir)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"control rm state hooks", "rm -rf ~/.defenseclaw/hooks", true, ""},
		{"L1 link entry", "rm -rf dclink/hooks", true, ""},
		{"L5 glob after link dot-dot", "rm -rf dclink/../.defenseclaw/*", true, ""},
		{"link dot-dot hooks", "rm -rf dclink/../.defenseclaw/hooks", true, ""},
		{"tilde link dot-dot hooks", "rm -rf ~/project/dclink/../.defenseclaw/hooks", true, ""},
		{"tilde git -C link clean", "git -C ~/project/dclink clean -fdx", true, ""},
		{"tilde project dot-dot build", "rm -rf ~/project/dclink/../project/build", false, ""},
		{"quoted tilde stays text", `echo "~/project/dclink/../.defenseclaw/hooks"`, false, ""},
		{"L11 git -C link clean", "git -C dclink clean -fdx", true, ""},
		{"git -C hooklink clean", "git -C hooklink clean -fdx", true, ""},
		{"git --work-tree= link clean", "git --work-tree=hooklink clean -fdx", true, ""},
		{"cd link then git clean", "cd dclink && git clean -fdx", true, ""},
		{"W sh -c xargs", `sh -c "echo ~/.defenseclaw/hooks | xargs rm -rf"`, true, ""},
		{"xargs printf", "printf '%s\\n' ~/.defenseclaw/hooks | xargs rm -rf", true, ""},
		{"project dot-dot build", "rm -rf dclink/../project/build", false, ""},
		{"project dot-dot glob", "rm -rf build/../out/*", false, ""},
		{"list link parent", "ls dclink/../", false, ""},
		{"git -C link status", "git -C dclink status", false, ""},
		{"git -C link clean dry run", "git -C dclink clean -n -d", false, ""},
		{"cd project then git clean", "cd proj2 && git clean -fdx", false, ""},
		{"xargs project", `sh -c "echo build out | xargs rm -rf"`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
