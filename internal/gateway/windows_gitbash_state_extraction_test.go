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

// rel-1-0-10:GAP-1173 (P1, cert110 L75) and GAP-0154: on a Windows home a
// Git Bash archive extraction into the DefenseClaw state (tar -C, unzip -d,
// a member that lands in the state, a folder linked to it) and an inline
// python -c hand-off that writes a state file were allowed with no finding,
// while the same rows block on Linux and macOS (GAP-2415, GAP-0142,
// GAP-0661, GAP-0365): the state judge of those readers read a POSIX home
// only. Extractions into project folders and a proven read stay quiet.
func TestGAP1173WindowsGitBashExtractionAndHandoffIntoState(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Windows drive home is a Windows form")
	}
	home, cwd := gap1173WindowsStateHome(t)
	for _, file := range []string{"project/a.tar", "project/a.zip", "project/out/.keep"} {
		full := filepath.Join(home, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link, target := filepath.Join(cwd, "dclink"), filepath.Join(home, ".defenseclaw")
	if err := os.Symlink(target, link); err != nil {
		// A junction needs no symlink privilege.
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("link: %v %s", err, out)
		}
	}
	rows := []r105StateRow{
		{"tar -C state", "tar -xf a.tar -C ~/.defenseclaw", true, ""},
		{"tar -C state HOME", "tar -xf a.tar -C $HOME/.defenseclaw", true, ""},
		{"tar --directory= state", "tar --extract --file a.tar --directory=$HOME/.defenseclaw", true, ""},
		{"tar -C state hooks", "tar -xf a.tar -C ~/.defenseclaw/hooks", true, ""},
		{"tar -C home state member", "tar -xf a.tar -C ~ .defenseclaw/config.yaml", true, ""},
		{"unzip -d state", "unzip -o a.zip -d ~/.defenseclaw", true, ""},
		{"unzip state member -d home", "unzip -o a.zip .defenseclaw/config.yaml -d ~", true, ""},
		{"tar -C link", "tar -xf a.tar -C dclink", true, ""},
		{"unzip -d link", "unzip -o a.zip -d dclink", true, ""},
		{"python -c writes state", `python3 -c 'import sys; open(sys.argv[1], "w").write("")' ~/.defenseclaw/config.yaml`, true, ""},
		// Allowed: project folders, the home with a project member, a listing
		// and a proven read.
		{"tar into project", "tar -xf a.tar -C out", false, ""},
		{"unzip into project", "unzip -o a.zip -d ~/project/out", false, ""},
		{"tar -C home project member", "tar -xf a.tar -C ~ project/notes.txt", false, ""},
		{"tar list with -C state", "tar -tf a.tar -C ~/.defenseclaw", false, ""},
		{"python -c reads project", `python3 -c 'import sys; print(open(sys.argv[1]).read())' notes.txt`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

// gap1173WindowsStateHome is r105StateFixture without the r104ReviewHome
// symlink: a standard Windows user holds no symlink privilege, and these
// rows need no protected-file alias.
func gap1173WindowsStateHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, file := range []string{
		"config.yaml", "installer/install.sh", "hooks/claude-code-hook.sh", "policies/default.yaml",
	} {
		full := filepath.Join(state, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}
