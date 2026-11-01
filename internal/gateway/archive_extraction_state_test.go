// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2415 (P2 security, pod check20): an archive extraction into a folder
// that is a link to ~/.defenseclaw (or into the state spelled as it is)
// writes the state as a redirect through the same link would. unzip -d,
// tar -C, 7z -o, cpio -D and ditto are judged on the folder they write in;
// extraction into project folders, listings and tests stay allowed. As
// for the redirect, the link is followed where the gateway may read the
// home (the per-user install).
func TestR105GAP2415ArchiveExtractionIntoStateBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, cwd := r105StateFixture(t)
	for _, file := range []string{"proj/a.zip", "proj/evil.zip", "proj/a.tar", "proj/b/.keep"} {
		full := filepath.Join(home, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"proj/evil": ".defenseclaw", "proj/hk": ".defenseclaw/hooks"} {
		if err := os.Symlink(filepath.Join(home, target), filepath.Join(home, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	rows := []r105StateRow{
		{"unzip answered into link", `yes | unzip -q -d ~/proj/evil ~/proj/evil.zip`, true, ""},
		{"unzip into link", `unzip -q -d ~/proj/evil ~/proj/evil.zip`, true, ""},
		{"unzip -d after archive", `unzip -o ~/proj/evil.zip -d ~/proj/evil`, true, ""},
		{"unzip attached -d", `unzip -o -d` + home + `/proj/evil ~/proj/evil.zip`, true, ""},
		{"unzip -qod cluster", `unzip -qod ~/proj/evil ~/proj/evil.zip`, true, ""},
		{"unzip into hooks link", `unzip -o -d ~/proj/hk ~/proj/evil.zip`, true, ""},
		{"unzip into link subfolder", `unzip -o -d ~/proj/evil/hooks ~/proj/evil.zip`, true, ""},
		{"unzip into state", `yes | unzip -q -d ~/.defenseclaw ~/proj/evil.zip`, true, ""},
		{"unzip into state hooks", `unzip -o -d $HOME/.defenseclaw/hooks ~/proj/evil.zip`, true, ""},
		{"unzip in linked cwd", `cd ~/proj/evil && unzip -o ../evil.zip`, true, ""},
		{"tar -C link", `tar -xf ~/proj/a.tar -C ~/proj/evil`, true, ""},
		{"tar --directory= state", `tar --extract --file ~/proj/a.tar --directory=$HOME/.defenseclaw`, true, ""},
		{"tar old style -C state", `tar xf ~/proj/a.tar -C ~/.defenseclaw`, true, ""},
		{"7z -o link", `7z x -y -o` + home + `/proj/evil ~/proj/evil.zip`, true, ""},
		{"ditto -x -k into link", `ditto -x -k ~/proj/evil.zip ~/proj/evil`, true, ""},
		{"cpio -D state", `cpio -idm -D ~/.defenseclaw < ~/proj/a.tar`, true, ""},
		// Allowed: project folders, listings, tests and creation.
		{"unzip into project", `unzip -o -d ~/proj/out ~/proj/a.zip`, false, ""},
		{"unzip -d after archive project", `unzip -q ~/proj/a.zip -d ~/proj/b`, false, ""},
		{"unzip list link archive", `unzip -l ~/proj/evil.zip`, false, ""},
		{"unzip test into link", `unzip -t ~/proj/evil.zip -d ~/proj/evil`, false, ""},
		{"tar into project", `tar -xf ~/proj/a.tar -C ~/proj/b`, false, ""},
		{"tar list with -C link", `tar -tf ~/proj/a.tar -C ~/proj/evil`, false, ""},
		{"7z list", `7z l ~/proj/evil.zip`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
