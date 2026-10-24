// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf16"
)

func w24EncodedPowerShell(command string) string {
	var encoded []byte
	for _, unit := range utf16.Encode([]rune(command)) {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func w24BalancedHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(cwd, "copy"), filepath.Join(cwd, "scripts")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		filepath.Join(home, ".ssh", "authorized_keys"): "marker\n",
		filepath.Join(home, ".ssh", "id_rsa"):          "key\n",
		filepath.Join(home, ".ssh", "id_ed25519"):      "key\n",
		filepath.Join(cwd, "run.sh"):                   "echo ok\n",
		filepath.Join(cwd, "regular.txt"):              "regular\n",
		filepath.Join(cwd, "report.txt"):               "report\n",
		filepath.Join(cwd, "a.txt"):                    "a\n",
		filepath.Join(cwd, "b.txt"):                    "b\n",
	} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	return home, cwd
}

// W24 loop round 2 (balanced defaults, GAP-1010): a script, interpreter or
// launcher whose body the action proof does not read is uncertainty, not SSH
// persistence evidence. It counts only when the text names a protected
// target or the command also writes to a computed destination.
func TestW24UnreadScriptLaunchesNeedProtectedEvidence(t *testing.T) {
	w24POSIXRows(t, []w24Row{
		command string
		block   bool
	}{
		{`bash run.sh test`, false},
		{`./run.sh test`, false},
		{`sh scripts/build.sh a b`, false},
		{`python3 scripts/gen.py --out build`, false},
		{`node scripts/build.js prod`, false},
		{`source ./env.sh extra`, false},
		{`bash -s < run.sh`, false},
		{`../outside.sh`, false},
		{`"$RUNNER" test`, false},
		{`bash run.sh test 2>&1 | tee build.log`, false},
		{`pwsh -File ./build.ps1 -Configuration Release`, false},
		{`bash run.sh test >> ~/.ssh/authorized_keys`, true},
		{`bash run.sh ~/.ssh/authorized_keys`, true},
		{`cd ~/.ssh && bash run.sh test`, true},
		{`bash run.sh test; echo key > "$dest"`, true},
		{`bash run.sh test && cat key | tee -a "$target"`, true},
		{`"$RUNNER" "$HOME/.ssh/authorized_keys"`, true},
		{`./run.sh test alias`, true},
	})
	w24WindowsRows(t, []w24Row{
		{`pwsh.exe -NoProfile -ExecutionPolicy Bypass -File C:/dc-test/t9-a4w1-sec/scripts/t9s-webhook-case.ps1 -Case missing-dry -Source native`, false},
		{`pwsh -File .\build.ps1 -Configuration Release`, false},
		{`powershell -ExecutionPolicy Bypass -File .\build.ps1`, false},
		{`.\scripts\check.ps1 -Case missing-send -Source native`, false},
		{`& .\build.ps1 -Configuration Release`, false},
		{`cmd /c build.bat release`, false},
		{`python tools\gen.py`, false},
		{`bash run.sh test`, false},
		{`pwsh -EncodedCommand ` + w24EncodedPowerShell(`.\build.ps1 -Configuration Release`), false},
		{`pwsh -File .\x.ps1 -Target $env:USERPROFILE\.ssh\authorized_keys`, true},
		{`.\x.ps1 C:\Users\alice\.ssh\authorized_keys`, true},
		{`pwsh -File .\build.ps1; Set-Content -Path $target -Value key`, true},
		{`pwsh -EncodedCommand ` + w24EncodedPowerShell(`.\x.ps1 C:\Users\alice\.ssh\authorized_keys`), true},
		{`Set-Location ~; .\setup.ps1`, true},
		{`Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value key`, true},
	})
}

type w24Row struct {
	command string
	block   bool
}

// w24POSIXRows judges POSIX rows in a real temporary home. Native Windows
// has no POSIX home (and no unprivileged symlink), so they run elsewhere.
func w24POSIXRows(t *testing.T, rows []w24Row) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Log("POSIX rows need a POSIX home")
		return
	}
	home, cwd := w24BalancedHome(t)
	for _, tc := range rows {
		if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
			t.Errorf("POSIX %q decision = %q, want block=%t", tc.command, got, tc.block)
		}
	}
}

// w24WindowsRows judges rows for a Windows profile, on every OS.
func w24WindowsRows(t *testing.T, rows []w24Row) {
	t.Helper()
	const cwd, home = `C:\Users\alice\project`, `C:\Users\alice`
	for _, tc := range rows {
		if got := ActionCommandDecision(tc.command, cwd, home); (got != "") != tc.block {
			t.Errorf("Windows %q decision = %q, want block=%t", tc.command, got, tc.block)
		}
	}
}

// W24 loop round 2 (GAP-1012): a for loop over literal words or pathname
// patterns binds known values, and an unresolved copy or read source names
// no destination. A possible protected destination still blocks.
func TestW24LoopValuesAndCopySourcesNeedProtectedDestination(t *testing.T) {
	w24POSIXRows(t, []w24Row{
		{`for f in regular.txt; do cp "$f" copy/; done; echo ok > second-report.txt`, false},
		{`for f in regular.txt report.txt; do cp "$f" copy/; done`, false},
		{`for f in *.txt; do cp "$f" copy/; done`, false},
		{`for f in *.log; do cp "$f" copy/; done`, false},
		{`for f in a.txt; do touch "$f"; done`, false},
		{`for f in *.txt; do sed -i 's/a/b/' "$f"; done`, false},
		{`for f in a.txt b.txt; do sed -i 's/a/b/' "$f"; done`, false},
		{`for f in a.txt; do tee "$f" < regular.txt; done`, false},
		{`for f in regular.txt; do mv "$f" copy/; done`, false},
		{`for f in a.txt b.txt; do echo ok > "$f"; done`, false},
		{`while read -r f; do cp "$f" copy/; done < list.txt`, false},
		{`cp "$1" copy/`, false},
		{`cat "$f" > out.txt`, false},
		{`tee out.txt < "$f"`, false},
		{`for f in regular.txt alias; do echo key >> "$f"; done`, true},
		{`for f in ~/.ssh/authorized_keys; do cp key.pub "$f"; done`, true},
		{`for f in *.txt; do cp "$f" "$dest"; done`, true},
		{`for f in regular.txt; do cp "$f" ~/.ssh/; done`, true},
		{`for f in a.txt b.txt; do f="$X"; echo key > "$f"; done`, true},
		{`for f in ~/.ssh/id_rsa; do cat "$f" > out.txt; done`, true},
		{`for f in ~/.ssh/id_*; do cat "$f" > out.txt; done`, true},
		{`for f in "$@"; do echo key > "$f"; done`, true},
		{`cp "$f" alias`, true},
		{`for f in *.txt; do sed -i 's/a/b/' "$f"; done; for g in alias; do sed -i s/a/b/ "$g"; done`, true},
		// A computed copy destination inside a loop is the 1.0.3 decision
		// of UnprovenProtectedWrite, unchanged here.
		{`for f in regular.txt; do cp -- "$f" "copy/$f.bak"; done`, true},
	})
	w24WindowsRows(t, []w24Row{
		{`for f in regular.txt; do cp "$f" copy/; done; echo ok > second-report.txt`, false},
		{`foreach ($f in 'regular.txt','report.txt') { Copy-Item $f copy }`, false},
		{`Copy-Item $src out\`, false},
		{`Copy-Item -Path $src -Destination out`, false},
		{`Copy-Item -Recurse -Force $src out`, false},
		{`Move-Item $f archive\`, false},
		{`Copy-Item src $dest`, true},
		{`Copy-Item -Destination $dest -Path a.txt`, true},
		{`Copy-Item $f -Destination $d`, true},
		{`Copy-Item $f C:\Users\alice\.ssh\authorized_keys`, true},
		{`Copy-Item $f $env:USERPROFILE\.ssh\`, true},
		{`cp -t $d a.txt`, true},
	})
}
