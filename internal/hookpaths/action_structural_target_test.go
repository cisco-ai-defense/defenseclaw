// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestR104StructuralProtectedNamedPOSIX(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native POSIX fixture")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh, filepath.Join(cwd, "build")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cd ~/.ssh && "$tool" authorized_keys`,
		`pushd ~/.ssh && sh "$script" authorized_keys`,
		`cd ~/.ssh; python3 "$script" authorized_keys`,
		`pushd ~/.ssh; popd; cp payload ~/.ssh/authorized_keys`,
		`cp payload ~/.s*/authorized_keys`,
		`cp payload ~/.ss?/authorized_keys`,
		`for p in ~/.ssh/authorized_k*; do cp payload "$p"; done`,
		`for p in ~/.s*/authorized_keys; do cp payload "$p"; done`,
		`sh -c 'cat "$HOME/.ssh/authorized_keys"'`,
		`grep marker payload >> ~/.ssh/authorized_keys`,
		`wc -l ~/.ssh/authorized_keys > ~/.ssh/authorized_keys2`,
		`cd ~/.ssh && echo authorized_keys`,
		`ls ~/.ssh && echo done`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`cd ~/.ssh`, `pushd ~/.ssh`, `ls ~/.ssh`, `ls -o ~/.ssh`, `stat ~/.ssh`,
		`cd ~/.ssh && cat authorized_keys`, `cd ~/.ssh && ls authorized_keys`,
		`grep marker report.txt`,
		// Plain reads stay allowed in action (owner decision 2, GAP-2168).
		`grep marker ~/.ssh/authorized_keys`,
		`wc -l ~/.ssh/authorized_keys`,
		`cp payload ~/.s*/ordinary.txt`, `cp payload ~/.ssh/*.pub`,
		`pushd build; popd; cp payload authorized_keys`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}

func TestR104StructuralLessOptions(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	for _, option := range []string{"--LOG-FILE", "--Log-Fi", "--log-f", "--l", "-o", "-O"} {
		t.Run(option, func(t *testing.T) {
			if got := ActionCommandDecision("less "+option+" "+target, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	if got := ActionCommandDecision("less --LoG-Fi="+target, cwd, home); got != "protected-target" {
		t.Fatalf("attached abbreviated log target decision = %q", got)
	}
	if got := ActionCommandDecision("less "+target, cwd, home); got != "" {
		t.Fatalf("plain read decision = %q", got)
	}
}

func TestR104StructuralProtectedNamedWindows(t *testing.T) {
	const home = `C:\Users\b00`
	const cwd = `C:\work`
	const key = `C:\Users\b00\.ssh\authorized_keys`
	for _, command := range []string{
		`Set-Location ` + home + `\.ssh; & $tool authorized_keys`,
		`Push-Location ` + home + `\.ssh; & $script authorized_keys`,
		`Copy-Item payload C:\Users\b00\.s*\authorized_keys`,
		`Copy-Item payload C:\Users\b00\.ss?\authorized_keys`,
		`Copy-Item payload $root\.ssh\authorized_keys`,
		`Copy-Item payload %ROOT%\.ssh\authorized_keys`,
		`Get-ChildItem ` + home + `\.ssh | Select-Object @{e={Set-Content ` + key + ` marker}}`,
		`Get-Content ` + key + ` | Select-Object {Add-Content ` + key + ` marker}`,
		`Get-ChildItem ` + home + `\.ssh | Select-Object -Property {Set-Content ` + key + ` marker}`,
		`Get-Content (Resolve-Path ` + key + `)`,
		`pwsh -Command 'Get-Content $env:USERPROFILE\.ssh\authorized_keys'`,
		`Push-Location ` + home + `\.ssh; Pop-Location; Add-Content notes.txt ok`,
		`Get-ChildItem ` + home + `\.ssh | Format-Table Name`,
		`foreach ($n in Get-ChildItem ` + home + `\.ssh) { Write-Output $n.Name }`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`cd ` + home + `\.ssh`, `pushd ` + home + `\.ssh`,
		`ls ` + home + `\.ssh`, `stat ` + home + `\.ssh`,
		`Test-Path ` + home + `\.ssh`, `Resolve-Path ` + home + `\.ssh`,
		`Get-ChildItem ` + home + `\.ssh`,
		`Set-Location ` + home + `\.ssh; Get-Content authorized_keys`,
		`Push-Location C:\work\build; Pop-Location; Add-Content notes.txt ok`,
		`Copy-Item payload C:\Users\b00\.s*\ordinary.txt`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}

// Round-k loop 2: a quoted, escaped or parameter-derived tilde is a literal
// name, and an unresolved word names a key only through a complete path
// component. Both forms allowed at the train baseline and blocked at
// 6f741b9e80; the protected forms beside them must keep blocking.
func TestR104StructuralLiteralTildeAndKeyComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native POSIX fixture")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`echo '~/.ssh/authorized_keys'`,
		`echo "~/.ssh/authorized_keys"`,
		`echo \~/.ssh/authorized_keys`,
		`echo ~"/.ssh/authorized_keys"`,
		`printf '%s\n' '~/.ssh/authorized_keys'`,
		`x='~/.ssh/authorized_keys'; echo "$x"`,
		`grep -n '~/.ssh/authorized_keys' README.md`,
		`git commit -m 'Document ~/.ssh/authorized_keys'`,
		`echo "$prefix/authorized_keys.bak"`,
		`cp report "$prefix/authorized_keys.bak"`,
		`cp report "$prefix/authorized_keys2.txt"`,
		`cp report "$out/my_authorized_keys"`,
		`cp report "${prefix}authorized_keys.orig"`,
		`cp report "$dir/authorized_keys-$stamp.txt"`,
		`cp report "$dir/$(date +%s)-authorized_keys.bak"`,
		`cp report "$dir/${name}s"`,
		`cp report "$dir/$name"`,
		`cp payload '~/.ssh/authorized_keys'`,
		`cp payload "~/.ssh/authorized_keys"`,
		`mv payload \~/.ssh/authorized_keys`,
		`touch '~/.ssh/authorized_keys'`,
		`mkdir -p '~/.ssh' && cp payload '~/.ssh/authorized_keys'`,
		`tee '~/.ssh/authorized_keys' < payload`,
		`ln -s '~/.ssh/authorized_keys' link`,
		`dd if=payload of='~/.ssh/authorized_keys'`,
		// Loop round 2: transparent wrappers and Git options that only
		// place the repository keep a quoted tilde literal.
		`git -C docs commit -m 'Document ~/.ssh/authorized_keys'`,
		`git -C docs --no-pager log --grep '~/.ssh/authorized_keys'`,
		`git --no-pager -C docs show HEAD -- '~/.ssh/authorized_keys'`,
		`git -P diff -- "~/.ssh/authorized_keys"`,
		`git grep -n '~/.ssh/authorized_keys'`,
		`command cp payload '~/.ssh/authorized_keys'`,
		`command -p cp payload "~/.ssh/authorized_keys"`,
		`command -- mv payload \~/.ssh/authorized_keys`,
		`builtin echo '~/.ssh/authorized_keys'`,
		`nohup cp payload '~/.ssh/authorized_keys'`,
		`nice -n 5 cp payload '~/.ssh/authorized_keys'`,
		`exec cp payload '~/.ssh/authorized_keys'`,
		`time cp payload '~/.ssh/authorized_keys'`,
		`env cp payload '~/.ssh/authorized_keys'`,
		`env -i LC_ALL=C cp payload '~/.ssh/authorized_keys'`,
		`LC_ALL=C grep -n '~/.ssh/authorized_keys' README.md`,
		`command nohup git -C docs commit -m 'Document ~/.ssh/authorized_keys'`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
	for _, command := range []string{
		`echo ~/.ssh/authorized_keys`,
		`echo ~/".ssh/authorized_keys"`,
		`echo '~/.ssh/authorized_keys' > notes.txt`,
		`echo "check ~/.ssh/authorized_keys" > notes.txt`,
		`cp payload ~/.ssh/authorized_keys`,
		`cp payload '~/.ssh/authorized_keys' > notes.txt`,
		`cp payload '~/x' && sh -c 'cat payload >> ~/.ssh/authorized_keys'`,
		`tee '~/.ssh/authorized_keys' < payload | sh`,
		`x=~/.ssh/authorized_keys; cp payload "$x"`,
		`dd if=payload of=~/.ssh/authorized_keys`,
		`python3 -c "import os; open(os.path.expanduser('~/.ssh/authorized_keys'),'a').write('k')"`,
		`python3 add_key.py '~/.ssh/authorized_keys'`,
		`echo 'cat payload >> ~/.ssh/authorized_keys' | s` + `h`,
		`eval "$(echo 'cp payload ~/.ssh/authorized_keys')"`,
		`git -c core.sshCommand='cat payload >> ~/.ssh/authorized_keys' fetch`,
		`cp payload "$prefix/authorized_keys"`,
		`cp payload "$prefix/authorized_keys2"`,
		`cp payload "$prefix"/authorized_keys`,
		`cp payload "$prefix/authorized_keys$suffix"`,
		`cp payload "$prefix/authorized_key$s"`,
		`cp payload "$prefix/authorized_k"*`,
		`cp payload "$prefix/${base}_keys"`,
		`cp payload "$prefix/$(printf %s authorized_keys)"`,
		`cp payload "$prefix/${x:+authorized_keys}"`,
		// Loop round 2 controls: an interpreting wrapper, option or
		// environment value may expand the quoted tilde later.
		`git -C docs -c core.pager='cat payload >> ~/.ssh/authorized_keys' log`,
		`git -c alias.x='!cp payload ~/.ssh/authorized_keys' -C docs commit -m x`,
		`git --config-env=core.pager=P -C docs log '~/.ssh/authorized_keys'`,
		`git --exec-path=. -C docs commit -m '~/.ssh/authorized_keys'`,
		`git -C docs grep -O'cp payload ~/.ssh/authorized_keys' x`,
		`git grep --open-files-in-pager='cp payload ~/.ssh/authorized_keys' x`,
		`git grep -nO'cp payload ~/.ssh/authorized_keys' x`,
		`git -C docs push origin '~/.ssh/authorized_keys'`,
		`GIT_PAGER='cat payload >> ~/.ssh/authorized_keys' git log`,
		`export GIT_PAGER='cat payload >> ~/.ssh/authorized_keys'; git log`,
		`EDITOR='cp payload ~/.ssh/authorized_keys' git -C docs commit`,
		`env GIT_PAGER='cat payload >> ~/.ssh/authorized_keys' git log`,
		`LESSOPEN='|cp payload ~/.ssh/authorized_keys' less README.md`,
		`command eval 'cp payload ~/.ssh/authorized_keys'`,
		`command sh -c 'cp payload ~/.ssh/authorized_keys'`,
		`builtin eval 'cp payload ~/.ssh/authorized_keys'`,
		`nohup sh -c 'cp payload ~/.ssh/authorized_keys'`,
		`exec sh -c 'cp payload ~/.ssh/authorized_keys'`,
		`env -S 'cp payload ~/.ssh/authorized_keys'`,
		`command cp payload '~/.ssh/authorized_keys' > notes.txt`,
		`nice -n 5 cp payload ~/.ssh/authorized_keys`,
		`command cp payload ~/.ssh/authorized_keys`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
}

func TestR104WindowsDynamicKeyComponent(t *testing.T) {
	const home = `C:\Users\b00`
	const cwd = `C:\work`
	for _, command := range []string{
		`Copy-Item payload $root\.ssh\authorized_keys.bak`,
		`Copy-Item payload %ROOT%\.ssh\authorized_keys2.txt`,
		`Copy-Item payload $env:TEMP\.ssh\my_authorized_keys`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
	for _, command := range []string{
		`Copy-Item payload $root\.ssh\authorized_keys`,
		`Copy-Item payload %ROOT%\.ssh\AUTHORIZED_KEYS2`,
		`Copy-Item payload $root\.ssh\authorized_keys$sfx`,
		`Copy-Item payload "$root\.ssh\authorized_keys"`,
		`Copy-Item payload $root\.ssh\authorized_k*`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
}
