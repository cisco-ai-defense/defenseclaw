// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestR104ActionProtectedMentionIndependentOfOperandRole(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(target, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"cp " + target + " report.pub",
		"python3 safe.py " + target,
		"echo " + target,
		"cat " + target + " > out.log",
		"cat " + target + " | tee out.log",
		"sed --in s/a/b/ " + target,
		"cp report.pub --output=" + target,
		"git show HEAD --output=" + target,
		"rg --pre='sh -c \"echo marker > " + target + "\"' marker .",
		"cd " + filepath.Join(home, ".ssh") + " && echo " + target,
		"grep marker report.pub >> " + target,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		"cat " + target,
		"cat " + target + " | head -n 1",
		// A plain read stays allowed in action (owner decision 2, GAP-2168).
		"grep marker " + target,
		"echo '$HOME/.ssh/authorized_keys'",
		"stat " + target,
		"cd " + filepath.Join(home, ".ssh"),
		"pushd " + filepath.Join(home, ".ssh"),
		"popd",
		"cd -- " + filepath.Join(home, ".ssh"),
		"cd -- " + filepath.Join(home, ".ssh") + " && cat authorized_keys",
		"ls " + filepath.Join(home, ".ssh"),
		"cp report.pub result.pub",
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
	// A POSIX shell keeps an escaped dollar literal. A Windows home selects
	// the PowerShell grammar, where a backslash is a path separator and
	// $HOME still expands, so there the same text names the protected file
	// like any echo of it. The single-quoted literal above is allowed on both.
	escaped := "echo \\$HOME/.ssh/authorized_keys"
	wantEscaped := ""
	if actionWindowsHome(home) {
		wantEscaped = "protected-target"
	}
	if got := ActionCommandDecision(escaped, cwd, home); got != wantEscaped {
		t.Errorf("escaped dollar %q decision = %q, want %q", escaped, got, wantEscaped)
	}
	if runtime.GOOS != "windows" {
		for _, command := range []string{
			"sh -c 'echo marker > $HOME/.ssh/authorized_keys'",
			`env -S 'sh -c "echo marker > $HOME/.ssh/authorized_keys"'`,
			`env -u OLD -S 'sh -c "echo marker > $HOME/.ssh/authorized_keys"'`,
			`env -u OLD --split-string 'sh -c "echo marker > $HOME/.ssh/authorized_keys"'`,
		} {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Errorf("nested shell %q decision = %q, want protected-target", command, got)
			}
		}
	}
}

func TestR104WindowsProtectedMentionNormalizationAndReadOnly(t *testing.T) {
	const home = `C:\Users\Alice`
	const cwd = home + `\project`
	const target = `C:\Users\Alice\.ssh\authorized_keys`
	for _, command := range []string{
		`cp ` + target + ` report.pub`,
		`echo ` + target,
		`cp report.pub --future-output=` + target,
		`Copy-Item -FutureSwitch:` + target + ` report.pub`,
		`git show HEAD --output=` + target,
		`rg --pre="cmd /c echo marker > ` + target + `" marker .`,
		`cp report.pub C:\Users\Alice\project\..\.ssh\authorized_keys`,
		`cd C:\Users\Alice\.ssh && echo ` + target,
		`cp report.pub C:\Users\Alice\.ssh\missing~1`,
		`cat ` + target + ` > out.log`,
		`cat ` + target + ` | tee out.log`,
		`timeout 5 cp report.pub ` + target,
		`pwsh -Command 'Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker'`,
		`powershell.exe -NoProfile -Command 'Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker'`,
		`env -S 'pwsh -Command "Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker"'`,
		`env -u OLD -S 'pwsh -Command "Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker"'`,
		`env -u OLD --split-string 'pwsh -Command "Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value marker"'`,
		`Get-Content ` + target + ` | Select-Object -First 1 | Set-Content ` + target,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`Get-Content ` + target,
		`cat ` + target + ` | head -n 1`,
		// A read piped into a select filter writes nothing, as cat | head
		// (owner decision 2, GAP-2168).
		`Get-Content ` + target + ` | Select-Object -First 1`,
		`Test-Path C:\Users\Alice\.ssh`,
		`cd C:\Users\Alice\.ssh`,
		`cd -- C:\Users\Alice\.ssh`,
		`pushd C:\Users\Alice\.ssh`,
		`pushd -- C:\Users\Alice\.ssh`,
		`popd`,
		`Set-Location -Path C:\Users\Alice\.ssh`,
		`Push-Location -LiteralPath C:\Users\Alice\.ssh`,
		`Get-ChildItem C:\Users\Alice\.ssh`,
		`dir C:\Users\Alice\.ssh`,
		`ls C:\Users\Alice\.ssh`,
		`stat C:\Users\Alice\.ssh`,
		`Get-Content C:\Users\Alice\.ssh\missing~1`,
		`cp report.pub C:\Users\Alice\project\missing~1`,
		`cp report.pub C:\Users\Alice\.ssh\..\project\missing~1`,
		`cp report.pub report.txt`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
	if reason := ActionCommandAuditReason(`cp report.pub C:\Users\Alice\.ssh\missing~1`, cwd, home); reason == "" {
		t.Fatal("unresolved protected-directory path needs an audit reason")
	}
	if got, known := actionWindowsPath(`\\server\share\project\..\report.txt`, cwd, home); !known || got != "//server/share/report.txt" {
		t.Fatalf("UNC traversal = %q, known=%t", got, known)
	}
}

func TestR104ActionProtectedMentionBeforeSSHDirectoryExists(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "remote-home")
	cwd := filepath.Join(root, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	for _, command := range []string{
		"echo " + target,
		`node -e 'require("fs").readFileSync("` + target + `")'`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("uncreated protected target %q decision = %q", command, got)
		}
	}
	for _, command := range []string{
		"cat " + target,
		"echo ok > " + filepath.Join(home, ".ssh", "known_hosts"),
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("ordinary/read-only %q decision = %q", command, got)
		}
	}
}

func TestR104PosixHomeTargetMentionOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows host resolving a POSIX shell home")
	}
	const home, cwd = "/home/alice", "/repo"
	const target = "/home/alice/.ssh/authorized_keys"
	for _, command := range []string{
		"echo " + target,
		"echo $HOME/.ssh/authorized_keys",
		"echo ~/.ssh/authorized_keys",
		"cp payload ~/.ssh/authorized_k*",
		"cd ~/.ssh && echo authorized_keys",
		`pushd ~/.ssh && sh "$script" authorized_keys`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("POSIX target %q decision = %q", command, got)
		}
	}
	for _, command := range []string{
		"cat " + target,
		"cd /home/alice/.ssh",
		"cd -- /home/alice/.ssh",
		"cd ~/.ssh && ls -la",
		"cd ~/.ssh && cat authorized_keys",
		"echo /repo/report.txt",
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("POSIX ordinary/read-only %q decision = %q", command, got)
		}
	}
}

func TestR104ActiveDefenseClawStateTargetMention(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	for _, command := range []string{
		"echo " + state,
		"cp " + state + " report.txt",
		"printf marker > " + filepath.Join(home, "project", "..", ".defenseclaw", "config.yaml"),
		"cp report.txt --future-output=" + state,
		"echo " + filepath.Join(home, ".defenseclaw", "device.key"),
		"echo " + filepath.Join(home, ".defenseclaw", "policies", "active.yaml"),
	} {
		if !ActionStateTargetMention(command, cwd, home) {
			t.Errorf("active state %q lacks protected-state mention", command)
		}
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("active state %q was attributed to SSH: %q", command, got)
		}
	}
	for _, command := range []string{
		"cat " + state,
		"printf marker > .defenseclaw/config.yaml",
		"printf marker > " + filepath.Join(home, ".defenseclaw", "logs", "gateway.log"),
		"printf marker > " + filepath.Join(home, "other", "config.yaml"),
	} {
		if ActionStateTargetMention(command, cwd, home) {
			t.Errorf("ordinary/read-only %q has protected-state mention", command)
		}
	}
}

func TestR104WindowsActiveDefenseClawStateTargetMention(t *testing.T) {
	const home = `C:\Users\Alice`
	const cwd = home + `\project`
	const state = home + `\.defenseclaw\config.yaml`
	for _, command := range []string{
		`echo ` + state,
		`Copy-Item report.txt -FutureSwitch:` + state,
		`Set-Content -LiteralPath ` + home + `\project\..\.defenseclaw\config.yaml -Value marker`,
	} {
		if !ActionStateTargetMention(command, cwd, home) {
			t.Errorf("Windows active state %q lacks protected-state mention", command)
		}
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("Windows active state %q was attributed to SSH: %q", command, got)
		}
	}
	for _, command := range []string{
		`Get-Content ` + state,
		`Set-Content -LiteralPath .defenseclaw\config.yaml -Value marker`,
		`Set-Content -LiteralPath ` + home + `\.defenseclaw\logs\gateway.log -Value marker`,
	} {
		if ActionStateTargetMention(command, cwd, home) {
			t.Errorf("Windows ordinary/read-only %q has protected-state mention", command)
		}
	}
}

func TestR104ActionArgvGlobProtectedMention(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".ssh", "authorized_key")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`"$tool" ~/.ssh/authorized_k*`,
		`cp payload ~/.ssh/authorized_ke?`,
		`install -m 600 payload ~/.ssh/authorized_k[e]ys`,
		`rsync payload ~/.ssh/authorized_key?`,
		`tee ~/.ssh/authorized_k* < payload`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	if got := ActionCommandDecision(`cp payload ~/.ssh/*.pub`, cwd, home); got != "" {
		t.Fatalf("ordinary glob decision = %q", got)
	}
	if runtime.GOOS != "windows" {
		if got := ActionCommandDecision(`cp payload '~/.ssh/authorized_k*'`, cwd, home); got != "" {
			t.Fatalf("literal glob decision = %q", got)
		}
	}
}

func TestR104WindowsActionArgvGlobProtectedMention(t *testing.T) {
	const home = `C:\Users\b00`
	const cwd = `C:\work`
	for _, command := range []string{
		`cp payload C:\Users\b00\.ssh\authorized_k*`,
		`Copy-Item payload $HOME\.ssh\authorized_key?`,
		`install -m 600 payload C:\Users\b00\.ssh\authorized_k[e]ys`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("protected glob %q decision = %q", command, got)
		}
	}
	if got := ActionCommandDecision(`cp payload C:\Users\b00\.ssh\*.pub`, cwd, home); got != "" {
		t.Errorf("ordinary glob decision = %q", got)
	}
}

func TestR104WindowsNestedProtectedMention(t *testing.T) {
	const home = `C:\Users\b00`
	const cwd = `C:\work`
	const target = `C:\Users\b00\.ssh\authorized_keys`
	for _, command := range []string{
		`Get-ChildItem C:\Users\b00\.ssh | Select-Object @{e={Set-Content ` + target + ` marker}}`,
		`Get-ChildItem C:\Users\b00\.ssh | Select-Object -Property {Add-Content -Path ` + target + ` -Value marker}`,
		`Get-Content C:\work\a.txt | Select-Object {Set-Content $env:USERPROFILE\.ssh\authorized_keys marker}`,
		`[System.IO.File]::ReadAllText('C:/work/a.txt') + [System.IO.File]::AppendAllText('C:/Users/b00/.ssh/authorized_keys','marker')`,
		`[IO.File]::ReadAllText([IO.File]::AppendAllText('C:/Users/b00/.ssh/authorized_keys','marker'))`,
		`Test-Path (Add-Content -Path ` + target + ` -Value marker -PassThru)`,
		`Get-Item (Set-Content -Path $HOME\.ssh\authorized_keys -Value marker -PassThru)`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
}

func TestR104ActionSSHDirectoryOnlyMentions(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`cd ~/.ssh && ls -la`,
		`ls -la ~/.ssh`,
		`stat ~/.ssh`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("directory-only decision = %q, want allow", got)
			}
		})
	}
	for _, command := range []string{
		`ls -la ~/.ssh; pwd`,
		`find ~/.ssh -name '*.pub'`,
		`cd ~/.ssh && pwd`,
		`ls ~/.ssh && echo done`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("directory named outside read-only list %q: %q", command, got)
		}
	}
	const winHome = `C:\Users\b00`
	const winCWD = `C:\work`
	for _, command := range []string{
		`Set-Location C:\Users\b00\.ssh; Get-ChildItem`,
		`Push-Location C:\Users\b00\.ssh; Get-ChildItem; Pop-Location`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, winCWD, winHome); got != "" {
				t.Fatalf("directory-only decision = %q, want allow", got)
			}
		})
	}
	for _, command := range []string{
		`Get-ChildItem C:\Users\b00\.ssh | Format-Table Name`,
		`foreach ($n in Get-ChildItem C:\Users\b00\.ssh) { Write-Output $n.Name }`,
	} {
		if got := ActionCommandDecision(command, winCWD, winHome); got != "protected-target" {
			t.Errorf("directory named outside read-only list %q: %q", command, got)
		}
	}
}

func TestR104LessOutputProtectedMention(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	for _, option := range []string{"-o", "-O", "--log-file"} {
		if got := ActionCommandDecision("cat payload | less "+option+" "+target, cwd, home); got != "protected-target" {
			t.Errorf("less %s decision = %q", option, got)
		}
	}
	if got := ActionCommandDecision("less "+target, cwd, home); got != "" {
		t.Errorf("read-only less decision = %q", got)
	}
}

func TestR104DirectoryScopedWriteSurvivesDirectoryMentionExemption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory write proof uses native POSIX paths")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ssh, filepath.Join(cwd, "dirlink")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"cd dirlink && echo marker >> authorized_keys",
		"env -C dirlink python3 <<'PY'\nopen(\"authorized_keys\",\"a\").write(\"marker\")\nPY",
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			writes, unknown := ShellDirectoryWriteOperands(command, cwd, home, nil, false, false)
			t.Errorf("directory-scoped write %q decision = %q, directory writes=%v unknown=%v", command, got, writes, unknown)
		}
	}
	if got := ActionCommandDecision("cd dirlink && cat authorized_keys", cwd, home); got != "" {
		t.Errorf("read-only directory command decision = %q", got)
	}
	if got := ActionCommandDecision("env -C build python3 <<'PY'\nopen(\"authorized_keys\",\"a\").write(\"marker\")\nPY", cwd, home); got != "" {
		t.Errorf("ordinary directory write decision = %q", got)
	}
}
