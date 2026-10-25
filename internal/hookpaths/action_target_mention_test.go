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
		"cd -- " + filepath.Join(home, ".ssh") + " && cat authorized_keys",
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
		"echo '$HOME/.ssh/authorized_keys'",
		"echo \\$HOME/.ssh/authorized_keys",
		"grep marker " + target,
		"stat " + target,
		"cd " + filepath.Join(home, ".ssh"),
		"pushd " + filepath.Join(home, ".ssh"),
		"popd",
		"cd -- " + filepath.Join(home, ".ssh"),
		"ls " + filepath.Join(home, ".ssh"),
		"cp report.pub result.pub",
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
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
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`Get-Content ` + target,
		`Get-Content ` + target + ` | Select-Object -First 1`,
		`cat ` + target + ` | head -n 1`,
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
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("POSIX target %q decision = %q", command, got)
		}
	}
	for _, command := range []string{
		"cat " + target,
		"cd /home/alice/.ssh",
		"cd -- /home/alice/.ssh",
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
