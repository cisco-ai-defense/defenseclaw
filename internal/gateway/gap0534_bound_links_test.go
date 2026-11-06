// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// boundLinkHome lays out a home with the keys file, an agent settings file
// and a project whose ordinary-looking names are links to them (or a second
// hard name of the keys file), next to ordinary files and an ordinary link.
func boundLinkHome(t *testing.T) func(home, cwd string) {
	return func(home, cwd string) {
		t.Helper()
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
		must(os.MkdirAll(filepath.Join(home, ".claude"), 0o700))
		keys := filepath.Join(home, ".ssh", "authorized_keys")
		settings := filepath.Join(home, ".claude", "settings.json")
		must(os.WriteFile(keys, []byte("ssh-ed25519 AAAA test\n"), 0o600))
		must(os.WriteFile(settings, []byte("{}\n"), 0o600))
		must(os.WriteFile(filepath.Join(cwd, "plain.txt"), []byte("x\n"), 0o600))
		must(os.Symlink(keys, filepath.Join(cwd, "output")))
		must(os.Symlink(settings, filepath.Join(cwd, "report")))
		must(os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "shared")))
		must(os.Symlink(filepath.Join(cwd, "plain.txt"), filepath.Join(cwd, "latest")))
		must(os.Link(keys, filepath.Join(cwd, "mirror")))
	}
}

// GAP-0677 and GAP-0534 (review 3): a call the readers did not finish is
// graded by what its words reach, not only by what its text names. A word
// that is a link to the keys file or the agent settings, a link to the
// .ssh folder, or a second hard name of the keys file keeps the block in
// every tier, named directly or through a value the call assigns, however
// the call is nested. An ordinary file or link looks the same in the text and
// runs with an alert in the default tier.
func TestGAP0677BoundCallsThroughLinksKeepTheBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes, links and a mode 0 homes folder")
	}
	const prefix = `Write-Output $(.\a[1]<#x#>); `
	nested := func(body string) string { return readingBoundNest(10, body) }
	readingBoundCellsIn(t, []readingBoundRow{
		{"linked keys file", "Bash", nested("echo x > output"), guardrailActionBlock},
		{"linked keys file, known value", "Bash", "p=output; " + nested(`echo x > "$p"`), guardrailActionBlock},
		{"linked keys file, 12 levels", "Bash", readingBoundNest(12, "echo x > output"), guardrailActionBlock},
		{"linked agent settings", "Bash", nested("echo x > report"), guardrailActionBlock},
		{"linked folder, new file", "Bash", nested("echo x > shared/new-file"), guardrailActionBlock},
		{"second hard name of the keys file", "Bash", nested("echo x > mirror"), guardrailActionBlock},
		{"ordinary file", "Bash", nested("echo x > plain.txt"), guardrailActionAlert},
		{"ordinary link", "Bash", nested("echo x > latest"), guardrailActionAlert},
		{"ordinary new file", "Bash", nested("echo x > fresh.txt"), guardrailActionAlert},
		{"recovered parse, linked keys file", "PowerShell", prefix + "Remove-Item -Recurse -Force output", guardrailActionBlock},
		{"recovered parse, linked settings", "PowerShell", prefix + "Remove-Item -Recurse -Force report", guardrailActionBlock},
		{"recovered parse, ordinary file", "PowerShell", prefix + "Remove-Item -Recurse -Force plain.txt", guardrailActionAlert},
		{"recovered parse, ordinary link", "PowerShell", prefix + "Remove-Item -Recurse -Force latest", guardrailActionAlert},
	}, 0, boundLinkHome(t))
}

// GAP-0534 (review 3): an ordinary file whose name only contains a protected
// name (a settings, hooks or config name with more in it) is an ordinary
// target of a call the readers did not finish. The protected names stay
// protected as whole names.
func TestGAP0534BoundCallsNamedLikeProtectedFilesAreOrdinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	const prefix = `Write-Output $(.\a[1]<#x#>); `
	var rows []readingBoundRow
	for _, name := range []string{"notes-settings.json", "hooks.log", ".config-cache", "my_profile.txt", "settings.json.bak"} {
		rows = append(rows,
			readingBoundRow{"recovered parse, ordinary " + name, "PowerShell", prefix + "Remove-Item -Recurse -Force ~/project/" + name, guardrailActionAlert},
			readingBoundRow{"nested bodies, ordinary " + name, "Bash", readingBoundNest(10, "rm -f ~/project/"+name), guardrailActionAlert})
	}
	for _, name := range []string{"settings.json", "hooks.json", ".bashrc", "CLAUDE.md"} {
		rows = append(rows,
			readingBoundRow{"recovered parse, protected " + name, "PowerShell", prefix + "Remove-Item -Recurse -Force " + name, guardrailActionBlock},
			readingBoundRow{"nested bodies, protected " + name, "Bash", readingBoundNest(10, "rm -f "+name), guardrailActionBlock})
	}
	readingBoundCells(t, rows, 0)
}
