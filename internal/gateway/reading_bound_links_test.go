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
	rows := []readingBoundRow{
		{"linked keys file", "Bash", nested("echo x > output"), guardrailActionBlock},
		{"linked keys file, known value", "Bash", "p=output; " + nested(`echo x > "$p"`), guardrailActionBlock},
		{"linked folder, new file", "Bash", nested("echo x > shared/new-file"), guardrailActionBlock},
		{"second hard name of the keys file", "Bash", nested("echo x > mirror"), guardrailActionBlock},
		{"linked keys file, appended value", "Bash", "p=out; p+=put; " + nested(`echo x > "$p"`), guardrailActionBlock},
		{"linked keys file, empty substitution", "Bash", nested(`echo x > "out$(true)put"`), guardrailActionBlock},
		{"linked keys file, working directory", "Bash", nested(`echo x > "$PWD/output"`), guardrailActionBlock},
		{"ordinary file, appended value", "Bash", "p=plain; p+=.txt; " + nested(`echo x > "$p"`), guardrailActionAlert},
		{"ordinary file", "Bash", nested("echo x > plain.txt"), guardrailActionAlert},
		{"recovered parse, linked keys file", "PowerShell", prefix + "Remove-Item -Recurse -Force output", guardrailActionBlock},
		{"recovered parse, linked settings", "PowerShell", prefix + "Remove-Item -Recurse -Force report", guardrailActionBlock},
		{"recovered parse, ordinary file", "PowerShell", prefix + "Remove-Item -Recurse -Force plain.txt", guardrailActionAlert},
		{"recovered parse, ordinary link", "PowerShell", prefix + "Remove-Item -Recurse -Force latest", guardrailActionAlert},
	}
	// Each row runs in one default cell, per user and managed by turns
	// (test budget); the strict cells block every row.
	var cells [2][]readingBoundRow
	for index, row := range rows {
		cells[index%2] = append(cells[index%2], row)
	}
	for index, part := range cells {
		readingBoundCellsIn(t, part, 0, boundLinkHome(t), readingBoundDefaultCells[index:index+1])
	}
}

// GAP-0534 (reviews 3 and 6): an ordinary file whose name only contains a
// protected name (a settings, hooks or config name with more in it), or a
// project document named like agent hook settings (settings.json,
// hooks.json outside an agent folder), is an ordinary target of a call the
// readers did not finish. The protected names stay protected as whole names,
// and the settings names in an agent folder.
func TestGAP0534BoundCallsNamedLikeProtectedFilesAreOrdinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	const prefix = `Write-Output $(.\a[1]<#x#>); `
	recovered := func(target string) string { return prefix + "Remove-Item -Recurse -Force " + target }
	nested := func(target string) string { return readingBoundNest(10, "rm -f "+target) }
	readingBoundCellsIn(t, []readingBoundRow{
		{"recovered parse, ordinary notes-settings.json", "PowerShell", recovered("~/project/notes-settings.json"), guardrailActionAlert},
		{"nested bodies, ordinary hooks.log", "Bash", nested("~/project/hooks.log"), guardrailActionAlert},
		{"recovered parse, project settings.json", "PowerShell", recovered("~/project/settings.json"), guardrailActionAlert},
		{"nested bodies, project hooks.json", "Bash", nested("hooks.json"), guardrailActionAlert},
		{"recovered parse, protected .bashrc", "PowerShell", recovered(".bashrc"), guardrailActionBlock},
		{"nested bodies, protected CLAUDE.md", "Bash", nested("CLAUDE.md"), guardrailActionBlock},
		{"recovered parse, agent settings.json", "PowerShell", recovered("~/.claude/settings.json"), guardrailActionBlock},
		{"nested bodies, project agent settings.json", "Bash", nested(".claude/settings.json"), guardrailActionBlock},
	}, 0, nil, readingBoundDefaultCells)
}
