// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestReviewHP3WindowsReadings holds the independent review rows of
// fix/r107-bd-hookparse3 for the Windows readings (IN-bd-hookparse3-REVIEW.md).
// Each row is asserted in the unhinted and PowerShell readings; posix rows
// also in the POSIX hint. want "?" is a logged probe.
func TestReviewHP3WindowsReadings(t *testing.T) {
	const home = `C:\Users\b00`
	envelope := "*** Begin Patch\n*** Update File: notes.txt\n@@\n marker\n+x\n*** End Patch"
	const pt = "protected-target"
	rows := []struct {
		name, command, want string
		posix               bool
	}{
		// rel-1-0-6:GAP-0236: a here-string that a later writer reaches.
		{"0236-outvariable", "Write-Output @\x27\n.ssh/authorized_keys\n\x27@ -OutVariable t; Add-Content -Path $t -Value k", pt, false},
		{"0236-ov-alias", "Write-Output @\x27\n.ssh/authorized_keys\n\x27@ -ov t; Add-Content -Path $t -Value k", pt, false},
		{"0236-global-scope", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Add-Content -Path $global:t -Value k", pt, false},
		{"0236-script-scope", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Add-Content -Path $script:t -Value k", pt, false},
		{"0236-get-variable", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Add-Content -Path (Get-Variable t -ValueOnly) -Value k", pt, false},
		{"0236-variable-drive", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Add-Content -Path (Get-Content variable:t) -Value k", pt, false},
		{"0236-redirect-target", "Write-Output k >> @\x27\n.ssh/authorized_keys\n\x27@", pt, false},
		{"0236-allow-print", "Write-Output @\x27\n.ssh/authorized_keys\n\x27@", "", false},
		{"0236-nested-writer-herestring", "Write-Output (Set-Content -Path @\x27\n.ssh/authorized_keys\n\x27@ -Value k)", pt, false},
		// rel-1-0-6:GAP-0211: an unquoted print pattern that a writer reaches.
		{"0211-pipe-get-item-add", "echo .ssh/authorized_k* | Get-Item | Add-Content -Value k", pt, false},
		{"0211-pipe-remove-item", "echo .ssh/authorized_k* | Remove-Item", pt, false},
		{"0211-pipe-delay-bind", "echo .ssh/authorized_k* | Add-Content -Path {$_} -Value k", pt, false},
		{"0211-outvariable", "Write-Output .ssh/authorized_k* -OutVariable p; Add-Content -Path $p -Value k", pt, false},
		{"0211-paren-path", "Add-Content -Path (echo .ssh/authorized_k*) -Value k", pt, false},
		{"0211-subexpr-path", "Add-Content -Path $(echo .ssh/authorized_k*) -Value k", pt, false},
		{"0211-quoted-pipe-remove-item", "echo \x27.ssh/authorized_k*\x27 | Remove-Item", pt, false},
		{"0211-quoted-pipe-get-item-add", "echo \x27.ssh/authorized_k*\x27 | Get-Item | Add-Content -Value k", pt, false},
		{"0211-git-checkout", "git checkout -- .ssh/authorized_k*", "?", false},
		{"0211-git-restore", "git restore .ssh/authorized_k*", "?", false},
		{"0211-allow-echo-star", "echo *", "", false},
		// rel-1-0-4:GAP-2590: a discarded output is no read-only pass for a writer.
		{"2590-uniq-output-operand", "uniq a.txt .ssh/authorized_keys > /dev/null", pt, true},
		{"2590-discard-then-write", "cat a.txt > $null > .ssh/authorized_keys", pt, false},
		{"2590-sort-o-discard", "sort -o .ssh/authorized_keys a.txt > /dev/null", pt, true},
		// rel-1-0-6:GAP-0237: a here-doc body that holds a quote character.
		{"0237-heredoc-apostrophe-unquoted", "echo hi <<EOF\nit\x27s\nEOF\ncp a.txt .ssh/authorized_k*", pt, true},
		{"0237-heredoc-apostrophe-add", "echo hi <<EOF\nit\x27s\nEOF\nAdd-Content -Path \x27.ssh/authorized_k*\x27 -Value k", "?", false},
		// IN-bd-classifier review rows not pinned elsewhere.
		{"1717-envelope-second-line", "printf \x27" + envelope + "\x27\nAdd-Content -Path \x27.ssh/authorized_k*\x27 -Value k", pt, false},
		{"1717-envelope-second-line-crlf", "printf \x27" + envelope + "\x27\r\nRemove-Item \x27.ssh/authorized_k*\x27", pt, false},
		{"1717-list-xargs", "printf \x27.ssh/authorized_k*\x27 > list.txt; cat list.txt | xargs -I{} cp a.txt {}", pt, false},
		{"1717-list-xargs-echo-twin", "echo \x27.ssh/authorized_k*\x27 > list.txt; cat list.txt | xargs -I{} cp a.txt {}", "?", false},
		{"1717-list-foreach", "printf \x27.ssh/authorized_k*\x27 > list.txt; Get-Content list.txt | % { Add-Content -Path $_ -Value k }", "?", false},
		{"1717-list-foreach-echo-twin", "echo \x27.ssh/authorized_k*\x27 > list.txt; Get-Content list.txt | % { Add-Content -Path $_ -Value k }", "?", false},
		{"0310-win-escaped-semicolon", "pwsh -Command Get-ChildItem ~/.ssh \\; Add-Content .ssh/authorized_keys k", pt, false},
		{"0310-win-quoted-pipe-remove", "pwsh -Command Get-ChildItem .ssh/authorized_keys \"|\" Remove-Item", pt, false},
		{"0310-win-quoted-semicolon", "pwsh -Command Get-ChildItem ~/.ssh \";\" Set-Content .ssh/authorized_keys k", pt, false},
		{"0310-win-split-list", "pwsh -Command Get-ChildItem ~/.ssh", "?", false},
		{"0310-win-glob", "pwsh -Command Get-ChildItem ~/.ssh/*", "?", false},
		{"0310-win-var", "pwsh -Command Get-ChildItem $env:USERPROFILE/.ssh", "?", false},
		// rel-1-0-6:GAP-0298 in the Windows readings.
		{"0298-md-then-set", "md ~/.ssh; Set-Content .ssh/authorized_keys k", pt, true},
		{"0298-mkdir-redirect", "mkdir ~/.ssh -Force > .ssh/authorized_keys", pt, false},
		{"0298-mkdir-two", "mkdir ~/.ssh ~/.ssh/authorized_keys", pt, true},
		{"0298-chmod-two", "chmod 700 ~/.ssh .ssh/authorized_keys", pt, true},
		{"0298-mkdir-value", "mkdir ~/.ssh -Value k", "?", false},
		// Round 2 rows (display sinks, here-string later use).
		{"r2-0211-pipe-findstr-remove-item", "echo .ssh/authorized_k* | findstr ssh | Remove-Item", pt, false},
		{"r2-0211-allow-pipe-findstr", "echo .ssh/authorized_k* | findstr ssh", "", false},
		{"r2-0211-allow-pipe-findstr-exe", "echo .ssh/authorized_k* | findstr.exe ssh", "", false},
		{"r2-0211-sink-outvariable", "echo .ssh/authorized_k* | Out-String -Stream -OutVariable p; Remove-Item $p", pt, false},
		{"r2-0211-sink-ov-alias", "echo .ssh/authorized_k* | Out-String -Stream -ov p; Remove-Item $p", pt, false},
		{"r2-0211-quoted-sink-outvariable", "echo \x27.ssh/authorized_k*\x27 | Out-String -Stream -OutVariable p; Remove-Item $p", pt, false},
		{"r2-0211-allow-sink-out-string", "echo .ssh/authorized_k* | Out-String -Stream", "", false},
		{"r2-0211-redirect-file-read-back", "Write-Output .ssh/authorized_k* > list.txt; Get-Content list.txt | Remove-Item", pt, false},
		{"r2-0211-allow-discard", "Write-Output .ssh/authorized_k* > $null", "", false},
		{"r2-0211-allow-nonewline-colon", "Write-Host -NoNewline:$true .ssh/authorized_k*", "", false},
		{"r2-0211-allow-quoted-dash-word", "Write-Output \x27-v\x27 .ssh/authorized_k*", "", false},
		{"r2-0236-allow-discard", "Write-Output @\x27\n.ssh/authorized_keys\n\x27@ > $null", "", false},
		{"r2-0236-redirect-file", "Write-Output @\x27\n.ssh/authorized_keys\n\x27@ > list.txt; Get-Content list.txt | Remove-Item", pt, false},
		{"r2-0236-quoted-subexpr", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$(Remove-Item $t)\"", pt, false},
		{"r2-0236-quoted-subexpr-braced", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$(Remove-Item ${t})\"", pt, false},
		{"r2-0236-quoted-subexpr-global", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$(Remove-Item $global:t)\"", pt, false},
		{"r2-0236-quoted-subexpr-gv", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$(Remove-Item (Get-Variable t -ValueOnly))\"", pt, false},
		{"r2-0236-quoted-subexpr-ec", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$($ExecutionContext.SessionState.PSVariable.GetValue(\x27t\x27) | Remove-Item)\"", pt, false},
		{"r2-0236-pipe-later", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output x | Remove-Item -Path $t", pt, false},
		{"r2-0236-quoted-subexpr-gv-alias", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$(Remove-Item (gv t -ValueOnly))\"", pt, false},
		{"r2-0236-iex-built-name", "$t = @\x27\n.ssh/authorized_keys\n\x27@; iex (\x27Remove-Item $\x27 + \x27t\x27)", pt, false},
		{"r2-0236-quoted-subexpr-ec-invoke", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output \"$($ExecutionContext.InvokeCommand.InvokeScript(\x27Remove-Item $\x27 + \x27t\x27))\"", pt, false},
		{"r2-0236-pipe-foreach-gv", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output t | % { gv $_ -ValueOnly } | Remove-Item", pt, false},
		{"r2-0298-win-mkdir-dotdot", "mkdir -p ~/.ssh/authorized_keys/..", pt, true},
		{"r2-0236-allow-assign-then-print", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Write-Output done", "", false},
		{"r2-0236-allow-assign-then-read", "$t = @\x27\n.ssh/authorized_keys\n\x27@; Get-ChildItem .", "", false},
		{"0298-allow-mkdir", "mkdir -p ~/.ssh", "", true},
	}
	for _, row := range rows {
		for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell, actionfacts.DialectPOSIX} {
			got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, dialect, nil)
			t.Logf("HP3WIN %s | %q | %q | want %q", row.name, dialect, got, row.want)
			if row.want == "?" || dialect == actionfacts.DialectPOSIX && !row.posix {
				continue
			}
			if got != row.want {
				t.Errorf("%s dialect %q %q = %q, want %q", row.name, dialect, row.command, got, row.want)
			}
		}
	}
}

// TestReviewHP3PosixRows pins at the hookpaths level the POSIX conditions
// the gateway otherwise backstops (review mutations M05, M06, M09): a
// redirect of the .ssh setup, a writer after it, and a writer on a link a
// plain rm removes in the same command.
func TestReviewHP3PosixRows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX links")
	}
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"keylink": "../.ssh/authorized_keys", "sshlink": "../.ssh"} {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, command, want string }{
		{"0298-mkdir-redirect-keys", "mkdir -p ~/.ssh > ~/.ssh/authorized_keys", "protected-target"},
		{"0298-setup-stderr-link", "mkdir -p ~/.ssh && chmod 700 ~/.ssh 2> keylink", "protected-target"},
		{"0298-setup-then-cp", "mkdir -p ~/.ssh && cp a.txt keylink", "protected-target"},
		{"0298-mkdir-pm777", "mkdir -pm777 ~/.ssh", "protected-target"},
		{"2590-rm-then-cp", "rm keylink && cp a.txt keylink", "protected-target"},
		{"2590-cp-then-rm", "cp a.txt keylink && rm keylink", "protected-target"},
		{"2590-rm-then-tee", "rm keylink && tee -a keylink < a.txt", "protected-target"},
		{"2590-rm-then-sort-o", "rm keylink; sort -o keylink a.txt", "protected-target"},
		{"2590-allow-live", "ls -l keylink && rm keylink && ls keylink; echo done", ""},
		{"0298-allow-setup", "mkdir -p ~/.ssh && chmod 700 ~/.ssh", ""},
	} {
		got := ActionCommandDecision(row.command, project, home)
		t.Logf("HP3WIN %s | posix-linux | %q | want %q", row.name, got, row.want)
		if got != row.want {
			t.Errorf("%s %q = %q, want %q", row.name, row.command, got, row.want)
		}
	}
}
