// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2168 (owner decision 2, TGT-0194): in action mode a plain read of a
// protected key file with no redirect, pipe into a writer or in-place flag
// stays allowed. grep, ssh-keygen -l, cmd type and the PowerShell search and
// select filters read only; a write in the same shapes still blocks.
func TestActionPlainReadOfAuthorizedKeysIsNotAWrite(t *testing.T) {
	if runtime.GOOS != "windows" {
		home := t.TempDir()
		cwd := filepath.Join(home, "proj")
		for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "k.pub")} {
			if err := os.WriteFile(name, []byte("ssh-ed25519 AAAA marker\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, command := range []string{
			"grep marker ~/.ssh/authorized_keys",
			"grep -c ssh-ed25519 ~/.ssh/authorized_keys",
			"egrep -n 'marker|other' ~/.ssh/authorized_keys",
			"ssh-keygen -l -f ~/.ssh/authorized_keys",
			"ssh-keygen -lf ~/.ssh/authorized_keys",
			"ssh-keygen -l -E sha256 -f ~/.ssh/authorized_keys",
			"cat ~/.ssh/authorized_keys | grep marker",
			// Codex wraps a command in an exit-status report; the wrapper
			// prints only (GAP-2168 live, Codex 0.159.3).
			`grep marker ~/.ssh/authorized_keys; status=$?; printf '\n[exit status] %s\n' "$status"; exit "$status"`,
			`grep marker ~/.ssh/authorized_keys; echo "exit=$?"`,
		} {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Errorf("ActionCommandDecision(%q) = %q, want allow", command, got)
			}
		}
		for _, command := range []string{
			"grep marker k.pub >> ~/.ssh/authorized_keys",
			"grep marker ~/.ssh/authorized_keys > ~/.ssh/authorized_keys2",
			"ssh-keygen -R host -f ~/.ssh/authorized_keys",
			"ssh-keygen -l -R host -f ~/.ssh/authorized_keys",
			"ssh-keygen -t ed25519 -N '' -f ~/.ssh/authorized_keys",
			"ssh-keygen -f ~/.ssh/authorized_keys",
			"cat k.pub | tee -a ~/.ssh/authorized_keys",
			`grep marker ~/.ssh/authorized_keys; status=$?; printf '%s\n' "$status" > ~/.ssh/authorized_keys`,
			`grep marker ~/.ssh/authorized_keys; printf 'k\n' >> ~/.ssh/authorized_keys`,
			`grep marker ~/.ssh/authorized_keys; echo ~/.ssh/authorized_keys`,
			`grep marker ~/.ssh/authorized_keys; echo done`,
			`grep marker ~/.ssh/authorized_keys; status=$?; echo "$status" "$HOME"`,
			`grep marker ~/.ssh/authorized_keys; PATH=/tmp/x; grep marker ~/.ssh/authorized_keys`,
			`grep marker ~/.ssh/authorized_keys; status=$(cp k.pub ~/.ssh/authorized_keys)`,
			`grep marker ~/.ssh/authorized_keys; exit "$(cp k.pub ~/.ssh/authorized_keys)"`,
		} {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
			}
		}
	}
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, command := range []string{
		`type %USERPROFILE%\.ssh\authorized_keys`,
		`Get-Content $HOME\.ssh\authorized_keys | Select-Object -First 1`,
		`Select-String marker $HOME\.ssh\authorized_keys`,
		`findstr marker %USERPROFILE%\.ssh\authorized_keys`,
		`Get-Content $HOME\.ssh\authorized_keys`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("Windows ActionCommandDecision(%q) = %q, want allow", command, got)
		}
	}
	for _, command := range []string{
		`type k.pub >> %USERPROFILE%\.ssh\authorized_keys`,
		`Get-Content k.pub | Add-Content $HOME\.ssh\authorized_keys`,
		`Get-Content $HOME\.ssh\authorized_keys | Select-Object -First 1 | Set-Content $HOME\.ssh\authorized_keys`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("Windows ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
}
