//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0935, GAP-0680: the guardian keeps a copy of the recorded hook binary
// and puts a missing (quarantined), empty or different binary back from it;
// a copy of another release is never restored.
func TestKeepWindowsManagedFileCopyRestoresADamagedHookBinary(t *testing.T) {
	requireAdministratorTestToken(t, "the product restore writes the hook binary with the install file descriptor (an Administrators owner); the guardian runs it as SYSTEM, so the product writer, not the fixture, needs an administrator token")
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	for _, c := range []struct {
		name, state string
		damage      func() error
	}{
		{"missing", "missing", func() error { return os.Remove(target) }},
		{"empty", "empty", func() error { return os.WriteFile(target, nil, 0o600) }},
		{"hash mismatch", "hash mismatch", func() error { return os.WriteFile(target, []byte("other"), 0o600) }},
	} {
		if err := c.damage(); err != nil {
			t.Fatal(err)
		}
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || !strings.Contains(damage, c.state) {
			t.Fatalf("%s: restored %q, %v", c.name, damage, err)
		}
		if body, err := os.ReadFile(target); err != nil || string(body) != "hook release" {
			t.Fatalf("%s: restored %q, %v", c.name, body, err)
		}
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("healthy binary: restored %q, %v", damage, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	damage, err := keepWindowsManagedFileCopy(target, copyPath, "0000", true)
	if err == nil || damage != "" {
		t.Fatalf("a copy of another release was restored: %q, %v", damage, err)
	}
	// Only Setup carries a payload to restore the binary from, and it is not
	// installed on the computer: the error runs it from its folder and says
	// where it comes from (cowork-1-0-8 GAP-0095).
	if message := err.Error(); !strings.Contains(message, windowsEnterpriseSetupCommand("/repair", "JSON=1")) ||
		!strings.Contains(message, managed.WindowsSetupSource) || strings.Contains(message, "Setup /repair") {
		t.Fatalf("no-copy error = %q", message)
	}
}

// GAP-0934, GAP-0937: the copy an upgrade kept of the ACP guard an editor
// still ran goes as soon as nothing runs it; other files stay.
func TestRemoveWindowsReplacementCopiesRemovesOnlyUnusedCopies(t *testing.T) {
	dir := t.TempDir()
	unused := filepath.Join(dir, "defenseclaw-acp.exe.backup.b93b18a784c74be1bdd7803057d577bd")
	held := filepath.Join(dir, "defenseclaw-hook.exe.backup.d9a400178cdb4634a2599baba406ffd5")
	other := filepath.Join(dir, "defenseclaw-acp.exe.backup.notacopy")
	for _, path := range []string{unused, held, other} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A running program holds its image open without delete sharing.
	name, err := windows.UTF16PtrFromString(held)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	removed := removeWindowsReplacementCopies(dir)
	if len(removed) != 1 || removed[0] != unused {
		t.Fatalf("removed %q", removed)
	}
	for _, path := range []string{held, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

// GAP-0656: while a hook call runs the binary, Windows refuses to replace
// its last name, so the guardian's MoveFileEx restore failed until no hook
// ran. The one-step swap keeps the running program under a backup name,
// puts the new file in place, and a start right after runs the new one.
func TestCopyWindowsManagedFileSwapsARunningProgram(t *testing.T) {
	system := os.Getenv("SystemRoot")
	if system == "" {
		system = `C:\Windows`
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	for from, to := range map[string]string{
		filepath.Join(system, "System32", "PING.EXE"):     target,
		filepath.Join(system, "System32", "HOSTNAME.EXE"): source,
	} {
		body, err := os.ReadFile(from)
		if err != nil {
			t.Skipf("system program unavailable: %v", err)
		}
		if err := os.WriteFile(to, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	running := exec.Command(target, "-n", "30", "127.0.0.1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.Process.Kill(); _, _ = running.Process.Wait() }()
	time.Sleep(200 * time.Millisecond)
	if err := copyWindowsManagedFile(source, target, "", true); err != nil {
		t.Fatalf("replace the running program: %v", err)
	}
	want, err := windowsFileSHA256Hex(source)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := windowsFileSHA256Hex(target); err != nil || got != want {
		t.Fatalf("target is %s (%v), want the new program %s", got, err, want)
	}
	if damage, err := windowsHookBinaryStructuralDamage(target); err != nil || damage != "" {
		t.Fatalf("new target: %q, %v", damage, err)
	}
	if out, err := exec.Command(target).Output(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		t.Fatalf("start after the swap: %q, %v", out, err)
	}
	backups, err := filepath.Glob(target + ".backup.*")
	if err != nil || len(backups) != 1 || !windowsReplacementCopyPattern.MatchString(filepath.Base(backups[0])) {
		t.Fatalf("backup of the running program: %q, %v", backups, err)
	}
	if removed := removeWindowsReplacementCopies(dir); len(removed) != 0 {
		t.Fatalf("removed the image a program still runs: %q", removed)
	}
	_ = running.Process.Kill()
	_, _ = running.Process.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		removed := removeWindowsReplacementCopies(dir)
		if len(removed) == 1 && removed[0] == backups[0] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the backup stayed after the program ended: %q", removed)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := copyWindowsManagedFile(target, filepath.Join(dir, "missing.exe"), "", true); err != nil {
		t.Fatalf("a missing destination is still created: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.backup.*")); len(left) != 0 {
		t.Fatalf("leftover backups: %q", left)
	}
}
