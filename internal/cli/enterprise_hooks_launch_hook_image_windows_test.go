//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0751: the guardian restores the launch image every agent config names
// from its protected copy, with its own holder gate, and leaves a layout
// without a launch folder and the retained folders alone.
func TestKeepWindowsStandaloneLaunchHookImageRestoresTheLaunchImage(t *testing.T) {
	requireAdministratorTestToken(t, "the restore writes the hook with the install file descriptor (an Administrators owner)")
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	for _, dir := range []string{bin, filepath.Dir(copyPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "defenseclaw-hook.exe"), []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	previous := guardianTargetHookSHA256Hex
	guardianTargetHookSHA256Hex = windowsFileSHA256Hex
	t.Cleanup(func() { guardianTargetHookSHA256Hex = previous })

	var stderr bytes.Buffer
	// No launch folder: nothing is created (verify reports it).
	keepWindowsStandaloneLaunchHookImage(&stderr, bin, want, copyPath, true)
	if _, err := os.Lstat(filepath.Join(bin, "hooks")); !os.IsNotExist(err) {
		t.Fatalf("the guardian created bin\\hooks: %v", err)
	}
	folder := filepath.Join(bin, "hooks", want[:16])
	retained := filepath.Join(bin, "hooks", strings.Repeat("a", 16))
	for _, dir := range []string{folder, retained} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	launch := filepath.Join(folder, "defenseclaw-hook.exe")
	if err := os.WriteFile(launch, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(retained, "defenseclaw-hook.exe"), []byte("older release"), 0o600); err != nil {
		t.Fatal(err)
	}
	keepWindowsStandaloneLaunchHookImage(&stderr, bin, want, copyPath, true)
	if body, err := os.ReadFile(launch); err != nil || string(body) != "hook release" {
		t.Fatalf("launch image after the check = %q, %v; log %s", body, err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "restored the hook binary "+launch) {
		t.Fatalf("no tamper line: %s", stderr.String())
	}
	if windowsHookBinaryActiveGate != &windowsHolderGate {
		t.Fatal("the launch image check left its holder gate active")
	}
	// The retained folder's hook does not have the digest its name says: one
	// notice, never a restore.
	if body, _ := os.ReadFile(filepath.Join(retained, "defenseclaw-hook.exe")); string(body) != "older release" {
		t.Fatal("the guardian changed a retained launch image")
	}
	if n := strings.Count(stderr.String(), "retained hook image"); n != 1 {
		t.Fatalf("retained notices = %d: %s", n, stderr.String())
	}
	keepWindowsStandaloneLaunchHookImage(&stderr, bin, want, copyPath, true)
	if n := strings.Count(stderr.String(), "retained hook image"); n != 1 {
		t.Fatalf("the retained notice repeats: %s", stderr.String())
	}
	if got := windowsLaunchHookImageFolders(bin); len(got) != 2 {
		t.Fatalf("launch folders = %v", got)
	}
}
