// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0751: the launch folders under bin\hooks get the protection of bin and
// their hook that of bin's hook; without a hooks folder (Secure Client, a
// 1.0.9 layout) the list is what it was.
func TestManagedInstallLayoutListsHookImageFolders(t *testing.T) {
	install := t.TempDir()
	bin := filepath.Join(install, "bin")
	layout := ManagedInstallLayout{InstallRoot: install}
	before := len(layout.targets())
	if err := os.MkdirAll(filepath.Join(bin, "hooks", "0123456789abcdef"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".staging-" + strings.Repeat("a", 32), "notes", "0123456789abcdeg"} {
		if err := os.MkdirAll(filepath.Join(bin, "hooks", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "hooks", "fedcba9876543210"), []byte("a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, target := range layout.targets()[before:] {
		added = append(added, string(target.kind)+":"+target.path)
	}
	want := []string{
		"ServiceInstallDirectory:" + filepath.Join(bin, "hooks"),
		"ServiceInstallDirectory:" + filepath.Join(bin, "hooks", "0123456789abcdef"),
		"InstallFile:" + filepath.Join(bin, "hooks", "0123456789abcdef", "defenseclaw-hook.exe"),
	}
	if strings.Join(added, "\n") != strings.Join(want, "\n") {
		t.Fatalf("added targets:\n%s\nwant:\n%s", strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	for _, target := range layout.targets()[before:] {
		if target.content {
			t.Fatalf("%s is listed as content; the install tree is not", target.path)
		}
	}
}

func TestManagedInstallLayoutWithoutHookImagesIsUnchanged(t *testing.T) {
	install := t.TempDir()
	if err := os.MkdirAll(filepath.Join(install, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, target := range (ManagedInstallLayout{InstallRoot: install}).targets() {
		if strings.Contains(target.path, "hooks") {
			t.Fatalf("a layout without bin\\hooks lists %s", target.path)
		}
	}
	// A link at bin\hooks is not walked.
	if err := os.Symlink(t.TempDir(), filepath.Join(install, "bin", "hooks")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if folders, ok := managedInstallHookImageFolders(filepath.Join(install, "bin")); ok || len(folders) != 0 {
		t.Fatalf("link at bin\\hooks = %v, %v", folders, ok)
	}
}
