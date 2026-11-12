// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A directory link whose target starts at the drive root (\Users\x) reaches
// the same file as the absolute spelling of that target, with a middle
// component, for an existing file and for a new file name.
func TestResolveWriteTargetFollowsADriveRootedDirectoryLink(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "proj")
	target := filepath.Join(root, "Users", "acct", "AppData", "Roaming", "PSReadLine")
	for _, dir := range []string{project, target} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	history := filepath.Join(target, "ConsoleHost_history.txt")
	if err := os.WriteFile(history, []byte("h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rooted := target[len(filepath.VolumeName(target)):]
	link := filepath.Join(project, "history-dir")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/D", link, rooted).CombinedOutput(); err != nil {
		t.Skipf("no symbolic link privilege: %v: %s", err, out)
	}
	for _, name := range []string{"ConsoleHost_history.txt", "NewFile.txt"} {
		got, ok := ResolveWriteTarget(filepath.Join(link, name))
		if want := filepath.Join(target, name); !ok || got != want {
			t.Errorf("ResolveWriteTarget(%s) = %q, %v; want %q", name, got, ok, want)
		}
	}
}
