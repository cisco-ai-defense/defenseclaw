// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCurrentUserKnownFolderPathIgnoresProcessEnvironmentOverrides(t *testing.T) {
	wantProfile, err := CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
	if err != nil {
		t.Fatal(err)
	}
	wantLocal, err := CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	foreignProfile := t.TempDir()
	for name, value := range map[string]string{
		"USERPROFILE":  foreignProfile,
		"HOME":         foreignProfile,
		"LOCALAPPDATA": filepath.Join(foreignProfile, "AppData", "Local"),
		"APPDATA":      filepath.Join(foreignProfile, "AppData", "Roaming"),
	} {
		t.Setenv(name, value)
	}
	gotProfile, err := CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
	if err != nil {
		t.Fatal(err)
	}
	gotLocal, err := CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.Clean(gotProfile), filepath.Clean(wantProfile)) {
		t.Fatalf("token-bound profile changed with process environment: got %q, want %q", gotProfile, wantProfile)
	}
	if !strings.EqualFold(filepath.Clean(gotLocal), filepath.Clean(wantLocal)) {
		t.Fatalf("token-bound LocalAppData changed with process environment: got %q, want %q", gotLocal, wantLocal)
	}
}

func TestExtendedLocalAndUNCPaths(t *testing.T) {
	local, err := Extended(filepath.Join(t.TempDir(), "nested", "file"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(local, `\\?\`) || strings.HasPrefix(local, `\\?\UNC\`) {
		t.Fatalf("local extended path = %q", local)
	}
	unc, err := Extended(`\\server\share\folder\file`)
	if err != nil {
		t.Fatal(err)
	}
	if unc != `\\?\UNC\server\share\folder\file` {
		t.Fatalf("UNC extended path = %q", unc)
	}
	if repeated, err := Extended(local); err != nil || repeated != local {
		t.Fatalf("idempotent extension = %q, %v", repeated, err)
	}
}

func TestExtendedRejectsEmptyAndNUL(t *testing.T) {
	for _, path := range []string{
		"",
		"bad\x00path",
		`\\.\PhysicalDrive0`,
		`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`,
		`\\?\UNC\server`,
	} {
		if _, err := Extended(path); err == nil {
			t.Fatalf("Extended(%q) succeeded", path)
		}
	}
}

func TestRejectReparseChainAllowsOrdinaryAndMissingLeafPaths(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existing, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}
	for _, path := range []string{
		existing,
		filepath.Join(root, "missing", "leaf.txt"),
	} {
		if err := RejectReparseChain(path); err != nil {
			t.Fatalf("RejectReparseChain(%q): %v", path, err)
		}
	}
}

func TestRejectReparseChainRejectsSymlinkPaths(t *testing.T) {
	t.Run("leaf file", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.txt")
		if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		link := filepath.Join(root, "link.txt")
		requireWinpathSymlink(t, target, link)
		if err := RejectReparseChain(link); err == nil {
			t.Fatal("leaf file symlink was accepted")
		}
	})

	t.Run("parent with existing descendant", func(t *testing.T) {
		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "child.txt"), []byte("fixture"), 0o600); err != nil {
			t.Fatalf("write target child: %v", err)
		}
		link := filepath.Join(t.TempDir(), "link")
		requireWinpathSymlink(t, target, link)
		if err := RejectReparseChain(filepath.Join(link, "child.txt")); err == nil {
			t.Fatal("symlink parent with existing descendant was accepted")
		}
	})

	t.Run("parent with missing descendant", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		requireWinpathSymlink(t, target, link)
		if err := RejectReparseChain(filepath.Join(link, "missing", "child.txt")); err == nil {
			t.Fatal("symlink parent with missing descendant was accepted")
		}
	})
}

func TestRejectReparseChainRejectsJunction(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	junction := filepath.Join(root, "junction")
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(junction); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove junction: %v", err)
		}
	})
	if err := RejectReparseChain(filepath.Join(junction, "missing", "leaf.txt")); err == nil {
		t.Fatal("junction was accepted")
	}
}

func requireWinpathSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
}
