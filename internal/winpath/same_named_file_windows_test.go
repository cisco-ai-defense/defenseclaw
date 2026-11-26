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

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// gap2175Image lays out a stand-in for an installed hook image folder. Its
// long names get 8.3 short names where the volume makes them.
func gap2175Image(t *testing.T) (root, hook, other string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, "DefenseClaw Program Files", "hooks", "e1132b0123456789")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hook = filepath.Join(dir, "defenseclaw-hook.exe")
	other = filepath.Join(dir, "defenseclaw-other.exe")
	for _, path := range []string{hook, other} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root, hook, other
}

// gap2175Short is the 8.3 spelling of an existing path; it skips when the
// volume makes no short names.
func gap2175Short(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	short := windows.UTF16ToString(buffer[:n])
	if !strings.Contains(short, "~") || strings.EqualFold(short, path) {
		t.Skipf("the volume of %s makes no 8.3 short names", path)
	}
	return short
}

func TestGAP2175SameNamedFileAcceptsTheInstalledBinaryByItsNames(t *testing.T) {
	_, hook, _ := gap2175Image(t)
	alias := gap2175Short(t, hook)
	for _, path := range []string{hook, strings.ToUpper(hook), alias, strings.ToLower(alias)} {
		if !SameNamedFile(path, hook) {
			t.Errorf("SameNamedFile(%s, %s) = false, want true", path, hook)
		}
	}
}

func TestGAP2175SameNamedFileRefusesOtherNamesAndFiles(t *testing.T) {
	root, hook, other := gap2175Image(t)
	if SameNamedFile(gap2175Short(t, other), hook) {
		t.Error("an 8.3 alias of a different executable must not name the hook binary")
	}

	junction := filepath.Join(root, "linked")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, filepath.Dir(hook)).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	viaJunction := filepath.Join(junction, filepath.Base(hook))
	if !pathidentity.Same(viaJunction, hook) {
		t.Fatal("fixture: the junction path must open the hook binary itself")
	}
	if SameNamedFile(viaJunction, hook) {
		t.Error("a path through a junction in a writable folder must not name the hook binary")
	}

	hardLink := filepath.Join(root, "defenseclaw-hook.exe")
	if err := os.Link(hook, hardLink); err != nil {
		t.Fatal(err)
	}
	if !pathidentity.Same(hardLink, hook) {
		t.Fatal("fixture: the hard link must be the hook binary's file")
	}
	if SameNamedFile(hardLink, hook) {
		t.Error("a hard link in a writable folder must not name the hook binary")
	}

	for _, path := range []string{"", hook + ".missing", filepath.Base(hook)} {
		if SameNamedFile(path, hook) {
			t.Errorf("SameNamedFile(%q, %s) = true, want false", path, hook)
		}
	}
	if SameNamedFile(hook, "") {
		t.Error("an empty want must match nothing")
	}
}
