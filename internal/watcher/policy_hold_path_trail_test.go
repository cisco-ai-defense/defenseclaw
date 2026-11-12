// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
)

// heldAndAdmittedForTest makes a held copy and an independent admitted copy
// beside it, each with a SKILL.md.
func heldAndAdmittedForTest(t *testing.T) (root, held, admitted string) {
	t.Helper()
	root = t.TempDir()
	held = filepath.Join(root, "held")
	admitted = filepath.Join(root, "admitted")
	for _, dir := range []string{held, admitted} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: shared-name\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, held, admitted
}

// A hard link to a link in the held copy is the same inode as that link, so
// it names the link whatever the link points to.
func TestPolicyHoldKeepsAHardLinkToALinkInTheHeldCopy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	root, held, admitted := heldAndAdmittedForTest(t)
	protected := filepath.Join(held, "protected-link")
	if err := os.Symlink(filepath.Join(admitted, "SKILL.md"), protected); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	hard := filepath.Join(root, "hard-to-link")
	if err := os.Link(protected, hard); err != nil {
		t.Skipf("hard links to links unavailable: %v", err)
	}
	if info, err := os.Lstat(hard); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Skip("the hard link followed the link on this platform")
	}
	entry := policyHoldEntryFor(held)
	if !holdIgnored(entry, filepath.Join(admitted, "SKILL.md")) {
		t.Error("the admitted file was held")
	}
	for label, path := range map[string]string{"the link in the held copy": protected, "a hard link to it": hard} {
		if holdIgnored(entry, path) {
			t.Errorf("%s was allowed", label)
		}
	}
}

// A link whose target steps out of the held folder again names the admitted
// file, not the held copy.
func TestPolicyHoldRunsAnAdmittedFileNamedThroughAParentElementOfALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	root, held, admitted := heldAndAdmittedForTest(t)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(held+"/../admitted/SKILL.md", alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	entry := policyHoldEntryFor(held)
	if !holdIgnored(entry, alias) || !holdIgnored(entry, filepath.Join(admitted, "SKILL.md")) {
		t.Error("an admitted file was held")
	}
	if holdIgnored(entry, filepath.Join(held, "SKILL.md")) {
		t.Error("the held file was allowed")
	}
	toHeld := filepath.Join(root, "to-held")
	if err := os.Symlink(admitted+"/../held/SKILL.md", toHeld); err != nil {
		t.Fatal(err)
	}
	if holdIgnored(entry, toHeld) {
		t.Error("a link that steps through the admitted folder to the held file was allowed")
	}
}

// A held folder this process cannot read through, or one too large to
// compare, does not make an independent file part of it: the held copy is
// reported unknown and the caller decides by profile.
func TestPolicyHoldReportsAHeldFolderItCannotCompareInFullAsUnknown(t *testing.T) {
	large := func(t *testing.T, held string) {
		for i := 0; i < policyHoldFileLimit+1; i++ {
			if err := os.WriteFile(filepath.Join(held, strconv.Itoa(i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	unreadable := func(t *testing.T, held string) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs POSIX permissions as a non-root user")
		}
		if err := os.Chmod(held, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(held, 0o700) })
		if _, err := os.ReadDir(held); err == nil {
			t.Skip("the folder is still readable")
		}
	}
	for name, prepare := range map[string]func(*testing.T, string){"too many entries": large, "no read permission": unreadable} {
		t.Run(name, func(t *testing.T) {
			_, held, admitted := heldAndAdmittedForTest(t)
			heldFile := filepath.Join(held, "SKILL.md")
			prepare(t, held)
			entry := policyHoldEntryFor(held)
			scope := PolicyHoldIgnoredFields(entry, []string{filepath.Join(admitted, "SKILL.md")})
			if !slices.Contains(scope.Ignored, "runtime") || !slices.Equal(scope.Unknown, []string{held}) {
				t.Errorf("admitted file: ignored %v, unknown %v; want runtime ignored and the held copy unknown", scope.Ignored, scope.Unknown)
			}
			if holdIgnored(entry, heldFile) {
				t.Error("the held file was allowed")
			}
		})
	}
	t.Run("readable and small", func(t *testing.T) {
		_, held, admitted := heldAndAdmittedForTest(t)
		scope := PolicyHoldIgnoredFields(policyHoldEntryFor(held), []string{filepath.Join(admitted, "SKILL.md")})
		if !slices.Contains(scope.Ignored, "runtime") || len(scope.Unknown) != 0 {
			t.Errorf("ignored %v, unknown %v; want runtime ignored and nothing unknown", scope.Ignored, scope.Unknown)
		}
	})
}
