// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func customPack(name string) string {
	return strings.Replace(minimalPack, "name: team", "name: "+name, 1)
}

// writePack writes <dir>/<name>/pack.yaml and returns the pack directory.
func writePack(t *testing.T, dir, name, body string) string {
	t.Helper()
	packDir := filepath.Join(dir, name)
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, PackFileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return packDir
}

func withHome(t *testing.T, home string) {
	t.Helper()
	previous := userHomeDir
	userHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { userHomeDir = previous })
}

func TestLoadResolvesReferences(t *testing.T) {
	root := t.TempDir()
	teamDir := writePack(t, root, "team", customPack("team"))
	// A custom directory named like a built-in never shadows it.
	writePack(t, root, "balanced", customPack("impostor"))
	withHome(t, root)

	for _, tc := range []struct {
		name, ref, packDir string
		wantName           string
		wantBuiltin        bool
		wantSource         string
	}{
		{"default", "", "", "open", true, "builtin:open"},
		{"default with spaces", "  ", root, "open", true, "builtin:open"},
		{"builtin", "strict", "", "strict", true, "builtin:strict"},
		{"builtin despite custom dir", "balanced", root, "balanced", true, "builtin:balanced"},
		{"custom name", "team", root, "team", false, filepath.Join(teamDir, PackFileName)},
		{"pack dir with tilde", "team", "~", "team", false, filepath.Join(teamDir, PackFileName)},
		{"absolute dir", teamDir, "", "team", false, filepath.Join(teamDir, PackFileName)},
		{"absolute file", filepath.Join(teamDir, PackFileName), "", "team", false, filepath.Join(teamDir, PackFileName)},
		{"tilde path", "~/team", "", "team", false, filepath.Join(teamDir, PackFileName)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack, err := Load(tc.ref, tc.packDir)
			if err != nil {
				t.Fatalf("Load(%q, %q): %v", tc.ref, tc.packDir, err)
			}
			if pack.Name != tc.wantName || pack.Builtin != tc.wantBuiltin || pack.Source != tc.wantSource {
				t.Fatalf("pack = %q builtin=%v source=%q", pack.Name, pack.Builtin, pack.Source)
			}
		})
	}

	custom, _ := Load("team", root)
	again, _ := Load(filepath.Join(teamDir, PackFileName), "")
	if custom.Digest == "" || custom.Digest != again.Digest {
		t.Fatalf("digest must depend on content only: %q vs %q", custom.Digest, again.Digest)
	}
}

func TestLoadRefusals(t *testing.T) {
	root := t.TempDir()
	withHome(t, root)
	teamDir := writePack(t, root, "team", customPack("team"))
	writePack(t, root, "mismatch", customPack("other"))
	writePack(t, root, "reserved", customPack("open"))
	writePack(t, root, "broken", customPack("broken")+"extra: 1\n")
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "dirfile", PackFileName), 0o755); err != nil {
		t.Fatal(err)
	}
	bigDir := writePack(t, root, "big", customPack("big")+"description: "+strings.Repeat("x", MaxPackBytes)+"\n")

	symlinkedDir := filepath.Join(root, "linkdir")
	symlinkedFile := filepath.Join(root, "linkfile")
	if err := os.Symlink(teamDir, symlinkedDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.MkdirAll(symlinkedFile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(teamDir, PackFileName), filepath.Join(symlinkedFile, PackFileName)); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, ref, packDir, code string
	}{
		{"unknown builtin-like name", "permissive", "", "not_found"},
		{"missing custom", "nothing", root, "not_found"},
		{"relative path", "./team", root, "relative_path"},
		{"relative name with slash", "team/pack.yaml", root, "relative_path"},
		{"name mismatch", "mismatch", root, "name_mismatch"},
		{"reserved name", "reserved", root, "reserved_name"},
		{"strict decode", "broken", root, "unknown_field"},
		{"no pack file", filepath.Join(root, "empty"), "", "not_found"},
		{"pack file is a directory", filepath.Join(root, "dirfile"), "", "not_regular"},
		{"too large", bigDir, "", "too_large"},
		{"symlinked pack dir", symlinkedDir, "", "symlink"},
		{"symlinked pack dir by name", "linkdir", root, "symlink"},
		{"symlinked pack file", symlinkedFile, "", "symlink"},
		{"missing path", filepath.Join(root, "nope"), "", "not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.ref, tc.packDir)
			wantPackError(t, err, tc.code, "")
		})
	}

	if _, err := Validate(filepath.Join(teamDir, PackFileName)); err != nil {
		t.Fatalf("Validate(valid pack): %v", err)
	}
	_, err := Validate(filepath.Join(root, "reserved"))
	wantPackError(t, err, "reserved_name", "name")
}

func TestLoadRefusesWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	root := t.TempDir()
	teamDir := writePack(t, root, "team", customPack("team"))
	file := filepath.Join(teamDir, PackFileName)
	chmod := func(path string, mode fs.FileMode) {
		t.Helper()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	// Group members are other local users too.
	for _, tc := range []struct {
		path       string
		mode, safe fs.FileMode
		code       string
	}{
		{file, 0o666, 0o644, "world_writable"},
		{file, 0o664, 0o644, "group_writable"},
		{teamDir, 0o777, 0o755, "world_writable"},
		{teamDir, 0o775, 0o755, "group_writable"},
	} {
		chmod(tc.path, tc.mode)
		_, err := LoadFile(teamDir)
		wantPackError(t, err, tc.code, "")
		if _, err := Load("team", root); err == nil {
			t.Fatalf("a named pack loaded with %s at %o", tc.path, tc.mode)
		}
		chmod(tc.path, tc.safe)
	}

	// A sticky world-writable directory (like /tmp) is not the user's to
	// vouch for: only a root-owned pack loads from it.
	chmod(teamDir, 0o777|fs.ModeSticky)
	if info, err := os.Stat(teamDir); err != nil || info.Mode()&fs.ModeSticky == 0 {
		t.Skip("sticky bit unsupported here")
	}
	fakeOwners(t, func(fs.FileInfo) int { return testUID })
	_, err := LoadFile(teamDir)
	if e := wantPackError(t, err, "world_writable", ""); !strings.Contains(e.Reason, "other users can write to") {
		t.Fatalf("sticky directory: %v", e)
	}
	fakeOwners(t, func(info fs.FileInfo) int {
		if info.IsDir() {
			return testUID
		}
		return 0
	})
	if _, err := LoadFile(teamDir); err != nil {
		t.Fatalf("root-owned pack in a sticky directory: %v", err)
	}
	// Without the sticky bit any user could replace even a root-owned file.
	chmod(teamDir, 0o777)
	_, err = LoadFile(teamDir)
	wantPackError(t, err, "world_writable", "")
}

// testUID is the current user's uid while fakeOwners is in effect.
const testUID = 4242

// fakeOwners makes testUID the current user and reports every inspected
// file's owner through owner, so ownership tests do not depend on who runs
// them.
func fakeOwners(t *testing.T, owner func(fs.FileInfo) int) {
	t.Helper()
	previousUID, previousOwner := currentUID, fileOwner
	currentUID = func() int { return testUID }
	fileOwner = func(info fs.FileInfo) (int, bool) { return owner(info), true }
	t.Cleanup(func() { currentUID, fileOwner = previousUID, previousOwner })
}

func TestLoadRefusesPacksOtherUsersOwn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX ownership")
	}
	root := t.TempDir()
	teamDir := writePack(t, root, "team", customPack("team"))
	const otherUID = 5151
	for _, tc := range []struct {
		name          string
		file, dir     int
		code, subject string
	}{
		{"own file and directory", testUID, testUID, "", ""},
		{"root-owned file and directory", 0, 0, "", ""},
		{"own file in a root-owned directory", testUID, 0, "", ""},
		{"root-owned file in own directory", 0, testUID, "", ""},
		{"file another user owns", otherUID, testUID, "foreign_owner", "pack file"},
		{"directory another user owns", testUID, otherUID, "foreign_owner", "pack directory"},
		{"root-owned file in a directory another user owns", 0, otherUID, "foreign_owner", "pack directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeOwners(t, func(info fs.FileInfo) int {
				if info.IsDir() {
					return tc.dir
				}
				return tc.file
			})
			for _, ref := range []string{teamDir, filepath.Join(teamDir, PackFileName)} {
				pack, err := LoadFile(ref)
				if tc.code == "" {
					if err != nil || pack.Name != "team" {
						t.Fatalf("LoadFile(%s) = %v, %v", ref, pack, err)
					}
					continue
				}
				if e := wantPackError(t, err, tc.code, ""); !strings.Contains(e.Reason, tc.subject) {
					t.Fatalf("LoadFile(%s) = %v, want a refusal naming the %s", ref, e, tc.subject)
				}
			}
			// Named packs and pack listings apply the same check.
			if _, err := Load("team", root); (err == nil) != (tc.code == "") {
				t.Fatalf("Load(team) = %v", err)
			}
		})
	}

	previous := fileOwner
	fileOwner = func(fs.FileInfo) (int, bool) { return 0, false }
	t.Cleanup(func() { fileOwner = previous })
	_, err := LoadFile(teamDir)
	wantPackError(t, err, "unreadable", "")
}

func TestListPacks(t *testing.T) {
	entries, err := List("")
	if err != nil || len(entries) != 3 {
		t.Fatalf("List(\"\") = %v, %v", entries, err)
	}
	entries, err = List(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(entries) != 3 {
		t.Fatalf("List(missing) = %v, %v", entries, err)
	}

	root := t.TempDir()
	writePack(t, root, "zeta", customPack("zeta"))
	writePack(t, root, "alpha", customPack("alpha"))
	writePack(t, root, "strict", customPack("strict"))
	writePack(t, root, "Upper", customPack("upper"))
	writePack(t, root, "broken", "version: 1\n")
	writePack(t, root, ".hidden", customPack("hidden"))
	if err := os.MkdirAll(filepath.Join(root, "feeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "alpha"), filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	entries, err = List(root)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Each row: name, then "builtin", the refusal code, or "custom".
	var got []string
	for _, entry := range entries {
		row := entry.Name + " custom"
		var packErr *Error
		switch {
		case errors.As(entry.Err, &packErr):
			row = entry.Name + " " + packErr.Code
		case entry.Err != nil:
			t.Fatalf("entry %s error %T", entry.Name, entry.Err)
		case entry.Digest == "" || entry.Profile == "" || entry.Source == "":
			t.Fatalf("entry %+v lacks metadata", entry)
		case entry.Builtin:
			row = entry.Name + " builtin"
		}
		got = append(got, row)
	}
	want := "open builtin, balanced builtin, strict builtin, Upper invalid_name, alpha custom, broken missing_field, " +
		"linked symlink, strict reserved_name, zeta custom"
	if strings.Join(got, ", ") != want {
		t.Fatalf("List rows = %s\nwant %s", strings.Join(got, ", "), want)
	}
}
