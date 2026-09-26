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

	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(teamDir)
	wantPackError(t, err, "world_writable", "")
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(teamDir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = LoadFile(teamDir)
	wantPackError(t, err, "world_writable", "")

	// A sticky world-writable directory (like /tmp) protects the file.
	if err := os.Chmod(teamDir, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(teamDir); err != nil || info.Mode()&fs.ModeSticky == 0 {
		t.Skip("sticky bit unsupported here")
	}
	if _, err := LoadFile(teamDir); err != nil {
		t.Fatalf("sticky directory: %v", err)
	}
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
	type row struct {
		name    string
		builtin bool
		errCode string
	}
	var got []row
	for _, entry := range entries {
		r := row{name: entry.Name, builtin: entry.Builtin}
		if entry.Err != nil {
			var packErr *Error
			if e, ok := entry.Err.(*Error); ok {
				packErr = e
			}
			if packErr == nil {
				t.Fatalf("entry %s error %T", entry.Name, entry.Err)
			}
			r.errCode = packErr.Code
		} else if entry.Digest == "" || entry.Profile == "" || entry.Source == "" {
			t.Fatalf("entry %+v lacks metadata", entry)
		}
		got = append(got, r)
	}
	want := []row{
		{"open", true, ""}, {"balanced", true, ""}, {"strict", true, ""},
		{"Upper", false, "invalid_name"},
		{"alpha", false, ""},
		{"broken", false, "missing_field"},
		{"linked", false, "symlink"},
		{"strict", false, "reserved_name"},
		{"zeta", false, ""},
	}
	if len(got) != len(want) {
		t.Fatalf("List rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d = %+v, want %+v (all %+v)", i, got[i], want[i], got)
		}
	}
}
