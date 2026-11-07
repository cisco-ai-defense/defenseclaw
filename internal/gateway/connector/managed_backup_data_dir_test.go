// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// The data folder a rollback restores is one directory however it is spelled:
// absolute, relative, through links, nested, or with other letter case on a
// case-insensitive volume. A path inside it is never an agent file.
func TestManagedDataDirContainsEverySpellingOfTheSameFolder(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "Data")
	if err := os.MkdirAll(filepath.Join(data, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	neighbor := filepath.Join(root, "agent", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(neighbor), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(data, link); err != nil {
		t.Skipf("cannot create a link: %v", err)
	}
	inside := filepath.Join(data, "nested", "config.json")
	t.Chdir(root)
	for _, tc := range []struct {
		name string
		dir  string
		path string
		want bool
	}{
		{"absolute", data, inside, true},
		{"relative", "Data", inside, true},
		{"linked folder", link, inside, true},
		{"target reached through the link", data, filepath.Join(link, "nested", "config.json"), true},
		{"folder not created yet", filepath.Join(root, "Later"), filepath.Join(root, "Later", "x.json"), true},
		{"the folder itself is not a file in it", data, data, false},
		{"neighboring agent file, absolute", data, neighbor, false},
		{"neighboring agent file, linked folder", link, neighbor, false},
		{"blank folder", "", inside, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newManagedDataDir(tc.dir).contains(tc.path); got != tc.want {
				t.Fatalf("contains(%q) with data folder %q = %v, want %v", tc.path, tc.dir, got, tc.want)
			}
		})
	}
}

// A volume that opens a folder through a spelling the path functions do not
// treat as equal (letter case on macOS and Windows) is told apart by the
// directory itself. The spellings below are what such a volume hands back, so
// this holds on every platform.
func TestManagedDataDirMatchesByIdentityWhenSpellingsDiffer(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "Data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(data)
	if err != nil {
		t.Fatal(err)
	}
	variant := filepath.Join(root, "dAtA")
	d := &managedDataDir{abs: variant, resolved: variant, info: info}
	if !d.contains(filepath.Join(data, "config.json")) {
		t.Fatal("a target inside the folder was not matched by the folder identity")
	}
	if d.contains(filepath.Join(root, "agent", "hooks.json")) {
		t.Fatal("a neighboring agent file matched the folder identity")
	}
}

// On a case-insensitive volume a record inside the data folder must not count
// as rollback proof when --data-dir is spelled with other letter case. Skips
// on a case-sensitive volume.
func TestVerifyManagedFileBackupsCaseVariantDataDirDoesNotCountInDataTarget(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "Data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	variant := filepath.Join(home, "dAtA")
	left, errLeft := os.Stat(data)
	right, errRight := os.Stat(variant)
	if errLeft != nil || errRight != nil || !os.SameFile(left, right) {
		t.Skip("the volume is case-sensitive")
	}
	target := filepath.Join(data, "config.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(t.TempDir(), "saved-data")
	if err := captureManagedFileBackup(saved, "newer-connector", "config.json", target); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{data, variant} {
		n, err := VerifyManagedFileBackups(saved, dir, home)
		if n != 0 || err == nil {
			t.Fatalf("data folder %q counted an in-data record: %d, %v", dir, n, err)
		}
	}
	// Control: the same record with an unrelated data folder is proof.
	if n, err := VerifyManagedFileBackups(saved, filepath.Join(t.TempDir(), "other"), home); n != 1 || err != nil {
		t.Fatalf("record under the home with another data folder = %d, %v; want 1, nil", n, err)
	}
}
