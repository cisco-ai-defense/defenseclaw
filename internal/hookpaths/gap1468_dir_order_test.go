// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// gap1468WideDir makes a directory of 5,001 entries, past the 4,096 entries
// a pattern expansion examines, whose first entry by name is made by place
// and listed past the first 4,097 entries in directory order: it is renamed
// (each name still sorts first) until the file system lists it there. It
// returns the directory and that entry's name.
func gap1468WideDir(t *testing.T, place func(path string) error) (dir, first string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5000; index++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", index)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for try := 0; try < 64; try++ {
		name := fmt.Sprintf("0first%02d", try)
		var err error
		if try == 0 {
			err = place(filepath.Join(dir, name))
		} else {
			err = os.Rename(filepath.Join(dir, first), filepath.Join(dir, name))
		}
		if err != nil {
			t.Fatal(err)
		}
		first = name
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		names, err := f.Readdirnames(-1)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if slices.Index(names, first) >= 4097 {
			return dir, first
		}
	}
	t.Fatalf("no name in 64 tries is listed past the first 4,097 entries of %s in directory order", dir)
	return "", ""
}

// A pattern over one directory past the cap examines the first entries by
// name, as rel did (os.ReadDir read and sorted the whole directory), not the
// first entries the file system lists: a link to an active key that sorts
// first is a key read wherever the directory lists it (rel-1-0-10:GAP-1468).
// On 1e148ebcd0 the walk read the first 4,097 entries in directory order and
// missed it.
func TestGAP1468PrivateKeyGlobPastTheCapExaminesTheFirstNames(t *testing.T) {
	home := t.TempDir()
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, first := gap1468WideDir(t, func(path string) error { return os.Symlink(key, path) })
	for _, command := range []string{"cat " + dir + "/*", "head -n1 " + dir + "/0*"} {
		if !ActionPrivateKeyRead(command, home, home) {
			t.Errorf("%q: the link %s to the key sorts first in a directory of 5,001 entries; want a key read, as rel", command, first)
		}
	}
}

// The registration reader of rm reads the matches of its pattern the same
// way: a registered file that sorts first in a directory past the cap is
// reached wherever the directory lists it (rel-1-0-10:GAP-1468).
func TestGAP1468RegistrationGlobPastTheCapExaminesTheFirstNames(t *testing.T) {
	home := t.TempDir()
	dir, first := gap1468WideDir(t, func(path string) error { return os.WriteFile(path, []byte("{}\n"), 0o644) })
	registered := filepath.Join(dir, first)
	command := "rm -f " + dir + "/0first*"
	if got := RegistrationWriteReached(command, home, home, []string{registered}); !slices.Contains(got, registered) {
		t.Errorf("%q reached %q; want the registered %s, which sorts first in a directory of 5,001 entries, as rel", command, got, first)
	}
}
