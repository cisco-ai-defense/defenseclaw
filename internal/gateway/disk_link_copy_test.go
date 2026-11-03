// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestR107CopyOfADiskLinkToAProjectFileIsThatLink: cp --archive, cp
// --recursive and cp -a -t of a link already on disk to a project file (or
// a folder holding one), then an append, get the plain-copy verdict per
// user and managed: the hook client lists the link texts of the source,
// so the copy is read as the same links (rel-1-0-6:GAP-0274, vsweep6e N4-N6).
// The F4-F6 twins, the same copies of a link to the keys file, still block.
func TestR107CopyOfADiskLinkToAProjectFileIsThatLink(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		readme := filepath.Join(f.project, "README.md")
		for _, dir := range []string{"tree", "treeb", "copy", "copyb"} {
			if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for link, target := range map[string]string{"projlink": readme, "treeb/k": readme, "tree/k": f.keys} {
			if err := os.Symlink(target, filepath.Join(f.project, filepath.FromSlash(link))); err != nil {
				t.Fatal(err)
			}
		}
	}
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"plain archive copy then append", "project", `cp --archive README.md notes.txt && echo k >> notes.txt`, "allow"},
		{"N4 archive copy of a project link", "project", `cp --archive projlink notes.txt && echo k >> notes.txt`, "allow"},
		{"N5 recursive copy of a folder with a project link", "project", `cp --recursive treeb copyb && echo k >> copyb/k`, "allow"},
		{"N6 cp -a -t of a folder with a project link", "project", `cp -a -t copyb treeb && echo k >> copyb/treeb/k`, "allow"},
		{"F4 archive copy of the keys link", "project", `cp --archive keylink notes.txt && echo k >> notes.txt`, "block"},
		{"F5 recursive copy of a folder with a keys link", "project", `cp --recursive tree copy && echo k >> copy/k`, "block"},
		{"F6 cp -a -t of a folder with a keys link", "project", `cp -a -t copy tree && echo k >> copy/tree/k`, "block"},
	}, setup)
}
