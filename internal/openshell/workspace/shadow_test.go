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

package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func packFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, en := range entries {
		out = append(out, en.Name())
	}
	return out
}

// The shadow's object files must be its own: a hard link shares the inode
// the agent can rewrite through the mount, which would silently change the
// snapshot too.
func TestSnapshotKeepsPrivateCopyOfObjects(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "gc", "-q")
	rec := mustSnapshot(t, e, "s1")
	if !rec.Git.ObjectsCopied {
		t.Fatalf("objects not copied: %v", rec.Warnings)
	}
	packDir := filepath.Join(e.project, ".git", "objects", "pack")
	var pack string
	for _, n := range packFiles(t, packDir) {
		if strings.HasSuffix(n, ".pack") {
			pack = n
		}
	}
	if pack == "" {
		t.Fatal("gc wrote no pack")
	}
	projPack := filepath.Join(packDir, pack)
	shadowRel := "objects/pack/" + pack
	pi, err := os.Stat(projPack)
	if err != nil {
		t.Fatal(err)
	}
	si, err := os.Stat(filepath.Join(rec.Git.Shadow, filepath.FromSlash(shadowRel)))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(pi, si) {
		t.Fatal("the snapshot shares the project's pack file inode")
	}
	original := readFile(t, rec.Git.Shadow, shadowRel)

	// The session rewrites the pack in place (same inode).
	if err := os.Chmod(projPack, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projPack, []byte("marker"), 0o644); err != nil {
		t.Fatal(err)
	}
	if readFile(t, rec.Git.Shadow, shadowRel) != original {
		t.Fatal("rewriting the project's pack changed the snapshot")
	}
	writeFile(t, e.project, "README.md", "changed\n")

	preview := mustUndo(t, e, "s1", true)
	if len(preview.LostObjects) == 0 {
		t.Fatal("the damaged pack was not noticed")
	}
	mustUndo(t, e, "s1", false)
	if readFile(t, e.project, "README.md") != "hello\n" {
		t.Fatal("working tree not restored from the snapshot's own objects")
	}
	if readFile(t, packDir, pack) != original {
		t.Fatal("the damaged pack was not replaced with the snapshot's copy")
	}
	if got := e.git(e.project, "cat-file", "-p", "HEAD:README.md"); got != "hello" {
		t.Fatalf("committed history not readable after undo: %q", got)
	}
	pi, _ = os.Stat(projPack)
	si, _ = os.Stat(filepath.Join(rec.Git.Shadow, filepath.FromSlash(shadowRel)))
	if os.SameFile(pi, si) {
		t.Fatal("the repaired pack shares an inode with the snapshot")
	}
}

// When the filesystem cannot clone and the objects exceed the copy limit,
// the snapshot says so, keeps no half-copied pack and still works through
// alternates.
func TestSnapshotObjectCopyLimit(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	e.git(e.project, "gc", "-q")
	opts := e.snapOpts("s1")
	opts.MaxObjectCopyBytes = 1
	rec, err := Snapshot(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Git.ObjectsCopied {
		found := false
		for _, w := range rec.Warnings {
			if strings.Contains(w, "shares the rest with the project") {
				found = true
			}
		}
		if !found {
			t.Fatalf("no warning about the copy limit: %v", rec.Warnings)
		}
	}
	shadowPacks := filepath.Join(rec.Git.Shadow, "objects", "pack")
	if names, err := os.ReadDir(shadowPacks); err == nil {
		have := map[string]bool{}
		for _, n := range names {
			if strings.HasPrefix(n.Name(), ".dc-copy-") {
				t.Fatalf("temporary copy left behind: %s", n.Name())
			}
			have[n.Name()] = true
		}
		for n := range have {
			if strings.HasSuffix(n, ".pack") && !have[strings.TrimSuffix(n, ".pack")+".idx"] {
				t.Fatalf("pack %s kept without its index", n)
			}
		}
	}
	writeFile(t, e.project, "README.md", "changed\n")
	mustUndo(t, e, "s1", false)
	if readFile(t, e.project, "README.md") != "hello\n" {
		t.Fatal("working tree not restored")
	}
}
