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

//go:build !windows

package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	matches, _ := filepath.Glob(filepath.Join(packDir, "*.pack"))
	if len(matches) == 0 {
		t.Fatal("gc wrote no pack")
	}
	projPack := matches[0]
	shadowPack := filepath.Join(rec.Git.Shadow, "objects", "pack", filepath.Base(projPack))
	sameInode := func() bool {
		t.Helper()
		pi, err1 := os.Stat(projPack)
		si, err2 := os.Stat(shadowPack)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		return os.SameFile(pi, si)
	}
	if sameInode() {
		t.Fatal("the snapshot shares the project's pack file inode")
	}
	original := readFile(t, shadowPack, "")

	// The session rewrites the pack in place (same inode) and deletes its
	// index.
	mustChmod(t, projPack, 0o644)
	must(t, os.WriteFile(projPack, []byte("marker"), 0o644))
	if readFile(t, shadowPack, "") != original {
		t.Fatal("rewriting the project's pack changed the snapshot")
	}
	idx := strings.TrimSuffix(projPack, ".pack") + ".idx"
	must(t, os.Remove(idx))
	writeFile(t, e.project, "README.md", "changed\n")
	if preview := mustUndo(t, e, "s1", true); len(preview.LostObjects) == 0 {
		t.Fatal("the damaged pack was not noticed")
	}
	mustUndo(t, e, "s1", false)
	// The working tree comes back from the snapshot's own objects, and the
	// damaged pack is replaced with the snapshot's copy, not linked to it,
	// along with the index it lost.
	wantFiles(t, e.project, "README.md", "hello\n")
	if readFile(t, projPack, "") != original || !pathExists(idx) || e.git(e.project, "cat-file", "-p", "HEAD:README.md") != "hello" || sameInode() {
		t.Fatal("the damaged pack was not repaired with a private copy")
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
	if !rec.Git.ObjectsCopied && !strings.Contains(strings.Join(rec.Warnings, "\n"), "shares the rest with the project") {
		t.Fatalf("no warning about the copy limit: %v", rec.Warnings)
	}
	names, _ := os.ReadDir(filepath.Join(rec.Git.Shadow, "objects", "pack"))
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
	writeFile(t, e.project, "README.md", "changed\n")
	mustUndo(t, e, "s1", false)
	wantFiles(t, e.project, "README.md", "hello\n")
}

// TestShadowStorageStaysOutOfSnapshotDirs: shadows live under <data>/shadows,
// apart from the per-name snapshot directories, and a snapshot directory
// that holds anything Snapshot does not write is neither reused nor deleted.
func TestShadowStorageStaysOutOfSnapshotDirs(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	if a := mustSnapshot(t, e, "a"); filepath.Dir(a.Git.Shadow) != filepath.Join(e.data, "shadows") {
		t.Fatalf("shadow lives in %s, want %s", filepath.Dir(a.Git.Shadow), filepath.Join(e.data, "shadows"))
	}
	writeFile(t, e.data, "snapshots/dc-old/0123abcd.git/defenseclaw-project.json", "marker")
	if _, err := Snapshot(bg, e.snapOpts("dc-old")); err == nil {
		t.Fatal("Snapshot reused a directory holding other data")
	}
	if err := DeleteSnapshot(bg, e.data, "dc-old"); err == nil {
		t.Fatal("DeleteSnapshot removed a directory holding other data")
	}
	wantFiles(t, e.data, "snapshots/dc-old/0123abcd.git/defenseclaw-project.json", "marker")
}
