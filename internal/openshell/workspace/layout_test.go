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
	"path/filepath"
	"testing"
)

// A sandbox may be called "git". Its snapshot directory must not be the
// place other snapshots keep their shadow git dirs, or deleting or
// replacing it takes every other snapshot's undo data with it.
func TestSandboxNamedGitKeepsOtherSnapshots(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	a := mustSnapshot(t, e, "a")
	if got, want := filepath.Dir(a.Git.Shadow), filepath.Join(e.data, "shadows"); got != want {
		t.Fatalf("shadow lives in %s, want %s", got, want)
	}
	mustSnapshot(t, e, "git")
	opts := e.snapOpts("git")
	opts.Replace = true
	if _, err := Snapshot(bg, opts); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSnapshot(bg, e.data, "git"); err != nil {
		t.Fatal(err)
	}
	if !pathExists(filepath.Join(a.Git.Shadow, "HEAD")) {
		t.Fatal("deleting the snapshot named git removed another snapshot's storage")
	}
	writeFile(t, e.project, "README.md", "changed\n")
	mustUndo(t, e, "a", false)
	if readFile(t, e.project, "README.md") != "hello\n" {
		t.Fatal("snapshot a no longer restores the folder")
	}
}

// A snapshot directory that holds anything Snapshot does not write (such as
// the shared shadow root older builds kept at snapshots/git) is neither
// reused nor deleted.
func TestSnapshotRefusesForeignSnapshotDir(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.data, "snapshots/git/0123abcd.git/defenseclaw-project.json", "marker")
	if _, err := Snapshot(bg, e.snapOpts("git")); err == nil {
		t.Fatal("Snapshot reused a directory holding other data")
	}
	if err := DeleteSnapshot(bg, e.data, "git"); err == nil {
		t.Fatal("DeleteSnapshot removed a directory holding other data")
	}
	if readFile(t, e.data, "snapshots/git/0123abcd.git/defenseclaw-project.json") != "marker" {
		t.Fatal("foreign data was changed")
	}
}
