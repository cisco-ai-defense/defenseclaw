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
	"slices"
	"strings"
	"testing"
)

// keepSnapshot snapshots e keeping copies of the named ignored directories
// up to limit bytes.
func keepSnapshot(t *testing.T, e *env, name string, limit int64, dirs ...string) *SnapshotRecord {
	t.Helper()
	opts := e.snapOpts(name)
	opts.KeepIgnored, opts.KeepIgnoredBytes = dirs, limit
	rec, err := Snapshot(bg, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func restoredPaths(changes []IgnoredChange) []string {
	var out []string
	for _, c := range changes {
		out = append(out, c.Path)
	}
	return out
}

// With openshell.workdir.undo_ignored on, the snapshot keeps a copy of the
// dependency directories git ignores, and undo puts them back as they
// were: an edited command, a new package, a deleted file, a retargeted
// symlink and a new executable (#944). Review says undo restores them, and
// after the undo the folder matches its undo point again.
func TestUndoRestoresKeptIgnoredDirs(t *testing.T) {
	e := ignoredProject(t)
	mustSymlink(t, "../left-pad/index.js", filepath.Join(e.project, "node_modules/.bin/lp"))
	keepSnapshot(t, e, "k1", 1<<20, "node_modules", ".venv")
	man, err := loadIgnored(e.data, "k1")
	if err != nil || man == nil || strings.Join(man.Kept, ",") != ".venv/,node_modules/" || len(man.OverCap) != 0 {
		t.Fatalf("manifest = %+v, %v", man, err)
	}
	lay, _ := newLayout(e.data)
	wantFiles(t, lay.keptIgnored("k1"), "node_modules/.bin/tool", "#!/bin/sh\necho tool\n", ".venv/bin/activate", "export VIRTUAL_ENV=.venv\n",
		// Only the named directories are copied.
		"calc/__pycache__/m.cpython-312.pyc", absent)

	// The session.
	rewriteKeepingTimes(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\necho evil\n", 0o755)
	writeFile(t, e.project, "node_modules/evil/index.js", "steal()\n")
	mustRemove(t, e.project, "node_modules/left-pad/index.js", "node_modules/.bin/lp")
	mustSymlink(t, "../evil/index.js", filepath.Join(e.project, "node_modules/.bin/lp"))
	rewriteKeepingTimes(t, e.project, ".venv/bin/activate", "export VIRTUAL_ENV=.evil\n", 0o644)
	writeFileMode(t, e.project, ".venv/bin/new", "#!/bin/sh\n", 0o755)
	rewriteKeepingTimes(t, e.project, "calc/__pycache__/m.cpython-312.pyc", "bytecode-v2", 0o644)

	rep := review(t, e, "k1", []ContentScanner{})
	flagWith(t, rep, "node_modules/", SeverityHigh, "Undo restores node_modules/ from the copy its undo point keeps")
	flagWith(t, rep, ".venv/", SeverityHigh, "Undo restores .venv/")

	preview := mustUndo(t, e, "k1", true)
	if preview.Empty() || len(preview.Unrestored()) != 0 || strings.Join(restoredPaths(preview.RestoredIgnored()), ",") != ".venv/,node_modules/" {
		t.Fatalf("preview: empty %v, unrestored %+v, restored %+v", preview.Empty(), preview.Unrestored(), preview.RestoredIgnored())
	}
	wantFiles(t, e.project, "node_modules/evil/index.js", present) // a preview changes nothing

	res := mustUndo(t, e, "k1", false)
	if len(res.Unrestored()) != 0 || len(res.RestoredIgnored()) != 2 {
		t.Fatalf("undo: unrestored %+v, restored %+v, warnings %v", res.Unrestored(), res.RestoredIgnored(), res.Warnings)
	}
	wantFiles(t, e.project,
		"node_modules/.bin/tool", "#!/bin/sh\necho tool\n",
		"node_modules/left-pad/index.js", "module.exports = 1\n",
		"node_modules/evil", absent,
		".venv/bin/activate", "export VIRTUAL_ENV=.venv\n",
		".venv/bin/new", absent,
		// The bytecode cache is deleted as before.
		"calc/__pycache__/m.cpython-312.pyc", absent)
	wantMode(t, e.project, "node_modules/.bin/tool", 0o755)
	if target, err := os.Readlink(filepath.Join(e.project, "node_modules/.bin/lp")); err != nil || target != "../left-pad/index.js" {
		t.Fatalf("node_modules/.bin/lp -> %q, %v", target, err)
	}
	// The manifest records the restored directories as they are now.
	if again := mustUndo(t, e, "k1", true); !again.Empty() || len(again.Ignored) != 0 {
		t.Fatalf("after the undo: empty %v, ignored %+v", again.Empty(), again.Ignored)
	}
	if rep := review(t, e, "k1", []ContentScanner{}); len(rep.Flags) != 0 {
		t.Fatalf("review after the undo flags %+v", rep.Flags)
	}
}

// A directory whose copy would pass the cap keeps none: the snapshot says
// so, and undo reports it as before (OverCap) while it restores the ones
// that fit. Without a name list nothing is copied.
func TestKeptIgnoredDirsStayWithinTheCap(t *testing.T) {
	e := ignoredProject(t)
	writeFile(t, e.project, "node_modules/big/blob.bin", strings.Repeat("x", 4096))
	rec := keepSnapshot(t, e, "c1", 1024, "node_modules", ".venv")
	man, _ := loadIgnored(e.data, "c1")
	if man == nil || strings.Join(man.Kept, ",") != ".venv/" || strings.Join(man.OverCap, ",") != "node_modules/" {
		t.Fatalf("manifest kept %v, over cap %v", man.Kept, man.OverCap)
	}
	if !slices.ContainsFunc(rec.Warnings, func(w string) bool {
		return strings.Contains(w, "undo keeps no copy of node_modules/: the copies would pass their 1.0 KiB cap")
	}) {
		t.Fatalf("warnings = %v", rec.Warnings)
	}
	lay, _ := newLayout(e.data)
	wantFiles(t, lay.keptIgnored("c1"), "node_modules", absent, ".venv/pyvenv.cfg", "home = /usr/bin\n")

	rewriteKeepingTimes(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\necho evil\n", 0o755)
	rewriteKeepingTimes(t, e.project, ".venv/pyvenv.cfg", "home = /tmp/xx\n", 0o644)
	res := mustUndo(t, e, "c1", false)
	un := res.Unrestored()
	if len(un) != 1 || un[0].Path != "node_modules/" || !un[0].OverCap || un[0].Restored {
		t.Fatalf("unrestored = %+v", un)
	}
	wantFiles(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\necho evil\n", ".venv/pyvenv.cfg", "home = /usr/bin\n")
}

// Off (the default), a snapshot copies nothing.
func TestKeptIgnoredDirsAreOffByDefault(t *testing.T) {
	e := ignoredProject(t)
	mustSnapshot(t, e, "n1")
	lay, _ := newLayout(e.data)
	if man, _ := loadIgnored(e.data, "n1"); man == nil || len(man.Kept) != 0 || len(man.OverCap) != 0 || pathExists(lay.keptIgnored("n1")) {
		t.Fatalf("a snapshot without KeepIgnored kept %+v", man)
	}
}

// A folder without git keeps copies of the dependency directories its
// snapshot skips, and a session that swaps one for a symlink to a folder
// outside gets a real directory back without that folder being touched.
// Replacing and deleting the snapshot takes the copies along.
func TestKeptIgnoredDirsInAPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "app.js", "require('left-pad')\n")
	writeFile(t, e.project, "node_modules/left-pad/index.js", "module.exports = 1\n")
	outside := filepath.Join(e.root, "outside")
	writeFile(t, outside, "index.js", "operator file\n")
	keepSnapshot(t, e, "p1", 1<<20, "node_modules")
	if man, _ := loadIgnored(e.data, "p1"); man == nil || strings.Join(man.Kept, ",") != "node_modules/" {
		t.Fatalf("manifest = %+v", man)
	}
	mustRemove(t, e.project, "node_modules")
	mustSymlink(t, outside, filepath.Join(e.project, "node_modules"))
	res := mustUndo(t, e, "p1", false)
	if len(res.Unrestored()) != 0 {
		t.Fatalf("unrestored = %+v, warnings %v", res.Unrestored(), res.Warnings)
	}
	if info, err := os.Lstat(filepath.Join(e.project, "node_modules")); err != nil || !info.IsDir() {
		t.Fatalf("node_modules = %v, %v; want a directory again", info, err)
	}
	wantFiles(t, e.project, "node_modules/left-pad/index.js", "module.exports = 1\n")
	wantFiles(t, outside, "index.js", "operator file\n")

	opts := e.snapOpts("p1")
	opts.Replace, opts.KeepIgnored, opts.KeepIgnoredBytes = true, []string{"node_modules"}, 1<<20
	if _, err := Snapshot(bg, opts); err != nil {
		t.Fatalf("replace a snapshot with kept copies: %v", err)
	}
	must(t, DeleteSnapshot(bg, e.data, "p1"))
	lay, _ := newLayout(e.data)
	if pathExists(lay.snapshotDir("p1")) {
		t.Fatal("the deleted snapshot left its directory (and its copies)")
	}
}
