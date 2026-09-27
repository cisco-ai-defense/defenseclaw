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
	"time"
)

// ignoredProject is a git project whose dependency and cache directories
// git ignores, as in most Node and Python projects.
func ignoredProject(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "*.log\nbuild/\n.env\nnode_modules/\n.venv/\n__pycache__/\n")
	writeFile(t, e.project, "calc/m.py", "X = 1\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "python and node")
	writeFileMode(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\necho tool\n", 0o755)
	writeFile(t, e.project, "node_modules/left-pad/index.js", "module.exports = 1\n")
	writeFile(t, e.project, ".venv/bin/activate", "export VIRTUAL_ENV=.venv\n")
	writeFile(t, e.project, ".venv/pyvenv.cfg", "home = /usr/bin\n")
	writeFile(t, e.project, "calc/__pycache__/m.cpython-312.pyc", "bytecode-v1")
	return e
}

// rewriteKeepingTimes replaces rel with content of the same length and puts
// its modification time back, the way a careful agent hides an edit.
func rewriteKeepingTimes(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFileMode(t, root, rel, content, mode)
	if err := os.Chtimes(p, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func TestReviewAndUndoSeeChangesInIgnoredExecutableDirs(t *testing.T) {
	e := ignoredProject(t)
	mustSnapshot(t, e, "s1")

	// The session: same-size rewrites with the old modification times, and
	// a new executable in an ignored bytecode cache.
	rewriteKeepingTimes(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\necho evil\n", 0o755)
	rewriteKeepingTimes(t, e.project, ".venv/bin/activate", "export VIRTUAL_ENV=.evil\n", 0o644)
	writeFileMode(t, e.project, "calc/__pycache__/x.sh", "#!/bin/sh\necho x\n", 0o755)
	rewriteKeepingTimes(t, e.project, "calc/__pycache__/m.cpython-312.pyc", "bytecode-v2", 0o644)

	rep := review(t, e, "s1", []ContentScanner{})
	for _, label := range []string{"node_modules/", ".venv/", "calc/__pycache__/", "calc/__pycache__/x.sh"} {
		if _, ok := flagByLabel(rep, label); !ok {
			t.Errorf("review has no flag %s; flags: %+v", label, rep.Flags)
		}
	}
	if f, _ := flagByLabel(rep, "calc/__pycache__/x.sh"); f.Severity != SeverityHigh || f.Kind != RiskExecutable {
		t.Errorf("the new ignored executable = %+v, want a high executable flag", f)
	}

	if f, _ := flagByLabel(rep, "node_modules/"); f.Severity != SeverityHigh || !strings.Contains(f.Detail, ".bin/tool") ||
		!strings.Contains(f.Detail, "npm ci") || !strings.Contains(f.Detail, "Undo cannot restore node_modules/") {
		t.Errorf("node_modules flag = %+v", f)
	}
	if f, _ := flagByLabel(rep, ".venv/"); f.Severity != SeverityHigh || !strings.Contains(f.Detail, "bin/activate") {
		t.Errorf(".venv flag = %+v", f)
	}
	if f, _ := flagByLabel(rep, "calc/__pycache__/"); f.Kind != RiskAutoExec || f.Severity != SeverityMedium || !strings.Contains(f.Detail, "2 files were written") {
		t.Errorf("bytecode cache flag = %+v", f)
	}
	if n := countLabel(rep, "node_modules/"); n != 1 {
		t.Errorf("node_modules/ is flagged %d times: %+v", n, rep.Flags)
	}
	if line := rep.RiskLine(); !strings.Contains(line, "node_modules/") || !strings.Contains(line, "calc/__pycache__/x.sh") {
		t.Errorf("RiskLine = %q", line)
	}

	preview := mustUndo(t, e, "s1", true)
	if preview.Empty() {
		t.Fatalf("undo preview is empty although the session changed ignored executables: %+v", preview)
	}
	areas := map[string]IgnoredChange{}
	for _, c := range preview.Ignored {
		areas[c.Path] = c
	}
	if c := areas["calc/__pycache__/"]; !c.Removed || c.Added != 1 || c.Modified != 1 || c.ExecutableCount != 1 {
		t.Errorf("bytecode cache = %+v", c)
	}
	if c := areas["node_modules/"]; c.Removed || !c.Dependencies || c.Modified != 1 || c.Remedy == "" || c.Executables[0] != "node_modules/.bin/tool" {
		t.Errorf("node_modules = %+v", c)
	}
	if got := len(preview.Unrestored()); got != 2 {
		t.Errorf("Unrestored = %+v, want node_modules/ and .venv/", preview.Unrestored())
	}

	res := mustUndo(t, e, "s1", false)
	if len(res.Unrestored()) != 2 {
		t.Errorf("undo result Unrestored = %+v", res.Unrestored())
	}
	for _, gone := range []string{"calc/__pycache__/x.sh", "calc/__pycache__/m.cpython-312.pyc"} {
		if pathExists(filepath.Join(e.project, filepath.FromSlash(gone))) {
			t.Errorf("undo left %s", gone)
		}
	}
	// What undo cannot restore is left as the session left it.
	if got := readFile(t, e.project, "node_modules/.bin/tool"); !strings.Contains(got, "evil") {
		t.Errorf("node_modules/.bin/tool = %q", got)
	}
	// A second undo has nothing left to delete, but still names what it
	// cannot restore.
	again := mustUndo(t, e, "s1", true)
	if !again.Empty() || len(again.Unrestored()) != 2 {
		t.Errorf("second preview = empty %v, unrestored %+v", again.Empty(), again.Unrestored())
	}
}

func countLabel(r *ReviewReport, label string) int {
	n := 0
	for _, f := range r.Flags {
		if f.Label == label {
			n++
		}
	}
	return n
}

func TestIgnoredManifestCleanSessionAndMaskedFiles(t *testing.T) {
	e := ignoredProject(t)
	writeFile(t, e.project, ".env", "TOKEN=placeholder\n")
	opts := e.snapOpts("s1")
	opts.Skip = []string{".env"}
	if _, err := Snapshot(bg, opts); err != nil {
		t.Fatal(err)
	}
	man, err := loadIgnored(e.data, "s1")
	if err != nil || man == nil {
		t.Fatalf("manifest = %v, %v", man, err)
	}
	if _, ok := man.Files[".env"]; ok {
		t.Error("the masked .env is in the manifest")
	}
	if _, ok := man.Files["node_modules/.bin/tool"]; !ok || !man.covers("node_modules/") {
		t.Errorf("manifest roots %+v", man.Roots)
	}
	rep := review(t, e, "s1", []ContentScanner{})
	if len(rep.Flags) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("a session that changed nothing: flags %+v, warnings %v", rep.Flags, rep.Warnings)
	}
	if p := mustUndo(t, e, "s1", true); !p.Empty() || len(p.Ignored) != 0 {
		t.Fatalf("a session that changed nothing: %+v", p)
	}
	// A new ignored directory and an ignored file are reported; the masked
	// file, which the sandbox cannot change, never is.
	writeFileMode(t, e.project, "build/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "build/out.txt", "x\n")
	writeFile(t, e.project, "debug.log", "x\n")
	writeFile(t, e.project, ".env", "TOKEN=other\n")
	rep = review(t, e, "s1", []ContentScanner{})
	if f, ok := flagByLabel(rep, "build/tool"); !ok || f.Severity != SeverityHigh || !strings.Contains(f.Detail, "undo cannot restore it") {
		t.Errorf("build/tool flag = %+v (flags %+v)", f, rep.Flags)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "build/") || !strings.Contains(rep.Warnings[0], "debug.log") || strings.Contains(rep.Warnings[0], ".env") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
	p := mustUndo(t, e, "s1", true)
	if !p.Empty() || len(p.Unrestored()) != 2 {
		t.Errorf("preview: empty %v, unrestored %+v", p.Empty(), p.Unrestored())
	}
}

func TestIgnoredManifestPlainFolder(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, "main.py", "print(1)\n")
	writeFileMode(t, e.project, "node_modules/.bin/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "pkg/__pycache__/main.cpython-312.pyc", "v1")
	mustSnapshot(t, e, "p1")
	if p := mustUndo(t, e, "p1", true); len(p.Warnings) != 0 || len(p.Ignored) != 0 {
		t.Fatalf("clean plain preview: %+v", p)
	}
	writeFile(t, e.project, "node_modules/evil/index.js", "x\n")
	writeFile(t, e.project, "pkg/__pycache__/main.cpython-312.pyc", "v2")
	rep := review(t, e, "p1", []ContentScanner{})
	f, ok := flagByLabel(rep, "node_modules/")
	if !ok || f.Severity != SeverityMedium || !strings.Contains(f.Detail, "does not copy") {
		t.Errorf("node_modules flag = %+v (flags %+v)", f, rep.Flags)
	}
	if n := countLabel(rep, "node_modules/"); n != 1 {
		t.Errorf("node_modules/ is flagged %d times", n)
	}
	if _, ok := flagByLabel(rep, "pkg/__pycache__/"); !ok {
		t.Errorf("no bytecode flag: %+v", rep.Flags)
	}
	res := mustUndo(t, e, "p1", false)
	if pathExists(filepath.Join(e.project, "pkg", "__pycache__", "main.cpython-312.pyc")) {
		t.Error("undo left the changed bytecode")
	}
	if len(res.Unrestored()) != 1 || res.Unrestored()[0].Path != "node_modules/" {
		t.Errorf("Unrestored = %+v", res.Unrestored())
	}
}

func TestIgnoredManifestCapFallsBackToChangeTime(t *testing.T) {
	// Serial: it lowers package limits the parallel tests read.
	oldMax, oldSlack := maxIgnoredFiles, ignoredClockSlack
	maxIgnoredFiles, ignoredClockSlack = 3, 50*time.Millisecond
	t.Cleanup(func() { maxIgnoredFiles, ignoredClockSlack = oldMax, oldSlack })
	e := newSerialEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", "build/\n")
	e.git(e.project, "add", "-A")
	e.git(e.project, "commit", "-q", "-m", "ignore build")
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		writeFile(t, e.project, "build/"+n+".txt", n)
	}
	// Past the slack (and a coarse clock tick), so these files predate the
	// snapshot by their change time too.
	time.Sleep(200 * time.Millisecond)
	mustSnapshot(t, e, "c1")
	man, _ := loadIgnored(e.data, "c1")
	if man == nil || !man.Truncated || len(man.Files) != 3 {
		t.Fatalf("capped manifest = %+v", man)
	}
	rep := review(t, e, "c1", []ContentScanner{})
	if len(rep.Flags) != 0 {
		t.Fatalf("unchanged files past the cap were reported: %+v", rep.Flags)
	}
	if !slicesContain(rep.Warnings, "more files git ignores than DefenseClaw checks") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
	// d and e are past the cap: their change time gives them away.
	writeFileMode(t, e.project, "build/e.txt", "#!/bin/sh\n", 0o755)
	rep = review(t, e, "c1", []ContentScanner{})
	if _, ok := flagByLabel(rep, "build/e.txt"); !ok {
		t.Errorf("a changed file past the cap was missed: %+v", rep.Flags)
	}
}

func slicesContain(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestIgnoredManifestOlderSnapshotKeepsFingerprints(t *testing.T) {
	e := ignoredProject(t)
	mustSnapshot(t, e, "o1")
	lay, _ := newLayout(e.data)
	if err := os.Remove(lay.ignoredManifest("o1")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.project, "node_modules/new-pkg/index.js", "x\n")
	rep := review(t, e, "o1", []ContentScanner{})
	if f, ok := flagByLabel(rep, "node_modules/"); !ok || !strings.Contains(f.Detail, "installed or changed inside the sandbox") {
		t.Errorf("a snapshot without a manifest must keep the fingerprint flag: %+v", rep.Flags)
	}
	if p := mustUndo(t, e, "o1", true); len(p.Ignored) != 0 {
		t.Errorf("Ignored without a manifest = %+v", p.Ignored)
	}
}

func TestIgnoredWalkStaysInsideTheProject(t *testing.T) {
	e := ignoredProject(t)
	outside := filepath.Join(e.root, "outside")
	writeFile(t, outside, "__pycache__/keep.pyc", "operator file")
	mustSnapshot(t, e, "l1")
	// The session swaps calc/ for a symlink to a folder outside the project
	// that holds a bytecode cache of its own.
	if err := os.RemoveAll(filepath.Join(e.project, "calc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.project, "calc")); err != nil {
		t.Fatal(err)
	}
	res := mustUndo(t, e, "l1", false)
	if got := readFile(t, outside, "__pycache__/keep.pyc"); got != "operator file" {
		t.Fatalf("undo reached outside the project: %q", got)
	}
	for _, c := range res.Ignored {
		if c.Added > 0 || c.Modified > 0 {
			if strings.HasPrefix(c.Path, "calc/") {
				t.Errorf("files behind the symlink were read as the project's: %+v", c)
			}
		}
	}
}

func TestNormalizeRootsAndAreas(t *testing.T) {
	got := normalizeRoots([]string{"build/", "build/x", "a.log", "../up", "/abs", ".", "node_modules/", "node_modules/.bin/", "sub/b.log", "a.log"})
	want := []string{"a.log", "build/", "node_modules/", "sub/b.log"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("normalizeRoots = %v, want %v", got, want)
	}
	m := &ignoredManifest{Roots: []ignoredRoot{{Path: "build/", Complete: true}, {Path: "a.log", Complete: true}, {Path: "dist/"}}}
	for rel, want := range map[string]bool{"build": true, "build/": true, "build/x/y": true, "a.log": true, "dist/x": false, "builds/x": false, "x": false} {
		if got := m.covers(rel); got != want {
			t.Errorf("covers(%s) = %v", rel, got)
		}
	}
	roots := map[string]bool{"build/": true}
	for rel, want := range map[string]string{
		"node_modules/.bin/tool":                   "node_modules/",
		"web/node_modules/x/index.js":              "web/node_modules/",
		".venv/lib/python3.12/site-packages/a.pth": ".venv/",
		"calc/__pycache__/m.pyc":                   "calc/__pycache__/",
		"node_modules/x/__pycache__/m.pyc":         "node_modules/",
		"build/deep/tool":                          "build/",
		"debug.log":                                "debug.log",
		"sub/debug.log":                            "sub/debug.log",
	} {
		if got, _ := ignoredAreaOf(rel, roots); got != want {
			t.Errorf("ignoredAreaOf(%s) = %s, want %s", rel, got, want)
		}
	}
	for _, tc := range []struct {
		rel, area string
		mode      os.FileMode
		want      bool
	}{
		{"build/tool", "build/", 0o755, true},
		{"build/out.txt", "build/", 0o644, false},
		{".venv/bin/activate", ".venv/", 0o644, true},
		{"node_modules/.bin/tool", "node_modules/", os.ModeSymlink | 0o777, true},
		{".venv/lib/python3.12/site-packages/evil.pth", ".venv/", 0o644, true},
		{".venv/lib/python3.12/site-packages/sitecustomize.py", ".venv/", 0o644, true},
		{"node_modules/x/index.js", "node_modules/", 0o644, false},
	} {
		if got := runsOnHost(tc.rel, uint32(tc.mode), tc.area); got != tc.want {
			t.Errorf("runsOnHost(%s, %v) = %v", tc.rel, tc.mode, got)
		}
	}
}
