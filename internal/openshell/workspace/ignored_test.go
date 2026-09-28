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
	e.commit("python and node")
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
	must(t, os.Chtimes(p, info.ModTime(), info.ModTime()))
}

// flagWith fails unless the report has exactly one flag for label, of the
// given severity (any when empty), whose detail holds every phrase.
func flagWith(t *testing.T, rep *ReviewReport, label string, sev Severity, phrases ...string) Flag {
	t.Helper()
	var got []Flag
	for _, f := range rep.Flags {
		if f.Label == label {
			got = append(got, f)
		}
	}
	if len(got) != 1 || (sev != "" && got[0].Severity != sev) {
		t.Fatalf("flags for %s = %+v, want one of severity %q (all flags %+v)", label, got, sev, rep.Flags)
	}
	for _, p := range phrases {
		if !strings.Contains(got[0].Detail, p) {
			t.Fatalf("%s detail %q lacks %q", label, got[0].Detail, p)
		}
	}
	return got[0]
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
	if f := flagWith(t, rep, "calc/__pycache__/x.sh", SeverityHigh); f.Kind != RiskExecutable {
		t.Errorf("the new ignored executable = %+v", f)
	}
	flagWith(t, rep, "node_modules/", SeverityHigh, ".bin/tool", "npm ci", "Undo cannot restore node_modules/")
	flagWith(t, rep, ".venv/", SeverityHigh, "bin/activate")
	if f := flagWith(t, rep, "calc/__pycache__/", SeverityMedium, "2 files were written"); f.Kind != RiskAutoExec {
		t.Errorf("bytecode cache flag = %+v", f)
	}
	if line := rep.RiskLine(); !strings.Contains(line, "node_modules/") || !strings.Contains(line, "calc/__pycache__/x.sh") {
		t.Errorf("RiskLine = %q", line)
	}

	preview := mustUndo(t, e, "s1", true)
	if preview.Empty() || len(preview.Unrestored()) != 2 {
		t.Fatalf("undo preview = %+v; want changes, and node_modules/ and .venv/ it cannot restore", preview)
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
	if res := mustUndo(t, e, "s1", false); len(res.Unrestored()) != 2 {
		t.Errorf("undo result Unrestored = %+v", res.Unrestored())
	}
	wantFiles(t, e.project, "calc/__pycache__/x.sh", absent, "calc/__pycache__/m.cpython-312.pyc", absent,
		// What undo cannot restore is left as the session left it.
		"node_modules/.bin/tool", "#!/bin/sh\necho evil\n")
	// A second undo has nothing left to delete, but still names what it
	// cannot restore.
	if again := mustUndo(t, e, "s1", true); !again.Empty() || len(again.Unrestored()) != 2 {
		t.Errorf("second preview = empty %v, unrestored %+v", again.Empty(), again.Unrestored())
	}
}

// TestIgnoredManifestCleanSessionAndMaskedFiles: an untouched session has
// nothing to report; a new ignored directory and an ignored file are, the
// masked file (which the sandbox cannot change) never is. A snapshot from
// before the manifest existed keeps the fingerprint flag.
func TestIgnoredManifestCleanSessionAndMaskedFiles(t *testing.T) {
	e := ignoredProject(t)
	writeFile(t, e.project, ".env", "TOKEN=placeholder\n")
	opts := e.snapOpts("s1")
	opts.Skip = []string{".env"}
	if _, err := Snapshot(bg, opts); err != nil {
		t.Fatal(err)
	}
	mustSnapshot(t, e, "o1")
	lay, _ := newLayout(e.data)
	must(t, os.Remove(lay.ignoredManifest("o1")))
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
	if rep := review(t, e, "s1", []ContentScanner{}); len(rep.Flags) != 0 || len(rep.Warnings) != 0 {
		t.Fatalf("a session that changed nothing: flags %+v, warnings %v", rep.Flags, rep.Warnings)
	}
	if p := mustUndo(t, e, "s1", true); !p.Empty() || len(p.Ignored) != 0 {
		t.Fatalf("a session that changed nothing: %+v", p)
	}
	writeFileMode(t, e.project, "build/tool", "#!/bin/sh\n", 0o755)
	writeFile(t, e.project, "build/out.txt", "x\n")
	writeFile(t, e.project, "debug.log", "x\n")
	writeFile(t, e.project, ".env", "TOKEN=other\n")
	rep := review(t, e, "s1", []ContentScanner{})
	flagWith(t, rep, "build/tool", SeverityHigh, "undo cannot restore it")
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "build/") || !strings.Contains(rep.Warnings[0], "debug.log") || strings.Contains(rep.Warnings[0], ".env") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
	if p := mustUndo(t, e, "s1", true); !p.Empty() || len(p.Unrestored()) != 2 {
		t.Errorf("preview: empty %v, unrestored %+v", p.Empty(), p.Unrestored())
	}

	writeFile(t, e.project, "node_modules/new-pkg/index.js", "x\n")
	flagWith(t, review(t, e, "o1", []ContentScanner{}), "node_modules/", "", "installed or changed inside the sandbox")
	if p := mustUndo(t, e, "o1", true); len(p.Ignored) != 0 {
		t.Errorf("Ignored without a manifest = %+v", p.Ignored)
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
	e.commit("ignore build")
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		writeFile(t, e.project, "build/"+n+".txt", n)
	}
	// Past the slack (and a coarse clock tick), so these files predate the
	// snapshot by their change time too.
	time.Sleep(200 * time.Millisecond)
	mustSnapshot(t, e, "c1")
	if man, _ := loadIgnored(e.data, "c1"); man == nil || !man.Truncated || len(man.Files) != 3 {
		t.Fatalf("capped manifest = %+v", man)
	}
	rep := review(t, e, "c1", []ContentScanner{})
	if len(rep.Flags) != 0 || !strings.Contains(strings.Join(rep.Warnings, "\n"), "more files git ignores than DefenseClaw checks") {
		t.Fatalf("unchanged files past the cap: flags %+v, warnings %v", rep.Flags, rep.Warnings)
	}
	// d and e are past the cap: their change time gives them away.
	writeFileMode(t, e.project, "build/e.txt", "#!/bin/sh\n", 0o755)
	flagWith(t, review(t, e, "c1", []ContentScanner{}), "build/e.txt", "")
}

func TestIgnoredWalkStaysInsideTheProject(t *testing.T) {
	e := ignoredProject(t)
	outside := filepath.Join(e.root, "outside")
	writeFile(t, outside, "__pycache__/keep.pyc", "operator file")
	mustSnapshot(t, e, "l1")
	// The session swaps calc/ for a symlink to a folder outside the project
	// that holds a bytecode cache of its own.
	mustRemove(t, e.project, "calc")
	mustSymlink(t, outside, filepath.Join(e.project, "calc"))
	res := mustUndo(t, e, "l1", false)
	wantFiles(t, outside, "__pycache__/keep.pyc", "operator file")
	for _, c := range res.Ignored {
		if (c.Added > 0 || c.Modified > 0) && strings.HasPrefix(c.Path, "calc/") {
			t.Errorf("files behind the symlink were read as the project's: %+v", c)
		}
	}
}

func TestNormalizeRootsAndAreas(t *testing.T) {
	got := normalizeRoots([]string{"build/", "build/x", "a.log", "../up", "/abs", ".", "node_modules/", "node_modules/.bin/", "sub/b.log", "a.log"})
	if want := "a.log,build/,node_modules/,sub/b.log"; strings.Join(got, ",") != want {
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
