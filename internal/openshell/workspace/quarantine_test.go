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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
)

const (
	testQuarantine      = "vendor/tool/" + nestguard.QuarantinePrefix + "20260928T054445Z"
	testQuarantineAgain = testQuarantine + "-1"
)

// plantQuarantine lays out what the guard leaves of one `git init` in
// vendor/tool that git recreated under the rename: two quarantined trees,
// the first with git's stock sample hooks, the second with empty
// directories only.
func plantQuarantine(t *testing.T, e *env) {
	t.Helper()
	for _, hook := range []string{"applypatch-msg.sample", "commit-msg.sample", "fsmonitor-watchman.sample", "post-update.sample"} {
		writeFileMode(t, e.project, testQuarantine+"/hooks/"+hook, "#!/bin/sh\n# ../../etc sample\nexit 0\n", 0o755)
	}
	writeFile(t, e.project, testQuarantine+"/HEAD", "ref: refs/heads/main\n")
	for _, dir := range []string{"objects/pack", "refs/heads", "refs/tags", "branches"} {
		mustMkdir(t, filepath.Join(e.project, filepath.FromSlash(testQuarantine), filepath.FromSlash(dir)))
		mustMkdir(t, filepath.Join(e.project, filepath.FromSlash(testQuarantineAgain), filepath.FromSlash(dir)))
	}
}

// A quarantined repository buried the session's real risks under git's
// sample hooks (23 entries, a 1000-line diff). It is one critical entry
// now, and its files are out of the counts, the scans and the diff.
func TestReviewCollapsesQuarantinedRepositories(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	plantQuarantine(t, e)
	writeFile(t, e.project, "package.json", `{"scripts":{"postinstall":"node x.js"}}`)

	rep := review(t, e, "s1", nil)
	var quarantined []Flag
	for _, f := range rep.Flags {
		if strings.Contains(f.Path, nestguard.QuarantinePrefix) {
			quarantined = append(quarantined, f)
		}
	}
	if len(quarantined) != 1 || quarantined[0].Severity != SeverityCritical || quarantined[0].Kind != RiskNestedRepo ||
		quarantined[0].Label != "vendor/tool/.git (quarantined)" || !strings.Contains(quarantined[0].Detail, "5 file(s)") ||
		rep.Flags[0].Label != quarantined[0].Label {
		t.Fatalf("quarantine flags = %+v, want one, first (all %+v)", quarantined, rep.Flags)
	}
	if _, ok := flagByLabel(rep, "package.json#scripts.postinstall"); !ok {
		t.Fatalf("the postinstall is not flagged: %+v", rep.Flags)
	}
	for _, c := range rep.Changes {
		if strings.Contains(c.Path, nestguard.QuarantinePrefix) {
			t.Fatalf("a quarantined file is in the changes: %+v", c)
		}
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Path, nestguard.QuarantinePrefix) {
			t.Fatalf("a quarantined file was scanned: %+v", f)
		}
	}
	if labels := rep.HostExecLabels(); rep.FilesChanged != 1 || !slices.Contains(labels, "vendor/tool/.git (quarantined)") || len(labels) != 2 {
		t.Fatalf("files changed = %d (want the package.json only), host exec labels = %v", rep.FilesChanged, labels)
	}
	diff, err := ReviewDiff(bg, e.data, "s1")
	if err != nil || strings.Contains(string(diff), "sample") || !strings.Contains(string(diff), "postinstall") ||
		!strings.Contains(string(diff), "file(s) of quarantined git repositories are left out: "+testQuarantine) {
		t.Fatalf("diff = %s, %v", diff, err)
	}
}

// Undo left the quarantines' empty directory trees in the project; it
// removes each quarantined .git of the session now. What undo was not told
// about stays, and so does a path that is not a quarantine or escapes the
// project.
func TestUndoRemovesQuarantineSkeletons(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	mustSnapshot(t, e, "s1")
	plantQuarantine(t, e)
	outside := "src/" + nestguard.QuarantinePrefix + "20260101T000000Z"
	mustMkdir(t, filepath.Join(e.project, filepath.FromSlash(outside)))

	res, err := Undo(bg, UndoOptions{DataDir: e.data, Name: "s1",
		Quarantined: []string{testQuarantine, testQuarantineAgain, "../escape/" + nestguard.QuarantinePrefix + "x", "README.md"}})
	if err != nil || !slices.Equal(res.QuarantineRemoved, []string{testQuarantine, testQuarantineAgain}) {
		t.Fatalf("removed = %+v, %v", res, err)
	}
	wantFiles(t, e.project, testQuarantine, absent, testQuarantineAgain, absent, outside, present, "README.md", present)
}

// A quarantined tree that still holds a file the restore did not take is
// kept, with a warning.
func TestRemoveQuarantinedKeepsFiles(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.project, testQuarantine+"/keep.txt", "x\n")
	if removed, warnings := removeQuarantined(e.project, []string{testQuarantine}); len(removed) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "keep.txt") {
		t.Fatalf("removed %v, warnings %v", removed, warnings)
	}
	wantFiles(t, e.project, testQuarantine+"/keep.txt", "x\n")
}
