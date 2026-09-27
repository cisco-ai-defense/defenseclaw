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
	"strings"
	"testing"
)

// A sandbox named "git" is now refused because it would conflict with the
// shadow storage root (which was previously under snapshots/git/, but is now
// separate at shadows/).
func TestSandboxNamedGitKeepsOtherSnapshots(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	// Verify "git" is a reserved name.
	_, err := Snapshot(bg, e.snapOpts("git"))
	if err == nil {
		t.Fatal("snapshot named 'git' should be refused")
	}
	if !strings.Contains(err.Error(), "reserved") && !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected reservation error, got: %v", err)
	}
	// Verify shadows are stored separately from per-name snapshot directories.
	a := mustSnapshot(t, e, "a")
	if got, want := filepath.Dir(a.Git.Shadow), filepath.Join(e.data, "shadows"); got != want {
		t.Fatalf("shadow lives in %s, want %s", got, want)
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
