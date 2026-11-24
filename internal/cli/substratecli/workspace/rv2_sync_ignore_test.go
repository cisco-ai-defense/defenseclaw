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

//go:build unix

package workspace

import (
	"context"
	"path/filepath"
	"testing"
)

// RV2 N6 (guard): a folder git ignores but that holds a force-added
// tracked file is watched (check-ignore does not report a folder with
// tracked files as ignored); its wholly ignored subfolders are not.
func TestSyncWatchesForceAddedFilesUnderIgnoredFolder(t *testing.T) {
	o, _, _ := copyInActor(t)
	write(t, o.project, "build/app.js", "app\n", 0o644)
	write(t, o.project, "build/tmp/x.bin", "x\n", 0o644)
	o.git(o.project, "add", "-f", "build/app.js")
	o.git(o.project, "commit", "-q", "-m", "force-add")
	tw, err := newTreeWatcher(o.project, newIgnoreCache(context.Background(), o.project, true))
	if err != nil {
		t.Fatal(err)
	}
	defer tw.close()
	watched := map[string]bool{}
	for _, w := range tw.w.WatchList() {
		rel, _ := filepath.Rel(o.project, w)
		watched[filepath.ToSlash(rel)] = true
	}
	if !watched["build"] {
		t.Fatalf("build (holds the tracked build/app.js) is not watched: %v", watched)
	}
	if watched["build/tmp"] {
		t.Fatal("watches the wholly ignored build/tmp")
	}
}
