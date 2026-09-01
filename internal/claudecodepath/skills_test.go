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

package claudecodepath

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestProjectSkillDirsIncludesLaunchAncestorsAndLazyNestedRoots(t *testing.T) {
	repository := filepath.Join(t.TempDir(), "repo")
	launch := filepath.Join(repository, "apps", "web")
	nested := filepath.Join(launch, "packages", "ui", ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(repository, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}

	got := ProjectSkillDirs(launch)
	for _, want := range []string{
		filepath.Join(launch, ".claude", "skills"),
		filepath.Join(repository, "apps", ".claude", "skills"),
		filepath.Join(repository, ".claude", "skills"),
		nested,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("ProjectSkillDirs() = %v, missing %q", got, want)
		}
	}
}

func TestSkillDirsFollowsAndDeduplicatesDocumentedDirectorySymlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	target := filepath.Join(t.TempDir(), "shared-skill")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"first", "second"} {
		if err := os.Symlink(target, filepath.Join(root, alias)); err != nil {
			t.Skipf("directory symlinks unavailable: %v", err)
		}
	}

	got := SkillDirs(root)
	if len(got) != 1 || !samePath(got[0], target) {
		t.Fatalf("SkillDirs() = %v, want canonical target %s once", got, target)
	}
}
