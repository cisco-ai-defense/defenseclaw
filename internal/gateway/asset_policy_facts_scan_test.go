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

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// GAP-1197: the folder that declares a skill name is found past the 256th
// entry of a skill root (files in the root do not count either).
func TestFoldersDeclaringSkillReadsPastTheOldEntryCap(t *testing.T) {
	root := t.TempDir()
	for i := range 300 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("a-note-%03d.md", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("b-skill-%03d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	renamed := filepath.Join(root, "zz-renamed")
	if err := os.Mkdir(renamed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(renamed, "SKILL.md"), []byte("---\nname: disabled-one\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := foldersDeclaringSkill(root, "disabled-one")
	if len(got) != 1 || got[0] != renamed {
		t.Fatalf("foldersDeclaringSkill = %v, want [%s]", got, renamed)
	}
}

// GAP-1197: past the folders it reads, every other folder of the root
// answers for the name, so the folder that declares it still gets the
// runtime disable (fail closed).
func TestFoldersDeclaringSkillFailsClosedPastTheScanCap(t *testing.T) {
	root := t.TempDir()
	for i := range maxDeclaredNameScan + 1 {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("b-skill-%05d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	renamed := filepath.Join(root, "zz-renamed")
	if err := os.Mkdir(renamed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(renamed, "SKILL.md"), []byte("---\nname: disabled-one\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := foldersDeclaringSkill(root, "disabled-one")
	if !slices.Contains(got, renamed) {
		t.Fatalf("foldersDeclaringSkill misses %s past the scan cap (%d folders listed)", renamed, len(got))
	}
}
