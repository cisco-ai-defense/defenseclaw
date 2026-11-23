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

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// A SKILL.md that is a hard link (a second name of another file, perhaps one
// the user cannot read) is hashed but its text is not kept, so neither the
// manifest nor its declared fields leave the endpoint (GAP-1811).
func TestHashSkillFolderKeepsNoHardLinkedManifest(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, []byte("---\nname: x\ndescription: not mine\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, filepath.Join(linked, "SKILL.md")); err != nil {
		t.Skipf("hard link: %v", err)
	}
	hash, status, manifest, _ := hashSkillFolder(linked, maxSkillBytes)
	if status != SkillContentOK || hash == "" {
		t.Fatalf("hard-linked skill: status %q hash %q, want ok with a hash", status, hash)
	}
	if manifest != nil {
		t.Fatalf("hard-linked SKILL.md kept as the manifest: %q", manifest)
	}

	plain := filepath.Join(dir, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plain, "SKILL.md"), []byte("---\nname: y\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, status, manifest, _ := hashSkillFolder(plain, maxSkillBytes); status != SkillContentOK || manifest == nil {
		t.Fatalf("own SKILL.md: status %q manifest %q, want it kept", status, manifest)
	}
}
