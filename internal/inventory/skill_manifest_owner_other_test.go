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
	hash, status, manifest, _ := hashSkillFolderCapture(linked, maxSkillBytes, maxSkillBytes)
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
	if _, status, manifest, _ := hashSkillFolderCapture(plain, maxSkillBytes, maxSkillBytes); status != SkillContentOK || manifest == nil {
		t.Fatalf("own SKILL.md: status %q manifest %q, want it kept", status, manifest)
	}
}

// The ownership check judges the file the walk read, not whatever the path
// names when it runs. A hard-linked SKILL.md that is swapped, after it was
// opened, for an own single-link copy with the same bytes is still refused;
// a check that opens the path again and compares the bytes would keep it
// (GAP-1811).
func TestSkillManifestOwnedChecksTheOpenedFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "skill")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	text := []byte("---\nname: x\ndescription: not mine\n---\n")
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, text, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "SKILL.md")
	for _, name := range []string{manifest, filepath.Join(dir, "third-name.txt")} {
		if err := os.Link(other, name); err != nil {
			t.Skipf("hard link: %v", err)
		}
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, text, 0o644); err != nil {
		t.Fatal(err)
	}
	if skillManifestOwned(opened, rootInfo) {
		t.Fatal("a hard-linked SKILL.md swapped out after it was opened was kept")
	}
	current, err := os.Open(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	if !skillManifestOwned(current, rootInfo) {
		t.Fatal("an own single-link SKILL.md was refused")
	}
	folder, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	if skillManifestOwned(folder, rootInfo) || skillManifestOwned(nil, rootInfo) || skillManifestOwned(current, nil) {
		t.Fatal("a folder, a missing file or a missing owner was accepted")
	}
}
