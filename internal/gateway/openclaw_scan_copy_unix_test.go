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

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10 REVIEW-6 P2-1: the separate-user scan reads a private copy made
// without following links; a link in the tree is not copied and a link on
// the way to the target makes the copy fail.
func TestCopyOpenClawScanTargetFollowsNoLinks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "oc-home")
	secret := filepath.Join(root, "dc-data")
	skill := filepath.Join(home, "skills", "s1")
	for _, d := range []string{skill, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "token"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(skill, "link")); err != nil {
		t.Fatal(err)
	}
	copied, err := copyOpenClawScanTarget(skill, []string{home})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(copied)) })
	if b, err := os.ReadFile(filepath.Join(copied, "SKILL.md")); err != nil || string(b) != "ok" {
		t.Fatalf("SKILL.md not copied: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(copied, "link")); !os.IsNotExist(err) {
		t.Fatalf("the link was copied or followed: %v", err)
	}

	// The target outside every anchor is refused.
	if _, err := copyOpenClawScanTarget(secret, []string{home}); err == nil {
		t.Fatal("a target outside the anchors was copied")
	}
	// A link inside the anchor that leads out resolves outside: refused.
	if err := os.Symlink(secret, filepath.Join(home, "skills", "swapped")); err != nil {
		t.Fatal(err)
	}
	if _, err := copyOpenClawScanTarget(filepath.Join(home, "skills", "swapped"), []string{home}); err == nil {
		t.Fatal("a link out of the anchor was copied")
	}
}
