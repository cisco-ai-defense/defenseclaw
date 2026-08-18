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

package enforce

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIsBundledSkillPath(t *testing.T) {
	t.Parallel()
	sep := string(filepath.Separator)
	// Table drives both positive and negative cases; each row asserts
	// exactly one boolean so a regression here points at one case, not
	// a matrix cell in a subtable.
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"user skill", "/Users/me/.codex/skills/hello", false},
		{"bundled container itself",
			"/Users/me/.codex/skills/.system", true},
		{"bundled child",
			"/Users/me/.codex/skills/.system/hello", true},
		{"bundled grandchild",
			"/Users/me/.codex/skills/.system/hello/README.md", true},
		{"basename contains .system substring only",
			"/Users/me/.codex/skills/hello.system.md", false},
		{"middle .system segment",
			"/some" + sep + ".system" + sep + "elsewhere", true},
		{"relative path bundled child",
			".codex/skills/.system/foo", true},
		{"cleaned trailing separator",
			"/Users/me/.codex/skills/.system" + sep, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsBundledSkillPath(tc.path); got != tc.want {
				t.Fatalf("IsBundledSkillPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestIsBundledSkillContainerName(t *testing.T) {
	t.Parallel()
	if !IsBundledSkillContainerName(".system") {
		t.Fatal("literal .system name should be classified as container")
	}
	if !IsBundledSkillContainerName("  .system  ") {
		t.Fatal("leading/trailing whitespace should be tolerated (walker passes entry.Name() as-is)")
	}
	if IsBundledSkillContainerName("system") {
		t.Fatal("system without leading dot must not classify as bundled container")
	}
	if IsBundledSkillContainerName(".SYSTEM") {
		t.Fatal("case-sensitive check: uppercase .SYSTEM is not the reserved name")
	}
}

// TestPluginEnforcerQuarantineRefusesBundledSkill verifies the
// path-level guard fires BEFORE any stat/copy on the source tree.
// A bundled skill placed at a real filesystem location must return
// ErrBundledSkill unchanged, and the source file must remain in place
// afterward so a caller retrying with a different (non-bundled)
// target sees an untouched tree.
func TestPluginEnforcerQuarantineRefusesBundledSkill(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bundledDir := filepath.Join(root, ".codex", "skills", ".system", "hello")
	if err := os.MkdirAll(bundledDir, 0o755); err != nil {
		t.Fatalf("prepare bundled skill: %v", err)
	}
	marker := filepath.Join(bundledDir, "skill.md")
	if err := os.WriteFile(marker, []byte("bundled content"), 0o644); err != nil {
		t.Fatalf("write bundled skill marker: %v", err)
	}

	quarantineDir := filepath.Join(root, "quarantine")
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		t.Fatalf("prepare quarantine dir: %v", err)
	}
	e := NewPluginEnforcer(quarantineDir, nil)
	dest, err := e.Quarantine(bundledDir)
	if !errors.Is(err, ErrBundledSkill) {
		t.Fatalf("expected ErrBundledSkill, got dest=%q err=%v", dest, err)
	}
	if dest != "" {
		t.Fatalf("expected empty dest on refusal, got %q", dest)
	}
	// Source tree must remain untouched.
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("bundled source was disturbed on refusal: %v", statErr)
	}
	// Quarantine store must NOT have received a partial copy.
	if entries, _ := os.ReadDir(filepath.Join(quarantineDir, "plugins")); len(entries) > 0 {
		t.Fatalf("quarantine store received partial copy: %v", entries)
	}
}

// TestPluginEnforcerQuarantineAcceptsUserSkill is the positive
// baseline: an ordinary user skill (same directory shape as bundled,
// minus the `.system` container) must move to quarantine as before.
// Guards a regression where the .system check falsely matches a
// sibling directory.
func TestPluginEnforcerQuarantineAcceptsUserSkill(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	userDir := filepath.Join(root, ".codex", "skills", "hello")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatalf("prepare user skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "skill.md"), []byte("user"), 0o644); err != nil {
		t.Fatalf("write user marker: %v", err)
	}
	quarantineDir := filepath.Join(root, "quarantine")
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		t.Fatalf("prepare quarantine: %v", err)
	}
	e := NewPluginEnforcer(quarantineDir, nil)
	dest, err := e.Quarantine(userDir)
	if err != nil {
		t.Fatalf("user skill quarantine failed: %v", err)
	}
	if dest == "" {
		t.Fatal("expected a quarantine destination path")
	}
	if _, statErr := os.Stat(userDir); !os.IsNotExist(statErr) {
		t.Fatalf("user skill source not removed after quarantine: %v", statErr)
	}
	if _, statErr := os.Stat(dest); statErr != nil {
		t.Fatalf("quarantine copy missing at %q: %v", dest, statErr)
	}
}
