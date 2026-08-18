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

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSignalFromDirectoryChildrenExpandsBundledSkillContainer verifies
// the walker's `.system`-handling contract for skill directories:
//
//   - The `.system` directory itself is NEVER emitted as a skill_entry
//     (would let managed remediation act on the vendor container).
//   - Each `.system/<child>` IS emitted as a skill_entry with
//     origin="bundled", bundled=true so downstream mutation surfaces
//     can hard-refuse.
//   - Sibling user skills next to `.system` continue to emit with
//     origin="user" — a same-named user skill remains discoverable
//     and (per policy) enforceable.
//
// Non-skill detectors (`rule` / `plugin`) do NOT expand `.system`
// because the reserved-container contract is skill-specific.
func TestSignalFromDirectoryChildrenExpandsBundledSkillContainer(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	if err := os.MkdirAll(filepath.Join(skillsRoot, ".system", "hello"), 0o755); err != nil {
		t.Fatalf("prepare bundled hello: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(skillsRoot, ".system", "goodbye"), 0o755); err != nil {
		t.Fatalf("prepare bundled goodbye: %v", err)
	}
	// Same-named user skill next to the bundled container — must
	// still emit and remain distinguishable by origin.
	if err := os.MkdirAll(filepath.Join(skillsRoot, "hello"), 0o755); err != nil {
		t.Fatalf("prepare user hello: %v", err)
	}
	// Ordinary user skill sibling.
	if err := os.MkdirAll(filepath.Join(skillsRoot, "custom-review"), 0o755); err != nil {
		t.Fatalf("prepare user custom-review: %v", err)
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromDirectoryChildren(sig, SignalSkill, "skill", skillsRoot)

	byBasename := map[string]AIEvidence{}
	for _, ev := range signal.Evidence {
		if ev.Type == "skill_entry" {
			byBasename[ev.Basename] = ev
		}
	}

	// `.system` container must NOT appear as a skill_entry — that's
	// the whole point of the special-case.
	if _, ok := byBasename[".system"]; ok {
		t.Fatal("`.system` container was emitted as an ordinary skill_entry; walker special-case regressed")
	}

	// Bundled children must be present with origin/bundled stamped.
	for _, name := range []string{"hello", "goodbye"} {
		ev, ok := byBasename[name]
		if !ok {
			t.Fatalf("missing bundled skill_entry for %q; got %v", name, keys(byBasename))
		}
		// Note: two `hello` entries would collapse into one map slot
		// but the user-hello case (Origin=user) is asserted below.
		// This assertion is for the .system/hello reachable name.
		// We separate assertions by asserting the specific origins
		// present overall.
		_ = ev
	}

	var bundledCount, userCount int
	for _, ev := range signal.Evidence {
		if ev.Type != "skill_entry" {
			continue
		}
		switch ev.Origin {
		case "bundled":
			if !ev.Bundled {
				t.Fatalf("skill_entry %q has Origin=bundled but Bundled=false; origin/bundled must be in sync", ev.Basename)
			}
			bundledCount++
		case "user":
			if ev.Bundled {
				t.Fatalf("skill_entry %q has Origin=user but Bundled=true", ev.Basename)
			}
			userCount++
		default:
			t.Fatalf("skill_entry %q has empty Origin; missing-provenance rule requires explicit user|bundled stamp", ev.Basename)
		}
	}
	if bundledCount != 2 {
		t.Fatalf("bundled skill_entry count: got %d, want 2 (.system/hello + .system/goodbye)", bundledCount)
	}
	if userCount != 2 {
		t.Fatalf("user skill_entry count: got %d, want 2 (hello + custom-review)", userCount)
	}
}

// TestSignalFromDirectoryChildrenNonSkillDetectorTreatsSystemLiterally
// asserts the .system special-case is scoped to detector="skill". A
// plugin or rule directory named .system stays as a plain child so we
// don't accidentally reshape unrelated walkers.
func TestSignalFromDirectoryChildrenNonSkillDetectorTreatsSystemLiterally(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	pluginRoot := filepath.Join(root, "plugins")
	if err := os.MkdirAll(filepath.Join(pluginRoot, ".system"), 0o755); err != nil {
		t.Fatalf("prepare plugin .system: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(pluginRoot, "user-plugin"), 0o755); err != nil {
		t.Fatalf("prepare user plugin: %v", err)
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromDirectoryChildren(sig, SignalPlugin, "plugin", pluginRoot)

	seen := map[string]bool{}
	for _, ev := range signal.Evidence {
		if ev.Type == "plugin_entry" {
			seen[ev.Basename] = true
		}
	}
	if !seen[".system"] {
		t.Fatalf("plugin detector should emit `.system` as an ordinary plugin_entry; got %v", seen)
	}
	if !seen["user-plugin"] {
		t.Fatalf("plugin detector missed user-plugin; got %v", seen)
	}
}

func keys(m map[string]AIEvidence) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
