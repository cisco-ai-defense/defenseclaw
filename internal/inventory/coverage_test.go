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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSignalFromDirectoryChildrenCapExceededStampsPartial covers
// Vineet's [P1] silent-truncation finding (evidence limit / per-item cap)
// for skill/plugin/rule directories: when we have more children than fit
// under maxEvidencePerSignal, the emitted signal MUST carry
// Partial=true, CoverageReason="cap_exceeded" so managed remediation
// can distinguish "31 skills exist" from "32+ skills exist but we
// truncated." Explicitly enumerate one more than the cap so the guard
// fires deterministically regardless of iteration order.
func TestSignalFromDirectoryChildrenCapExceededStampsPartial(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	// Emit one child more than the parent-inclusive per-signal
	// evidence cap so the cap fires even after we reserve slot 0 for
	// the parent-directory row.
	for i := 0; i < maxEvidencePerSignal+5; i++ {
		if err := os.MkdirAll(filepath.Join(skillsRoot, fmt.Sprintf("skill-%03d", i)), 0o755); err != nil {
			t.Fatalf("prepare child %d: %v", i, err)
		}
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromDirectoryChildren(sig, SignalSkill, "skill", skillsRoot)

	if !signal.Partial {
		t.Fatalf("expected Partial=true when cap exceeded; got Partial=false with %d evidence rows", len(signal.Evidence))
	}
	if signal.CoverageReason != CoverageReasonCapExceeded {
		t.Fatalf("expected CoverageReason=%q, got %q", CoverageReasonCapExceeded, signal.CoverageReason)
	}
	if len(signal.Evidence) != maxEvidencePerSignal {
		t.Fatalf("expected exactly %d evidence rows (parent + %d children), got %d",
			maxEvidencePerSignal, maxEvidencePerSignal-1, len(signal.Evidence))
	}
}

// TestSignalFromDirectoryChildrenReadableDirNotPartial is the negative
// baseline. A small user-skill directory with no cap pressure and no
// read errors MUST leave Partial=false / CoverageReason="" so the
// omitempty JSON tags keep the fields off the wire.
func TestSignalFromDirectoryChildrenReadableDirNotPartial(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	for _, name := range []string{"hello", "goodbye", "custom-review"} {
		if err := os.MkdirAll(filepath.Join(skillsRoot, name), 0o755); err != nil {
			t.Fatalf("prepare %s: %v", name, err)
		}
	}

	s := &ContinuousDiscoveryService{}
	signal := s.signalFromDirectoryChildren(AISignature{ID: "codex"}, SignalSkill, "skill", skillsRoot)

	if signal.Partial {
		t.Fatalf("readable non-truncated dir should NOT be partial; got CoverageReason=%q", signal.CoverageReason)
	}
	if signal.CoverageReason != "" {
		t.Fatalf("readable non-truncated dir should have empty CoverageReason; got %q", signal.CoverageReason)
	}
	// omitempty round-trip: partial/coverage_reason must not appear
	// on the wire when the snapshot is complete.
	raw, err := json.Marshal(signal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["partial"]; ok {
		t.Fatalf("`partial` should be omitted from wire when false; got %s", string(raw))
	}
	if _, ok := decoded["coverage_reason"]; ok {
		t.Fatalf("`coverage_reason` should be omitted when empty; got %s", string(raw))
	}
}

// TestSignalFromDirectoryChildrenPermissionDeniedStampsPartial covers
// the read-side coverage gap. When the walker cannot list a directory
// due to a mode bit, downstream must see Partial=true /
// CoverageReason="permission_denied" — not a silent "zero children."
// Skips on non-unix hosts because 0o000 mode enforcement is
// platform-specific.
func TestSignalFromDirectoryChildrenPermissionDeniedStampsPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode-bit permission enforcement is unix-only")
	}
	t.Parallel()
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	if err := os.MkdirAll(skillsRoot, 0o755); err != nil {
		t.Fatalf("prepare skills dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillsRoot, "hello", "README.md"), []byte("x"), 0o644); err == nil {
		t.Fatal("write should have failed on a non-existent parent — test setup bug")
	}
	if err := os.MkdirAll(filepath.Join(skillsRoot, "hello"), 0o755); err != nil {
		t.Fatalf("prepare hello: %v", err)
	}
	// Drop read+execute on the skills root so os.ReadDir fails with
	// EACCES. Chmod back afterward so the tempdir cleanup can walk
	// the tree.
	if err := os.Chmod(skillsRoot, 0o000); err != nil {
		t.Fatalf("chmod 000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(skillsRoot, 0o755) })

	s := &ContinuousDiscoveryService{}
	signal := s.signalFromDirectoryChildren(AISignature{ID: "codex"}, SignalSkill, "skill", skillsRoot)

	// Root as owner may still have access in some sandboxes; skip if so.
	if !signal.Partial {
		if os.Geteuid() == 0 {
			t.Skip("running as root — mode bits do not restrict access, cannot exercise permission-denied path")
		}
		t.Fatalf("expected Partial=true on permission-denied dir; got CoverageReason=%q", signal.CoverageReason)
	}
	if signal.CoverageReason != CoverageReasonPermissionDenied && signal.CoverageReason != CoverageReasonReadError {
		t.Fatalf("expected CoverageReason permission_denied or read_error, got %q", signal.CoverageReason)
	}
}
