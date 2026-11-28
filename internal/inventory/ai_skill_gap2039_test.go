// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// GAP-2039: moving ~/.claude to a dotfiles repo and linking it back must not
// change the hash of a skill whose bytes did not change, with a cached scan
// before the move or without one, for a skill with a multi-megabyte file.
func TestGAP2039SkillHashSurvivesAMoveThroughALink(t *testing.T) {
	for _, cached := range []bool{true, false} {
		home := t.TempDir()
		skill := filepath.Join(home, ".claude", "skills", "big")
		writeSkillFiles(t, skill, map[string]string{"SKILL.md": gap2001Manifest})
		if err := os.WriteFile(filepath.Join(skill, "data.bin"), bytes.Repeat([]byte("0123456789abcdef"), 3<<16), 0o644); err != nil {
			t.Fatal(err)
		}
		svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
			Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
		}, nil)
		cleanupPreparedDiscoveryService(t, svc)
		svc.skillClock = skillClockAfterTheWrites

		before := *svc.skillFacts(skill, false)
		if before.ContentStatus != SkillContentOK {
			t.Fatalf("before the move: %+v", before)
		}
		if err := os.MkdirAll(filepath.Join(home, "dotfiles"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(home, ".claude"), filepath.Join(home, "dotfiles", "claude")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(home, "dotfiles", "claude"), filepath.Join(home, ".claude")); err != nil {
			t.Fatal(err)
		}
		if !cached {
			svc.skillHashCache = nil
		}
		svc.resetSkillFacts()
		after := *svc.skillFacts(skill, false)
		if after.ContentHash != before.ContentHash || after.ContentStatus != before.ContentStatus {
			t.Fatalf("cached=%t: hash after the move %+v, before %+v", cached, after, before)
		}
	}
}
