// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2034: a skill that read as unreadable reads ok on the first scan after
// it stops changing. No scan keeps a failed read: the hash cache keeps only
// an ok or too-large folder, skillFactsSeen lasts one scan, and the
// safefile retry keeps no state between reads.
func TestGAP2034UnreadableSkillReadsOkOnTheNextQuietScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "churn")
	writeSkillFiles(t, dir, map[string]string{
		"SKILL.md": "---\nname: churn\n---\nbody\n",
		"data.bin": "payload\n",
	})
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	svc.skillClock = skillClockAfterTheWrites
	scan := func() *AISkillFacts {
		t.Helper()
		svc.beginSkillFactsScan()
		defer svc.resetSkillFacts()
		return svc.skillFacts(dir, false)
	}
	first := scan()
	if first.ContentStatus != SkillContentOK || first.ContentHash == "" {
		t.Fatalf("first scan: %+v", first)
	}
	data := filepath.Join(dir, "data.bin")
	if err := os.Chmod(data, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if got := scan(); got.ContentStatus != SkillContentUnreadable || got.ContentHash != "" {
			t.Fatalf("scan %d while unreadable: %+v", i+2, got)
		}
		if entry, kept := svc.skillHashCache[dir]; kept && entry.status != SkillContentOK {
			t.Fatalf("the cache kept a %s read", entry.status)
		}
	}
	if err := os.Chmod(data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scan(); got.ContentStatus != SkillContentOK || got.ContentHash != first.ContentHash {
		t.Fatalf("first quiet scan: %+v; want ok with hash %s", got, first.ContentHash)
	}
}
