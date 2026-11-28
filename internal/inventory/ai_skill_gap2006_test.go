// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2006: an oversized file the walk cannot open (on Windows a writer
// holds it; here the scan may not read it) makes the folder too large, as on
// rel, not unreadable. Native Windows: TestGAP1901ShrunkByAHandleHeldAcrossAScan.
func TestGAP2006OversizedUnopenableFileIsTooLarge(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode 000 file")
	}
	dir := filepath.Join(t.TempDir(), "pdf")
	writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, maxSkillBytes+1024); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(big, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(big, 0o600) })
	if hash, status, read := hashSkillFolder(dir, maxSkillBytes); hash != "" || status != SkillContentTooLarge {
		t.Fatalf("oversized unopenable file: %q %s %d; want too large", hash, status, read)
	}
	for _, step := range []func() error{
		func() error { return os.Chmod(big, 0o600) },
		func() error { return os.Truncate(big, 64) },
		func() error { return os.Chmod(big, 0) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if _, status, _ := hashSkillFolder(dir, maxSkillBytes); status != SkillContentUnreadable {
		t.Fatalf("small unopenable file: %s; want unreadable", status)
	}
}
