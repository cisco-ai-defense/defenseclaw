// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestCodexCodeGuardSkillInstallRejectsReparseTarget(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	userHome := filepath.Join(dir, "profile")
	restoreHome, err := BindUserHomeDir(userHome)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restoreHome)

	skillsDir := filepath.Join(userHome, ".agents", "skills")
	if err := os.MkdirAll(skillsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside-skill")
	writeTestFile(t, filepath.Join(outside, "SKILL.md"), `---
name: software-security
---

# Software Security Skill (Project CodeGuard)
`)
	target := filepath.Join(skillsDir, nativeCodeGuardCodexSkillName)
	createTestDirectoryRedirect(t, target, outside)
	t.Cleanup(func() { _ = os.Remove(target) })

	opts := SetupOpts{DataDir: filepath.Join(dir, "data")}
	err = ensureCodexCodeGuardSkill(context.Background(), opts)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("reparse target install error = %v, want reparse refusal", err)
	}
	if _, err := os.Lstat(codexCodeGuardReceiptPath(opts)); !os.IsNotExist(err) {
		t.Fatalf("reparse refusal published an ownership receipt: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(outside, "SKILL.md")); err != nil {
		t.Fatalf("outside skill was removed: %v", err)
	} else if !strings.Contains(string(data), "Project CodeGuard") {
		t.Fatalf("outside skill was changed:\n%s", data)
	}
}
